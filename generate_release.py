#!/usr/bin/env python3
#
# Generate the RAKF install job stream.
#
# The RAKF core (HLASM modules, procs, macros) ships as SMP source that MVS
# assembles/link-edits on-target. USERS records contain raw binary password
# hashes embedded after a `DD DATA,DLM=` card.
#
# Because the file contains raw binary, submit it through the EBCDIC
# pass-through reader (device 001A / port 3506), NOT the ASCII reader 3505:
#     cat install_rakf.jcl | ncat --send-only -w1 127.0.0.1 3506
#
import os
import sys
import hashlib
import argparse

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('-u', '--users', help="Custom users file", default=False)
arg_parser.add_argument('-p', '--profiles', help="Custom profiles file", default=False)
arg_parser.add_argument('-o', '--output', default=None,
                        help="Output file (binary EBCDIC card images). Default: stdout.")
arg_parser.add_argument('--helplib', default="SYS2.HELP",
                        help="Target help library for the ADDUSER/ALTUSER HELP members")
arg_parser.add_argument('--codepage', default="cp037",
                        help="EBCDIC codepage for card images (cp037 or cp1047)")
arg_parser.add_argument('--shadow-recovery', '--users-recovery',
                        dest='users_recovery', action='store_true',
                        help="Emit a standalone job replacing SYS1.SECURE.CNTL(USERS) "
                             "with users and password hashes from users.txt")
arg_parser.add_argument('--run-rakfuser', action='store_true',
                        help="After USERS recovery, EXEC the installed RAKFUSER procedure "
                             "to reload the in-core user table (otherwise IPL/reload later)")
arg_parser.add_argument('--upgrade', action='store_true',
                        help="Generate an in-place RAKF upgrade job instead of a fresh install.")
arg_parser.add_argument('--userid', default=None,
                        help="Put USER= on the RAKFINST and recovery job cards "
                             "(1 to 7 characters)")
arg_parser.add_argument('--password', default=None,
                        help="Put PASSWORD= on those job cards (1 to 8 characters)")
args = arg_parser.parse_args()
if bool(args.userid) != bool(args.password):
    sys.exit('generate_release.py: --userid and --password must be given together')
if args.userid and len(args.userid) > 7:
    sys.exit('generate_release.py: --userid is longer than 7 characters')
if args.password and len(args.password) > 8:
    sys.exit('generate_release.py: --password is longer than 8 characters')
running_folder = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------------ #
#  Output is a byte stream of 80-column EBCDIC card images.          #
# ------------------------------------------------------------------ #
OUT = bytearray()
CP = args.codepage


def emit(line=''):
    """Append one line as an 80-column EBCDIC card image.

    The reader consumes a fixed 80-byte record.  A single over-length line
    shifts every subsequent card by that extra byte, so JCL that used to
    start in column 1 (for example RECEIVER's //SMPCNTL) is no longer
    recognized.  Fail here rather than silently misalign the stream.
    """
    line = line.rstrip()
    if len(line) > 80:
        sys.exit('generate_release.py: card image exceeds 80 columns ({}):\n  {}'
                 .format(len(line), line))
    card = "{:80}".format(line).encode(CP)
    if len(card) != 80:
        sys.exit('generate_release.py: EBCDIC card is {} bytes, not 80:\n  {}'
                 .format(len(card), line))
    OUT.extend(card)


def emit_text(text):
    """Append a (multi-line) text block, one card image per line."""
    for l in text.split('\n'):
        emit(l.rstrip())


APPLY_GUARD = "(4,LT,APPLYR.HMASMP)"


def _exec_line(line):
    """True for a named JCL EXEC statement (not comments/continuations)."""
    if not line.startswith('//') or line.startswith('//*'):
        return False
    body = line[2:]
    return bool(body) and not body[0].isspace() and ' EXEC ' in line


def _exec_continuation(line):
    """True for a blank-name JCL continuation card such as // PARM=... ."""
    if not line.startswith('//') or line.startswith('//*'):
        return False
    body = line[2:]
    return bool(body) and body[0].isspace()


def _next_exec_continuation(lines, index):
    """Return True when the EXEC at index is followed by an active continuation.

    JCL comments and blank cards may occur between continuation cards, so ignore
    those while looking ahead. A named JCL statement ends the EXEC statement.
    """
    for j in range(index + 1, len(lines)):
        r = lines[j].rstrip()
        if not r or r.startswith('//*'):
            continue
        return _exec_continuation(r)
    return False


def _exec_has_cond(lines, index):
    """Check the EXEC card and its active continuation cards for COND=."""
    r = lines[index].rstrip()
    if 'COND=' in r.upper():
        return True

    for j in range(index + 1, len(lines)):
        s = lines[j].rstrip()
        if not s or s.startswith('//*'):
            continue
        if not _exec_continuation(s):
            break
        if 'COND=' in s.upper():
            return True
        # A continuation without a trailing comma completes the EXEC.
        if not s.endswith(','):
            break
    return False


def _split_exec_for_guard(line):
    """Make a noncontinued EXEC continuable without using column 72.

    MVS JCL's statement field ends at column 71.  If an EXEC already occupies
    all 71 columns, simply appending ',' puts the comma in column 72 and JES
    reports IEF618I.  Move the last top-level EXEC operand to a continuation
    card instead.

    Example:
      //ASMCDSCB EXEC PGM=IFOX00,REGION=2048K,PARM=(...)
    becomes:
      //ASMCDSCB EXEC PGM=IFOX00,REGION=2048K,
      //         PARM=(...),
    """
    line = line.rstrip()
    if line.endswith(','):
        return [line]

    # If there is room for a comma in the actual JCL statement field, use it.
    # Column 71 is the last usable character, so the existing line may be at
    # most 70 columns before the comma is appended.
    if len(line) <= 70:
        return [line + ',']

    # Find top-level commas (ignore commas inside quotes/parentheses) and move
    # the shortest possible final operand to a continuation card.
    comma_positions = []
    depth = 0
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            if depth:
                depth -= 1
        elif ch == ',' and depth == 0:
            comma_positions.append(i)

    prefix = '//         '
    for pos in reversed(comma_positions):
        head = line[:pos + 1]
        tail = line[pos + 1:].strip()
        continuation = prefix + tail + ','
        if len(head) <= 71 and len(continuation) <= 71:
            return [head, continuation]

    sys.exit('generate_release.py: cannot safely add APPLY guard to EXEC '
             'within JCL columns 1-71:\n  {}'.format(line))


def emit_jcl_line(line, guard_apply=False, exec_continues=False,
                  existing_cond=False):
    """Emit one JCL line, optionally bypassing the step if core APPLY failed.

    When the original EXEC already has continuation cards, the inserted COND
    must itself end in a comma.  When there is no following continuation, COND
    closes the EXEC statement.  Full-width EXEC cards are split first so no
    continuation comma is ever placed in column 72.
    """
    line = line.rstrip()
    if (guard_apply and args.upgrade and _exec_line(line)
            and not existing_cond):
        if line.endswith(','):
            emit(line)
        else:
            for part in _split_exec_for_guard(line):
                emit(part)
        suffix = ',' if exec_continues else ''
        emit('//         COND={}{}'.format(APPLY_GUARD, suffix))
    else:
        emit(line)


def emit_guarded_lines(lines):
    """Emit JCL lines with an APPLY guard added safely to complete EXEC statements."""
    for i, l in enumerate(lines):
        r = l.rstrip()
        emit_jcl_line(
            r,
            guard_apply=True,
            exec_continues=_next_exec_continuation(lines, i) if _exec_line(r) else False,
            existing_cond=_exec_has_cond(lines, i) if _exec_line(r) else False,
        )


def emit_guarded_text(text):
    """Emit a post-APPLY JCL block with the upgrade APPLY guard on each step."""
    emit_guarded_lines(text.split('\n'))


steps = []


def check_step(line, jcl_filename):
    if (' EXEC ' in line and
        line.split()[1] == 'EXEC'):
        step_name = line.split()[0][2:]
        if step_name not in steps:
            steps.append(step_name)
        else:
            raise ValueError("Duplicate Step Name {} (from {}) Already exists".format(step_name, jcl_filename))


def read_file(filename, guard_apply=False):
    emit("//*" + "*" * 66)
    emit("//* {}".format("/".join(filename.split("/")[-2:])))
    emit("//*" + "*" * 66)
    with open(filename, 'r') as f:
        raw = f.readlines()

    jobcard = True
    lines = []
    for l in raw:
        if l.strip() == "//":
            continue
        if not l.strip():
            continue
        if jobcard:
            if l.strip()[-1] == ",":
                continue
            jobcard = False
            continue
        lines.append(l.rstrip())

    if guard_apply and args.upgrade:
        emit_guarded_lines(lines)
    else:
        for l in lines:
            emit(l)

    for l in lines:
        check_step(l, filename)


def _data_file(arg, default):
    """Resolve a users/profiles file path (relative paths are under the repo)."""
    fn = arg if arg else default
    return fn if os.path.isabs(fn) else os.path.join(running_folder, fn)


def _with_job_credentials(lines):
    """Put USER= and PASSWORD= on the job card's CLASS= continuation."""
    if not args.userid:
        return lines
    cred = 'USER={},PASSWORD={}'.format(args.userid.upper(), args.password.upper())
    out = []
    in_card = True
    replaced = False
    for raw in lines:
        line = raw.rstrip('\n')
        if in_card and not line.startswith('//'):
            in_card = False
        if in_card and not replaced and 'CLASS=' in line.upper():
            kept = []
            for part in line.split(','):
                word = part.lstrip().upper()
                if word.startswith('USER=') or word.startswith('PASSWORD='):
                    continue
                kept.append(part)
            line = ','.join(kept)
            if not line.endswith(','):
                line += ','
            class_at = line.upper().find('CLASS=')
            comma = line.find(',', class_at)
            line = line[:comma + 1] + cred + ',' + line[comma + 1:]
            while ',,' in line:
                line = line.replace(',,', ',')
            replaced = True
        out.append(line)
        if in_card and line.startswith('//') and not line.rstrip().endswith(','):
            in_card = False
    if not replaced:
        sys.exit('generate_release.py: job card has no CLASS= line for '
                 'USER and PASSWORD')
    return out


def emit_header(filename):
    """Emit 01_header.template with the fixes needed by an upgrade.

    RESETRC lets the ACDS UCLIN run even when harmless CDS deletes report RC 8.
    During an upgrade ICHSFR00 must remain in LPALIB because SMP can use the
    existing LMOD as link-edit input while changing functional ownership.

    ++VER is emitted as written.  DELETE(TRKF120,TRKF126) already covers
    an upgrade from RAKF 1.2.0 or 1.2.6, so the generator does not rewrite it.
    """
    with open(filename) as f:
        lines = _with_job_credentials(f.readlines())

    # The V2 target/distribution libraries named by the LIBS step are release
    # work libraries.  On an upgrade/retry they may already exist from an
    # earlier attempt.  Since LIBS allocates them NEW, that otherwise ends in:
    #   IEF253I ... LIBS ASAMPLIB - DUPLICATE NAME ON DIRECT ACCESS VOLUME
    # Recreate them from scratch so a retry cannot reuse stale V2 members.
    upgrade_lib_dsns = []
    if args.upgrade:
        in_libs = False
        for raw in lines:
            r = raw.rstrip()
            if _exec_line(r):
                if r.startswith('//LIBS '):
                    in_libs = True
                    continue
                if in_libs:
                    break
            if in_libs and 'DSN=' in r.upper():
                dsn = r.upper().split('DSN=', 1)[1].split(',', 1)[0].strip()
                if dsn and dsn not in upgrade_lib_dsns:
                    upgrade_lib_dsns.append(dsn)

    last_control = ''
    cleanup_emitted = False
    for l in lines:
        stripped = l.strip()

        if (args.upgrade and not cleanup_emitted and
                l.rstrip().startswith('//LIBS ') and _exec_line(l.rstrip())):
            emit('//* UPGRADE: remove stale V2 target/distribution libraries')
            emit('//CLNV2LIB EXEC PGM=IDCAMS')
            emit('//SYSPRINT DD SYSOUT=*')
            emit('//SYSIN    DD *')
            for dsn in upgrade_lib_dsns:
                emit('  DELETE {} PURGE'.format(dsn))
            emit('  SET MAXCC=0')
            emit('/*')
            check_step('//CLNV2LIB EXEC PGM=IDCAMS', filename)
            cleanup_emitted = True

        if stripped == 'UCLIN ACDS .' and last_control != 'RESETRC.':
            emit(' RESETRC.')

        if args.upgrade and 'SCRATCH ' in l and 'MEMBER=ICHSFR00' in l:
            # Do not emit a //* comment here: SYSIN DD * treats // in
            # columns 1-2 as the end of in-stream data, and JES then
            # generates a replacement SYSIN.
            continue

        emit(l.rstrip())
        check_step(l, filename)
        if stripped and not stripped.startswith('***'):
            last_control = stripped


def emit_trkf211_jclin(filename):
    """Emit TRKF211 JCLIN after verifying the V2 password-hash linkage."""
    with open(filename) as f:
        text = f.read().rstrip()

    # V2 ICHSFR00 must contain both hashing CSECTs. Refuse to generate a deck
    # from an old/stale JCLIN, because that produces a load module that links
    # with unresolved RAKFPWH and fails at TSO logon.
    required = ('INCLUDE SYSPUNCH(RAKFHASH)', 'INCLUDE SYSPUNCH(RAKFPWH)')
    missing = [item for item in required if item not in text]
    if missing:
        sys.exit('generate_release.py: JCLIN/TRKF211.jcl is missing: {}'
                 .format(', '.join(missing)))

    emit_text(text)


def emit_smp_tail(filename):
    """Emit 02_smp4.template, preventing ACCEPT after a failed APPLY."""
    with open(filename) as f:
        for l in f.readlines():
            r = l.rstrip()
            if r.startswith('//ACCEPTR ') and ' EXEC ' in r and 'COND=' not in r.upper():
                r += ',COND={}'.format(APPLY_GUARD)
            emit(r)
            check_step(l, filename)


# ------------------------------------------------------------------ #
#  Initial credentials: blank plaintext and build password hashes     #
# ------------------------------------------------------------------ #
#  Field offsets in a USERS record (0-based), per RAKFUSER's DSECT:    #
#    0-7 userid   8 record type   9-16 group   17 flag   18-25 password #
def build_user_cards(users_text):
    """Build FB80 USERS cards with salt and hash on type-1 records only."""
    records = []
    primary = set()
    userids = set()
    for number, line in enumerate(users_text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('*'):
            continue
        if len(line) > 80:
            sys.exit('generate_release.py: USERS line {} exceeds 80 columns'
                     .format(number))
        record = line.ljust(80)
        userid, kind = record[:8].strip(), record[8]
        if not userid or kind not in ('1', '2'):
            sys.exit('generate_release.py: USERS line {} needs a userid and '
                     'record type 1 or 2 in column 9'.format(number))
        userids.add(userid)
        password = record[18:26].strip()
        if kind == '1':
            if userid in primary:
                sys.exit('generate_release.py: duplicate type-1 USERS record '
                         'for {}'.format(userid))
            primary.add(userid)
            if password:
                salt = os.urandom(8)
                digest = hashlib.sha256(
                    salt + password.upper().encode('cp037')).digest()
                credential = salt + digest
            else:
                credential = bytes(40)
        else:
            credential = ' '.encode(CP) * 40
        prefix = record[:18] + ' ' * 8 + record[26:31]
        card = prefix.encode(CP) + credential + record[71:].encode(CP)
        if len(card) != 80:
            sys.exit('generate_release.py: USERS line {} is not an FB80 card'
                     .format(number))
        records.append(card)
    missing = userids - primary
    if missing:
        sys.exit('generate_release.py: missing type-1 USERS record for {}'
                 .format(', '.join(sorted(missing))))
    if not records:
        sys.exit('generate_release.py: no USERS records found')
    return b''.join(sorted(records))


def emit_rakfcust(filename, inserts):
    """Emit RAKFCUST.jcl, splicing USERS/PROFILES and handling upgrades.

    USERS cards are binary; use DD DATA and a collision-free delimiter.
    """
    emit("//*" + "*" * 66)
    emit("//* {}".format("/".join(filename.split("/")[-2:])))
    emit("//*" + "*" * 66)
    with open(filename) as f:
        lines = f.read().split('\n')
    jobcard = True
    skipping = False          # dropping an old placeholder body up to its /*
    skip_dd_cont = False      # dropping allocation continuations for reused DSNs
    n = 0                     # number of placeholders filled so far
    users_dlm = pick_dlm(inserts[0])
    for line_index, l in enumerate(lines):
        if l.strip() == "//" or not l.strip():
            continue
        if jobcard:
            if l.strip().endswith(","):
                continue
            jobcard = False
            continue
        if skipping:
            if l.strip() == "/*":
                skipping = False
                emit(users_dlm if n == 1 else l.rstrip())
            continue

        if skip_dd_cont:
            if l.startswith('//') and len(l) > 2 and l[2].isspace():
                continue
            skip_dd_cont = False
        if l.startswith('//SHADOW') and 'SYS1.SECURE.SHADOW' in l:
            skip_dd_cont = True
            continue

        # In upgrade mode these two datasets came from the previous RAKF
        # installation. Keep them and suppress the UNIT/DCB/SPACE continuation
        # cards belonging to their original DISP=(,CATLG) allocation DDs.
        if args.upgrade and l.startswith('//PWUP') and 'SYS1.SECURE.PWUP' in l:
            emit('//PWUP    DD DISP=SHR,DSN=SYS1.SECURE.PWUP')
            skip_dd_cont = True
            continue
        if args.upgrade and l.startswith('//RAKF') and 'SYS1.SECURE.CNTL' in l:
            emit('//RAKF    DD DISP=SHR,DSN=SYS1.SECURE.CNTL')
            skip_dd_cont = True
            continue

        toks = l.split()
        if n == 0 and len(toks) >= 3 and toks[0] == "//SYSUT1" \
                and toks[1] == "DD" and toks[2] == "*":
            emit("//SYSUT1 DD DATA,DLM='{}'".format(users_dlm))
            OUT.extend(inserts[0])
            n = 1
            skipping = True
            continue

        emit_jcl_line(
            l,
            guard_apply=True,
            exec_continues=_next_exec_continuation(lines, line_index)
                           if _exec_line(l.rstrip()) else False,
            existing_cond=_exec_has_cond(lines, line_index)
                          if _exec_line(l.rstrip()) else False,
        )
        check_step(l, filename)
        if n < 2 and len(toks) >= 3 and toks[0] == "//SYSUT1" \
                and toks[1] == "DD" and toks[2] == "*":
            emit_text(inserts[n])     # splice users.txt / profiles.txt
            n += 1
            skipping = True


def pick_dlm(payload):
    """Choose a 2-char delimiter whose EBCDIC bytes never start an 80-byte
    record (so DD DATA reads the whole binary intact)."""
    for cand in ("$$", "??", "@@", "##", "%%", "&&", "!!", "~~", "^^", "=="):
        b = cand.encode(CP)
        if not any(payload[i:i+2] == b for i in range(0, len(payload), 80)):
            return cand
    raise SystemExit("generate_release.py: could not find a collision-free DD DATA delimiter")


# Continue RAKFINST rather than racing the install in a separate job.
HELP_HEADER = """//* --- TSO HELP members for the admin commands -------------------
//HELPLOAD EXEC PGM=IEBUPDTE,PARM=NEW
//SYSPRINT DD SYSOUT=*
//SYSUT2   DD DSN={helplib},DISP=SHR
//SYSIN    DD *"""


def aliases_from_help_member(path):
    """Return alias names from leading `./ ALIAS NAME=` cards in a HELP file."""
    aliases = []
    with open(path) as f:
        for raw in f:
            s = raw.strip()
            if not s:
                continue
            if s.startswith('./ ALIAS NAME='):
                name = s.split('=', 1)[1].strip().split()[0]
                if name:
                    aliases.append(name)
                continue
            break
    return aliases


def help_member_has_add(path):
    """True if the HELP file already starts with `./ ADD NAME=`."""
    with open(path) as f:
        for raw in f:
            s = raw.strip()
            if not s:
                continue
            return s.startswith('./ ADD NAME=')
    return False


def emit_help():
    """Load HELP/* into the help library so 'HELP ADDUSER' works.

    One member per file in HELP/, named after the command. IEBUPDTE is
    used (PARM=NEW) so leading `./ ALIAS NAME=` cards in those files are
    honored; PDSLOAD mishandles ALIAS.  The same cards are reported on
    the `[gen] help members:` line (e.g. ALTUSER/ALU).
    """
    help_dir = os.path.join(running_folder, "HELP")
    if not os.path.isdir(help_dir):
        return
    members = sorted(f for f in os.listdir(help_dir)
                     if os.path.isfile(os.path.join(help_dir, f)))
    if not members:
        return
    listed = []
    for m in members:
        aliases = aliases_from_help_member(os.path.join(help_dir, m))
        listed.append("/".join([m] + aliases) if aliases else m)
    sys.stderr.write("[gen] help members: {}\n".format(", ".join(listed)))
    (emit_guarded_text if args.upgrade else emit_text)(
        HELP_HEADER.format(helplib=args.helplib))
    for m in members:
        path = os.path.join(help_dir, m)
        if not help_member_has_add(path):
            emit("./ ADD NAME={}".format(m))
        with open(path) as f:
            for line in f.read().split('\n'):
                line = line.rstrip()
                if len(line) > 80:
                    sys.exit("generate_release.py: HELP/{} has a line over 80 "
                             "columns:\n  {}".format(m, line))
                emit(line)
    emit("/*")



# ------------------------------------------------------------------ #
#  Standalone USERS recovery mode.                                    #
# ------------------------------------------------------------------ #
def write_output():
    """Write the accumulated EBCDIC card-image stream."""
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(bytes(OUT))
        sys.stderr.write("[gen] wrote {} ({} bytes). Submit via the EBCDIC reader:\n"
                         "      cat {} | ncat --send-only -w1 127.0.0.1 3506\n"
                         .format(args.output, len(OUT), args.output))
    else:
        sys.stdout.buffer.write(bytes(OUT))
        sys.stderr.write("[gen] wrote {} bytes to stdout. Submit the EBCDIC stream via port 3506.\n"
                         .format(len(OUT)))


def emit_users_recovery(cards):
    """Replace the USERS member without passing binary records through REXX."""
    dlm = pick_dlm(cards)
    emit("//RAKFRECV JOB (RAKF),'RAKF USERS RECOVERY',CLASS=A,MSGCLASS=A,")
    jobtail = "//         MSGLEVEL=(1,1),REGION=4096K"
    if args.userid:
        jobtail += ",USER={},PASSWORD={}".format(
            args.userid.upper(), args.password.upper())
    emit(jobtail)
    emit("//* Replace USERS with records and passwords from the input file")
    emit("//RECOVER  EXEC PGM=IEBGENER")
    emit("//SYSPRINT DD SYSOUT=*")
    emit("//SYSIN    DD DUMMY")
    emit("//SYSUT2   DD DSN=SYS1.SECURE.CNTL(USERS),DISP=OLD")
    emit("//SYSUT1   DD DATA,DLM='{}'".format(dlm))
    OUT.extend(cards)
    emit(dlm)
    if args.run_rakfuser:
        emit("//* Reload only after successful recovery")
        emit("//RELOAD   EXEC RAKFUSER,COND=(0,NE,RECOVER)")


if args.users_recovery:
    users_path = _data_file(args.users, 'users.txt')
    with open(users_path) as f:
        recovery_cards = build_user_cards(f.read())
    sys.stderr.write("[gen] WARNING: recovery replaces the entire USERS member "
                     "and resets passwords from {}.\n".format(users_path))
    sys.stderr.write("[gen] WARNING: the generated deck and JES input spool "
                     "contain password hashes; protect them accordingly.\n")
    emit_users_recovery(recovery_cards)
    write_output()
    sys.exit(0)


##################################################

emit_header(running_folder + "/TEMPLATES/01_header.template")
emit_trkf211_jclin(running_folder + "/JCLIN/TRKF211.jcl")

smp_dict = {
        'MACLIB': "++MAC({}) DISTLIB(AMACLIB)  SYSLIB(MACLIB).",
        'SRCLIB': "++SRC({}) DISTLIB(ASRCLIB)  SYSLIB(SRCLIB).",
        'PROCLIB': "++MAC({}) DISTLIB(APROCLIB) SYSLIB(PROCLIB).",
        'PARMLIB': "++MAC({}) DISTLIB(APARMLIB) SYSLIB(PARMLIB).",
        'SAMPLIB': "++MAC({}) DISTLIB(ASAMPLIB) SYSLIB(SAMPLIB)."
        }

folders = ["MACLIB", "SRCLIB", "PROCLIB", "PARMLIB", "SAMPLIB"]

for folder in folders:
    fileList = os.listdir("{}/{}".format(running_folder, folder))
    for filename in fileList:
        member = filename.split(".")[0]
        if not (1 <= len(member) <= 8):
            sys.exit('generate_release.py: {} member {} is not 1-8 characters '
                     '(from {})'.format(folder, member, filename))
        emit(smp_dict[folder].format(member))
        jfile = os.path.join('{}/{}/{}'.format(running_folder, folder, filename))
        with open(jfile, 'r') as f:
            body = f.read().rstrip()
        for line in body.split('\n'):
            line = line.rstrip()
            # Columns 1-2 of PTFIN starting with ++ begin a new MCS.
            # RAKF2MVS's ++LMODIN/++ENDLMODIN would abort RECEIVE
            # (HMA2032 / HMA3980) if left in column 1.
            if line.startswith('++'):
                line = ' ' + line
                if len(line) > 80:
                    sys.exit('generate_release.py: {}/{} ++ data exceeds 80 '
                             'columns after MCS-safe indent'.format(
                                 folder, filename))
            emit(line)

emit_smp_tail(running_folder + "/TEMPLATES/02_smp4.template")

install = []

# RAK0001 is already installed on the supported upgrade path.
if not args.upgrade:
    install.append('USERMODS/RAK0001.jcl')

install.extend([
    'USERMODS/ZJW0003.jcl',
    'USERMODS/JLM0003.jcl',
    'TOOLS/RAKFCUST.jcl',
    'AUX/VTOC/vtoc.jcl',
    'AUX/CDSCB.jcl',
    'TOOLS/VSAMSRAC.jcl',
    'TOOLS/VTOCSRAC.jcl',
])

# ---- process the initial users: blank passwords and embed credentials --
_users_raw = open(_data_file(args.users, 'users.txt')).read()
_profiles = open(_data_file(args.profiles, 'profiles.txt')).read().strip()
user_cards = build_user_cards(_users_raw)
sys.stderr.write('[gen] WARNING: the generated deck and JES input spool contain '
                 'password hashes; protect them accordingly.\n')

for jcl in install:
    path = running_folder + "/" + jcl
    if 'RAKFCUST' in jcl:
        emit_rakfcust(path, [user_cards, _profiles])
        emit_help()
    else:
        read_file(path, guard_apply=args.upgrade)

emit("//* Steps in this job stream")
for i in steps:
    emit("//* {}".format(i))

# ------------------------------------------------------------------ #
#  Write the EBCDIC byte stream.                                     #
# ------------------------------------------------------------------ #
write_output()
#
