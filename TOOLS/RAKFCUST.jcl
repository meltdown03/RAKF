//RAKFCUST JOB (TSO),
//             'Customizations',
//             CLASS=S,
//             MSGCLASS=A,
//             REGION=8192K,
//             MSGLEVEL=(1,1)
//* ******************************************************************
//* If you are generating this file with generate_release.py
//* Edit the files users.txt and profiles.txt this file
//* gets replaced by that script with the contents of those
//* files
//* ******************************************************************
//USERSIEB EXEC PGM=IEBGENER
//SYSPRINT DD SYSOUT=*
//SYSIN DD DUMMY
//SYSUT2   DD DSN=&&USERS,DISP=(,PASS),UNIT=VIO,
//            SPACE=(TRK,(5,5)),DCB=(RECFM=FB,LRECL=80,BLKSIZE=800)
//SYSUT1 DD *
HMVS01  1ADMIN   *CUL8TR   Y Y
HMVS01  2RAKFADM  CUL8TR   Y Y
HMVS02  2USER     PASS4U   N N
HERC01  1ADMIN   *CUL8TR   Y Y
HERC01  2RAKFADM  CUL8TR   Y Y
HERC02  1ADMIN             N N
IBMUSER 1ADMIN   *SYS1     Y Y
IBMUSER 2RAKFADM *SYS1     Y Y
/*
//* ******************************************************************
//PROFSIEB EXEC PGM=IEBGENER
//SYSPRINT DD SYSOUT=*
//SYSIN DD DUMMY
//SYSUT2   DD DSN=&&PROF,DISP=(,PASS),UNIT=VIO,
//            SPACE=(TRK,(5,5))
//SYSUT1 DD *
DASDVOL *                                                   READ
DASDVOL *                                           ADMIN   ALTER
DASDVOL *                                           STCGROUPALTER
DATASET *                                                   READ
DATASET *                                           ADMIN   ALTER
DATASET *                                           STCGROUPALTER
DATASET RPF.V1R5M3.SRPFPROF                                 UPDATE
DATASET SYS1.BRODCAST                                       UPDATE
DATASET SYS1.DUPLEX                                         NONE
DATASET SYS1.PAGECSA                                        NONE
DATASET SYS1.PAGELPA                                        NONE
DATASET SYS1.PAGEL01                                        NONE
DATASET SYS1.PAGEL02                                        NONE
DATASET SYS1.PAGES01                                        NONE
DATASET SYS1.SECURE.*                                       NONE
DATASET SYS1.SECURE.*                               ADMIN   NONE
DATASET SYS1.SECURE.*                               RAKFADM UPDATE
DATASET SYS1.STGINDEX                                       NONE
DATASET UCPUB000                                            UPDATE
DATASET UCPUB001                                            UPDATE
FACILITYDIAG8                                               NONE
FACILITYDIAG8                                       ADMIN   READ
FACILITYDIAG8                                       STCGROUPREAD
FACILITYRAKFADM                                             NONE
FACILITYRAKFADM                                     ADMIN   NONE
FACILITYRAKFADM                                     RAKFADM READ
FACILITYRAKFADM                                     STCGROUPREAD
FACILITYSVC244                                              NONE
FACILITYSVC244                                      ADMIN   READ
FACILITYSVC244                                      STCGROUPREAD
TAPEVOL *                                                   READ
TAPEVOL *                                           ADMIN   ALTER
TAPEVOL *                                           STCGROUPALTER
TERMINAL*                                                   READ
/*
//* ******************************************************************
//* Delete existing security datasets before a fresh install
//CLNSEC  EXEC PGM=IDCAMS
//SYSPRINT DD SYSOUT=*
//SYSIN    DD *
 LISTCAT ENTRIES(SYS1.SECURE.PWUP)
 IF LASTCC = 0 THEN -
   DELETE SYS1.SECURE.PWUP PURGE
 ELSE -
   IF LASTCC = 4 THEN SET MAXCC = 0
 IF MAXCC = 0 THEN DO
   LISTCAT ENTRIES(SYS1.SECURE.CNTL)
   IF LASTCC = 0 THEN -
     DELETE SYS1.SECURE.CNTL PURGE
   ELSE -
     IF LASTCC = 4 THEN SET MAXCC = 0
 END
/*
//ALLOC   EXEC PGM=IEFBR14,COND=(0,NE,CLNSEC)
//PWUP    DD DISP=(NEW,CATLG),DSN=SYS1.SECURE.PWUP,VOL=SER=MVS000,
//           UNIT=SYSDA,DCB=(RECFM=F,LRECL=18,BLKSIZE=18),
//           SPACE=(TRK,(1,1))
//RAKF    DD DISP=(NEW,CATLG),DSN=SYS1.SECURE.CNTL,VOL=SER=MVS000,
//           UNIT=SYSDA,DCB=(RECFM=FB,LRECL=80,BLKSIZE=19040),
//           SPACE=(TRK,(10,3,3))
//********************************************************************
//SORTREXX EXEC PGM=IEBGENER,COND=(0,NE,CLNSEC)
//SYSPRINT DD SYSOUT=*
//SYSIN DD DUMMY
//SYSUT1    DD *
SAY ''
SAY '******************************************'
SAY '* REXX SORT PROFILES                     *'
SAY '******************************************'
SAY ''
"EXECIO * DISKR PROFILES (FINIS STEM SORTIN."

SAY '*** NUMBER OF PROFILE ENTRIES' SORTIN.0
SAY '*** SORTING'
CALL RXSORT
SAY '*** DONE'


DO I=1 TO SORTIN.0
    SAY SORTIN.I
    PROFILES.I = SORTIN.I
END
PROFILES.0 = SORTIN.0

SAY "*** GENERATING IEBUPDTE STATEMENTS"

OUTDD.1 = "./ ADD NAME=PROFILES"
DO I=1 TO PROFILES.0
    X = I + 1
    OUTDD.X = PROFILES.I
END
SAY PROFILES.0
OUTDD.0 = 1 + PROFILES.0


"EXECIO * DISKW OUTDD (STEM OUTDD. FINIS"
IF RC > 0 THEN DO
    SAY "(T_T) ERROR READING OUTDD:" RC
    EXIT 1
END
SAY "*** DONE"
SAY ''
/*
//SYSUT2   DD DSN=&&RXSORT,DISP=(,PASS),UNIT=VIO,
//            SPACE=(TRK,(5,5))
//* **********************************************************
//EXECSORT EXEC PGM=BREXX,PARM='RXRUN',REGION=8192K,COND=(0,NE,CLNSEC)
//RXRUN    DD   DSN=&&RXSORT,DISP=SHR
//RXLIB    DD   DSN=BREXX.RXLIB,DISP=SHR
//STDIN    DD   DUMMY
//PROFILES DD   DSN=&&PROF,DISP=SHR
//OUTDD    DD DSN=&&STAGIN,DISP=(,PASS),UNIT=VIO,SPACE=(TRK,(5,5)),
//         DCB=(LRECL=80,BLKSIZE=800,RECFM=FB)
//STDOUT   DD   SYSOUT=*,DCB=(RECFM=FB,LRECL=140,BLKSIZE=5600)
//STDERR   DD   SYSOUT=*,DCB=(RECFM=FB,LRECL=140,BLKSIZE=5600)
//* **********************************************************
//RAKFCNTL EXEC PGM=IEBUPDTE,PARM=NEW,COND=(0,NE,CLNSEC)
//SYSPRINT DD  SYSOUT=*
//SYSUT2   DD  DISP=SHR,DSN=SYS1.SECURE.CNTL
//SYSIN    DD  DSN=&&STAGIN,DISP=SHR
//* **********************************************************
//USERCOPY EXEC PGM=IEBGENER,COND=((0,NE,RAKFCNTL),(0,NE,CLNSEC))
//SYSPRINT DD SYSOUT=*
//SYSIN    DD DUMMY
//SYSUT1   DD DSN=&&USERS,DISP=SHR
//SYSUT2   DD DSN=SYS1.SECURE.CNTL(USERS),DISP=SHR
