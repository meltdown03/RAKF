//INITPWUP JOB (RAKF),                                                 
//             'RAKF Customization',                                   
//             CLASS=A,                                                
//             MSGCLASS=X,                                             
//             MSGLEVEL=(1,1)                                          
//* ------------------------------------------------------------------*
//* Allocate the RAKF password queue dataset SYS1.SECURE.PWUP         *
//* Change 'tttttt' in the volume requested.                          *
//*                                                                   *
//* Expected return codes: Step DELETE:  00                           *
//*                        Step ALLOC:   00                           *
//* ------------------------------------------------------------------*
//*                                                                    
//* ------------------------------------------------------------------*
//* Delete SYS1.SECURE.PWUP                                           *
//* ------------------------------------------------------------------*
//LISTCAT  EXEC PGM=IDCAMS                                             
//SYSPRINT DD SYSOUT=*                                                 
//SYSIN    DD *                                                        
 DELETE SYS1.SECURE.PWUP PURGE SCRATCH                                 
 SET LASTCC=0                                                          
 SET MAXCC=0                                                           
/*                                                                     
//* ------------------------------------------------------------------*
//* Allocate SYS1.SECURE.PWUP                                         *
//* ------------------------------------------------------------------*
//ALLOC   EXEC PGM=IEFBR14                                             
//PWUP     DD  DISP=(,CATLG),DSN=SYS1.SECURE.PWUP,VOL=SER=tttttt,      
//             UNIT=SYSDA,DCB=(RECFM=F,LRECL=18,BLKSIZE=18),           
//             SPACE=(TRK,(1,1))                                       
//                                                                     
