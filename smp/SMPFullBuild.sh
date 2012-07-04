#!/bin/bash
#
# SMPFullBuild.sh
#
# Variables
#
R=2.5
#
# Subroutines
#
do_cmd()
{
   command=$*
   $command
   # Check return value of command, if it failed report error and exit
   if [ $? != 0 ]
   then
      echo command \"$command\" failed, exiting...
      exit 
   fi
}
#
# main()
#

# change directory one level up so the smp directory is included in the tar ball
do_cmd cd ..

# Remove the old tar ball
do_cmd rm -f SMPFull$R.tar.gz

# Remove all CVS directories
do_cmd find smp -depth -name CVS -exec rm -r {} \;

# Remove everything else that we do not want included in the tar ball
do_cmd rm -r smp/pkcs11_cryptopp/specs

do_cmd rm smp/cml/CML_Developer.dsw
do_cmd rm smp/cml/CML_DevNet.sln
do_cmd rm smp/cml/CML_DevNet.vssscc
do_cmd rm -r smp/cml/CM_Test
do_cmd rm -r smp/cml/CM_Tool
do_cmd rm -r smp/cml/data 
do_cmd rm smp/cml/changes.txt
do_cmd rm smp/cml/readme.txt
do_cmd rm smp/cml/license.txt
do_cmd rm -r smp/cml/docs
do_cmd rm -r smp/cml/cmcrl
do_cmd rm -r smp/cml/crlservice

do_cmd rm smp/cryptlib_mod42.dsp
do_cmd rm smp/cryptlib_mod50.dsp
do_cmd rm smp/cryptlib_mod50.vcproj
do_cmd rm smp/cryptlib_mod51.dsp
do_cmd rm smp/SMP_Developer.sln
do_cmd rm smp/SMP_Requirements.xls

do_cmd rm -r smp/SMIME/test
do_cmd rm -r smp/SMIME/testutil
do_cmd rm -r smp/SMIME/testsrc
do_cmd rm smp/SMIME/smime.dsp
do_cmd rm smp/SMIME/smime.dsw
do_cmd rm smp/SMIME/smime.sln
do_cmd rm smp/SMIME/smimeUtil.dsw
do_cmd rm smp/SMIME/ChangeLog.txt
do_cmd rm smp/SMIME/GENASN.BATold
do_cmd rm smp/SMIME/GENASNClean3.BAT
do_cmd rm smp/SMIME/libsmutil.dsp
do_cmd rm smp/SMIME/libsmutil.vcproj
do_cmd rm smp/SMIME/libsmutil.plg
do_cmd rm smp/SMIME/moveasn.bat
do_cmd rm -r smp/SMIME/BuildAllNoCtil
do_cmd rm -r smp/SMIME/BuildAllWinNT
do_cmd rm -r smp/SMIME/BuildAllDiag
do_cmd rm -r smp/SMIME/BuildAllWin98
do_cmd rm -r smp/SMIME/BuildPCTSupport
do_cmd rm -r smp/SMIME/certs.d
do_cmd rm -r smp/SMIME/CopyCTILMgrToSMPDist
do_cmd rm -r smp/SMIME/gnutools
do_cmd rm -r smp/SMIME/libCtilMgr/SMP_libCtilMgr_Dist

do_cmd rm -r smp/ACL/sample
do_cmd rm -r smp/ACL/CopyACLToSMPDist.dsp

# create the tar ball
do_cmd tar -czf SMPFull$R.tar.gz smp
#
# EOF SMPFullBuild.sh

