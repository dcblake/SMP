#!/bin/sh

# AUTHOR : Pierce Leonberger
# COMPANY: J.G. Van Dyke & Associates
# DATE   : 02-25-1998
#
# This script is used to generate make files.  It depends on Makehead.<os>
# being in the the ./makes directory.  These files must be created for
# each system the the SM library and SM UTILITY library are to be 
# compiled for.
#
# See README.TXT in the ./makes directory for more information.
#
#


if [ "$1" = "" ]; then
   echo "usage: $0 <path>/<Makefile>"
   echo ""
   makeFile="Makefile"
else
   makeFile="$1"
   if [ ! -f $makeFile.in ] ; then
      echo "$makeFile.in does not exist..."
      exit
   fi
fi

OS=`uname -s`
REL=`uname -r`
NOTAIL=0

#
# Check to see if make rules are needed.  It's not needed if you are
# only building an executable (i.e. drivers )
#
case $makeFile in
   *Makelib*)
	RULES=0;
        ;;
   *)
        RULES=1;
        ;;
esac

#
# If a rules are needed determine which set of rules to use (testsrc or libsrc)
#

OSTYPE=""

case $makeFile in
   *MakeSrc* | *Makefile*)
        MAKERULES="./makes/AclRules";
        ;;
   *MakeTool*)
        MAKERULES="./makes/AclToolRules";
        ;;
   *)
        echo "ERROR: add rules support for additional directory!!"
        ;;
esac

case $OS in
   HP-UX)
      case $REL in
         A.09.0*)
            OSTYPE="hpux9"
            ;;
      esac
      ;;
   SunOS | Linux )
      OSTYPE="${OS}"
      ;;
   *)
      echo "ERROR: Unrecognized OS [$OS] returned from uname" 
      exit
      ;;
esac

if [ "$OSTYPE" = "" ]; then
   echo "create ./makes/Makehead.$OSTYPE"
   exit
else
   if [ $RULES = 0 ]; then
      cat ./makes/Makehead.$OSTYPE $makeFile.in >$makeFile
   else
      cat ./makes/Makehead.$OSTYPE $makeFile.in $MAKERULES >$makeFile
   fi
fi
