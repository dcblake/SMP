THIS PROJECT MUST BE BUILT BEFORE THE CML cmlasn PROJECT.

The order of building MUST be
	SMIME libCtilMgr
	SMIME CopyCTILMgrToSMPDist
	CML   cmlasn
	<<<  ALL OF cml CAN BE BUILT HERE >>>
	SMIME BuildAllWinNT OR BuildAllWin98
	...


========================================================================
       DYNAMIC LINK LIBRARY : libCtilMgr
========================================================================


AppWizard has created this libCtilMgr DLL for you.  

This file contains a summary of what you will find in each of the files that
make up your libCtilMgr application.

libCtilMgr.dsp
    This file (the project file) contains information at the project level and
    is used to build a single project or subproject. Other users can share the
    project (.dsp) file, but they should export the makefiles locally.

libCtilMgr.cpp
    This is the main DLL source file.

libCtilMgr.h
    This file contains your DLL exports.

/////////////////////////////////////////////////////////////////////////////
Other standard files:

StdAfx.h, StdAfx.cpp
    These files are used to build a precompiled header (PCH) file
    named libCtilMgr.pch and a precompiled types file named StdAfx.obj.


/////////////////////////////////////////////////////////////////////////////
Other notes:

AppWizard uses "TODO:" to indicate parts of the source code you
should add to or customize.


/////////////////////////////////////////////////////////////////////////////
