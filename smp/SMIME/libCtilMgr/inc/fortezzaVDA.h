/*****************************************************************************
File:     fortezzaVDA.h
Project:  Fortezza Certificate Management Library
Contents: Header file for the fortezza.c code.

Created:  July 1997
Author:   David Dalkowski <dadalko@missi.ncsc.mil>
          Rich Nicholas <renich1@missi.ncsc.mil>

Last Updated:  23 January 1998

Version:  1.2 Release

*****************************************************************************/

#ifndef _FORTEZZA_H_
#define _FORTEZZA_H_ 1

#ifndef ulong
typedef unsigned long ulong;
#endif

#ifndef uchar
typedef unsigned char uchar;
#endif

#define F_NO_ERROR                  0
#define F_INVALID_PARAMETER         3
#define F_SIG_NOT_VALID				-1

short F_sig_check(uchar *p, uchar *q,uchar *g,uchar *y,uchar *hashValue,uchar *r,uchar *s);
                  //RWC;int pLength);
short F_sha1_hash(uchar *msgdata, long msgsize, unsigned char *hashValue);


#endif /* _FORTEZZA_H_ */

