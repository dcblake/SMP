/*****************************************************************************
File:     SRL_ldap.h
Project:  Storage & Retrieval library
Contents: LDAP include file for the SRL 

Created:  November 2002
Author:   Robin Moeller <Robin.Moeller@digitalnet.com>

Last Updated:  3 May 2004

Version:  2.4

*****************************************************************************/
#ifndef _LDAP_H
#define _LDAP_H

#ifndef WIN32
	#include <sys/time.h>
	#include <sys/types.h>
	#include <sys/socket.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif


/*
 * LDAP_API macro definition:
 */
#ifndef LDAP_API
	#define LDAP_API(rt) rt
#endif /* LDAP_API */


/* Calling conventions used by LDAP libraries */
#ifndef LDAP_CALL
	#ifdef WIN32
		#ifdef _USING_MS_LDAP
			#define LDAP_CALL __cdecl
		#else
			#define LDAP_CALL __stdcall
		#endif /* _USING_MS_LDAP */
	#else /* WIN32 */
		#define LDAP_CALL
	#endif /* WIN32 */
#endif /* LDAP_CALL */

/* 
 * Do not define the following prototypes when Microsoft's LDAP header file
 * has been included
 */
#ifndef LDAP_CLIENT_DEFINED

/* ---------------- */
/* Type Definitions */
/* ---------------- */
typedef struct ldap     LDAP;           /* opaque connection handle */
typedef struct ldapmsg  LDAPMessage;    /* opaque result/entry handle */

#ifndef _LBER_H	/* From lber.h: */
struct berval {
	unsigned long	bv_len;
	char		*bv_val;
};
#endif /* _LBER_H */


/* ------------------- */
/* Function Prototypes */
/* ------------------- */
LDAP_API(LDAP *) LDAP_CALL ldap_open( const char *host, int port );
LDAP_API(LDAP *) LDAP_CALL ldap_init( const char *defhost, int defport );
LDAP_API(int) LDAP_CALL ldap_set_option( LDAP *ld, int option, void *optdata );
LDAP_API(int) LDAP_CALL ldap_unbind( LDAP *ld );
LDAP_API(int) LDAP_CALL ldap_abandon( LDAP *ld, int msgid );
LDAP_API(int) LDAP_CALL ldap_simple_bind( LDAP *ld, const char *who,
	const char *passwd );

LDAP_API(int) LDAP_CALL ldap_search( LDAP *ld, const char *base, int scope,
	const char *filter, char **attrs, int attrsonly );
LDAP_API(int) LDAP_CALL ldap_result( LDAP *ld, int msgid, int all,
	struct timeval *timeout, LDAPMessage **result );
LDAP_API(int) LDAP_CALL ldap_msgfree( LDAPMessage *lm );
LDAP_API(int) LDAP_CALL ldap_msgid( LDAPMessage *lm );
LDAP_API(int) LDAP_CALL ldap_msgtype( LDAPMessage *lm );
LDAP_API(int) LDAP_CALL ldap_result2error( LDAP *ld, LDAPMessage *r, 
	int freeit );
LDAP_API(LDAPMessage *) LDAP_CALL ldap_first_entry( LDAP *ld, 
	LDAPMessage *chain );
LDAP_API(LDAPMessage *) LDAP_CALL ldap_next_entry( LDAP *ld, 
	LDAPMessage *entry );
LDAP_API(int) LDAP_CALL ldap_count_entries( LDAP *ld, LDAPMessage *chain );
LDAP_API(char **) LDAP_CALL ldap_get_values( LDAP *ld, LDAPMessage *entry,
	const char *target );
LDAP_API(struct berval **) LDAP_CALL ldap_get_values_len( LDAP *ld,
	LDAPMessage *entry, const char *target );
LDAP_API(int) LDAP_CALL ldap_count_values( char **vals );
LDAP_API(int) LDAP_CALL ldap_count_values_len( struct berval **vals );
LDAP_API(void) LDAP_CALL ldap_value_free_len( struct berval **vals );

#endif /* LDAP_CLIENT_DEFINED */

#ifdef __cplusplus
}
#endif

#endif /* _LDAP_H */
