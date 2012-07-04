///////////////////////////////////////////////////////////////////////////////
// File:		      openssl_fcns.cpp
// Project:		   Certificate Management Library
// Contents:	   Implementation of the OCSP revocation status callback code.
// Requirements:  CML Requirements 2.1-5.
// 
// Created:		   09 March 2005
// Author:		   Tom Horvath <Tom.Horvath@BAESystems.com>
// 
// Last Updated:  09 March 2005
// 
// Version:		   2.5
//
// Description:   This file contains two functions taken directly from the
//                OpenSSL 0.9.7.e library which are necessary for OCSP
//                revocation status checking. It also contains the CML utility
//                function to call these functions.
///////////////////////////////////////////////////////////////////////////////

////////////////////
// Included Files //
////////////////////
#include <ocsp_internal.h> // needed for CML OCSP and OpenSSL types

// Function prototypes for OpenSSL functions.
static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
                            X509_STORE *st, unsigned long flags);
static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id);


int OCSPi_find_signer(X509 **pSigner, OCSP_BASICRESP *pBasicResp, 
                  STACK_OF(X509) *pCerts, X509_STORE *pStore,
                  unsigned long flags)
{
   return ocsp_find_signer(pSigner, pBasicResp, pCerts, pStore, flags);
}
   
// Note: The following two functions ocsp_find_signer() and 
// ocsp_find_signer_sk() are copied verbatim from OpenSSL
// version 0.9.7e crypto\ocsp\ocsp_vfy.c

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs,
                            X509_STORE *st, unsigned long flags)
{
   X509 *signer;
   OCSP_RESPID *rid = bs->tbsResponseData->responderId;
   if ((signer = ocsp_find_signer_sk(certs, rid)) != NULL)
   {
      *psigner = signer;
      return 2;
   }
   if(!(flags & OCSP_NOINTERN) &&
      ((signer = ocsp_find_signer_sk(bs->certs, rid)) != NULL))
   {
      *psigner = signer;
      return 1;
   }
   /* Maybe lookup from store if by subject name */
   
   *psigner = NULL;
   return 0;
}

static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id)
{
   int i;
   unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;
   X509 *x;
   
   /* Easy if lookup by name */
   if (id->type == V_OCSP_RESPID_NAME)
      return X509_find_by_subject(certs, id->value.byName);
   
   /* Lookup by key hash */
   
   /* If key hash isn't SHA1 length then forget it */
   if (id->value.byKey->length != SHA_DIGEST_LENGTH) return NULL;
   keyhash = id->value.byKey->data;
   /* Calculate hash of each key and compare */
   for (i = 0; i < sk_X509_num(certs); i++)
   {
      x = sk_X509_value(certs, i);
      X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL);
      if(!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
         return x;
   }
   return NULL;
}

