//////////////////////////////////////////////////////////////////////////
//
// FILE:  sm_timeStamp.h
//
// DESCRIPTION:  One of the major uses of time-stamping is to time-stamp a 
// digital signature to prove that the digital signature was created before 
// a given time.  Should the corresponding public key certificate be
// revoked this allows a verifier to know whether the signature was
// created before or after the revocation date.
// 
// A sensible place to store a time-stamp is in a [CMS] structure as an
// unsigned attribute
//
// This file contains classes and member functions to support an unsigned
// time-stamp attribute.
//
// CLASSES:
//
//    CSM_TimeStampReq
//    CSM_TimeStampResp
//
//////////////////////////////////////////////////////////////////////////
#ifndef _sm_timeStamp_h_
#define _sm_timeStamp_h_

#include "sm_api.h"

_BEGIN_SFL_NAMESPACE


////////////////////////////////////////////////////////////////////////////////
//
// Class:  CSM_TimeStampReq
//
// Description:  Class that inherits the SNACC::TimeStampReq class and 
//               members that help build the TimeStampReq data
// 
// Member Functions:
//  Public:
//    CSM_TimeStampReq constructors
//    ~CSM_TimeStampReq destructor
//    Set
//    LoadMessageImprint
//
// Member Variables:
//    NONE
//
////////////////////////////////////////////////////////////////////////////////
class  CSM_TimeStampReq : public SNACC::TimeStampReq
{
public:

   CSM_TimeStampReq(){};                       // default constructor
   
   CSM_TimeStampReq(                           // constructor
      CERT::CSMIME *pCsmime,                   // 
      SNACC::SignedData *pSnaccSD=NULL,        // original SignedData message
      const SNACC::AsnOid &HashOid=SNACC::sha_1,      // hash oid
      const SNACC::AsnOid *pReqPolicyOid=NULL,  // TSA policy under which 
                                               //   TST should be provided
      CTIL::CSM_Buffer *pNonce=NULL,           // 64 bit integer create by 
                                               //   user optional
      bool  bCertReq=false);                   // if true, the TSA's public key
                                               // certificate that is referenced by the
                                               // ESSCertID inside a signing cert attr
                                               // in reponse must be provided by TSA
   
   CSM_TimeStampReq(const CSM_TimeStampReq &that);  // copy constructor
   CSM_TimeStampReq & operator = (const CSM_TimeStampReq &TSR);

   ~CSM_TimeStampReq() {};                        // destructor

   // Set the user data into the SNACC::TimeStampReq members 
   void Set(              
      CERT::CSMIME *pCsmime,            // 
      SNACC::SignedData *pSnaccSD,      // original SignedData message
      const SNACC::AsnOid &HashOid,     // hash oid
      const SNACC::AsnOid *pReqPolicyOid,// TSA policy under which 
                                        //   TST should be provided
      CTIL::CSM_Buffer *pNonce,         // 64 bit integer create by 
                                        //   user optional
      bool  bCertReq);                  // if true, the TSA's public key
                                        // certificate that is referenced by the
                                        // ESSCertID inside a signing cert attr
                                        // in reponse must be provided by TSA

   // loads messageImprint from snaccSD
   SM_RET_VAL LoadMessageImprint(SNACC::SignedData   *pSnaccSD);

   // Computes hash and loads messageImprint
   SM_RET_VAL LoadMessageImprint(  
      CSMIME              *pCsmime,
      const CSM_Buffer    *pBuf,
      const SNACC::AsnOid HashOid);
};


////////////////////////////////////////////////////////////////////////////////
//
// Class:  CSM_TimeStampResp
//
// Description:  Class that inherits the SNACC::TimeStampResp class and 
//               members that help build the TimeStampResp data
// 
// Member Functions:
//  Private:
//    CreateTimeStampToken
//    CreateTiimeStampResponse
//    CheckPolicyId
//    CheckMessageImprint
//  Public:
//    CSM_TimeStampResp constructors
//    ~CSM_TimeStampResp destructor
//    LoadMessageImprint
//    AccessTimeStampToken
//    WasSuccessful
//    SetStatusError
//
// Member Variables:  None
//
////////////////////////////////////////////////////////////////////////////////
class  CSM_TimeStampResp: public SNACC::TimeStampResp
{
private:

   CSM_Buffer *CreateTimeStampToken(CERT::CSMIME *pCsmime,
      CSM_TimeStampReq &TSReq, char *lpszLogin, int serialNum,
	  CSM_CertificateChoice *&pSigningCert,
      SNACC::AsnOid *pPolicyOid=NULL);
   
   CSM_Buffer *CreateTimeStampResponse(CERT::CSMIME *pCsmime, 
      CSM_TimeStampReq &TSReq,  char *lpszLogin, int serialNum,	 
	  CSM_CertificateChoice *&pSigningCert);
 
   // Check the TSA policy id
   bool CheckPolicyId(SNACC::Extensions *pExtensions, SNACC::AsnOid &policyOid);
   SM_RET_VAL CheckMessageImprint(SNACC::MessageImprint *pMsgImprint); // check messageImprint

public:

   CSM_TimeStampResp() {};                               // default constructor
   CSM_TimeStampResp(                                    // constructor
	  CERT::CSMIME *pCsmime,                             // Logins - if lpszLogin is
	                                                     // NULL then the pCsmime data must 
														 // contain a valid TSA.
														 // TSA's must have: 
														 // 1.  ability to sign
														 // 2.  KeyPurposeID id-kp-timeStamping
														 // 3.  unique policy id 
														 //              
      CSM_TimeStampReq &TSReq,                           // Time stamp request
      char *lpszLogin,                                   // TSA DN
      int serialNum,                                     // serial Number
	  CSM_CertificateChoice *&pSigningCert,              // Signing Certificate
      SNACC::AsnOid *pPolicyOid=NULL);                   // Policy oid - optional
      
   CSM_TimeStampResp(const CSM_TimeStampResp& that);     // copy construcor
   CSM_TimeStampResp & operator = (const CSM_TimeStampResp &TSResp);

   ~CSM_TimeStampResp() {};

   static CSM_CSInst *DetermineTSAInstance(
        CSMIME *pCsmime, char *lpszLogin, const char *&pErrorStr, bool bChkApplicable=false);

   static SM_RET_VAL AssignFirstTSA(CSMIME *pCsmime, const char *&pErrorStr);

   CSM_Buffer *AccessTimeStampToken();  // returns SNACC::timeStampToken

   bool WasSuccessful();  // checks timeStampToken
   void SetStatusError(int errorCode , const char *pStatusStr, int FailureInfo);

};

_END_SFL_NAMESPACE

#endif /* conditional include of sm_timeStamp.h */
