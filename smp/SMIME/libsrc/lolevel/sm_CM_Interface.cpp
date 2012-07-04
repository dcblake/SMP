
//
//  sm_CM_Interface.cpp
//
//################


#include "sm_api.h"

#include "sm_CM_Interface.h"

#ifdef CML_USED

  using namespace SNACC;  using namespace CTIL;
  using namespace CERT;
#include <malloc.h>
#include <string.h>

_BEGIN_SFL_NAMESPACE

///////////////////////////////////////////////////////////////////////////////
CM_Interface::CM_Interface()
{
   m_sRet = 0;
   m_pCtilMgr = NULL;
}

///////////////////////////////////////////////////////////////////////////////
CM_Interface::~CM_Interface() 
{
   this->m_sRet = 0;
}           // END ~CM_Interface()


//
//
char *CM_Interface::getErrInfo(CML::ErrorInfoList *pErrorInfo)
{
   char *pszResult=NULL;
   ErrorInfo_List *pCErrorInfo_List;
#ifdef CML_USED
   pCErrorInfo_List = *pErrorInfo;
   if (pCErrorInfo_List)
   {
      pszResult = getErrInfo(pCErrorInfo_List);
      CM_FreeErrInfo(&pCErrorInfo_List);
   }
#endif //CML_USED
   return(pszResult);
}        // END CM_Interface::getErrInfo(...)


//
//
char *CM_Interface::getErrInfo(struct errorInfo_List *pErrorInfo)
{
   char *pszResult=NULL;
#ifdef CML_USED
         if (pErrorInfo)
         {
            char *ptr;
            const char *ptr2;
            int i=1;
            ErrorInfo_List *pTmpError;
            char buf[4096];
            buf[0] = '\0';
            for (pTmpError=pErrorInfo; pTmpError; pTmpError=pTmpError->next)
            {
               ptr = pTmpError->xinfo;
               ptr2 = CMU_GetErrorString(pTmpError->error);
               sprintf(buf, "pErrorInfo: %d, DN= %s", i++, pTmpError->dn);
               if (ptr)
               {
                  strcat(buf, " xinfo=");
                  strcat(buf, ptr);
               }     // END if ptr
               if (ptr2)
               {
                  strcat(buf, " errorString=");
                  strcat(buf, ptr2);
                  strcat(buf, "\n");
               }     // END if ptr2
               if (strlen(buf))
               {
                  if (pszResult == NULL)
                     pszResult = strdup(buf);
                  else
                  {
                     char *ptr3 = (char *)calloc(1, 
                                          strlen(pszResult) + strlen(buf) + 1);
                     strcpy(ptr3, pszResult);
                     strcat(ptr3, buf);
                     free(pszResult);
                     pszResult = ptr3;
                  }
               }
            }     // END for each err info struct
         }        // END if any error info structs.
#endif //CML_USED


   return pszResult;
}        // END CM_Interface::getErrInfo(...)


////////////////////////////////////////////////////////////////////////////////////////////////
//
// dbFileAdd 
//
//    Calls SRL_DatabaseAdd to add the cert input in pCrlData to the database.  
//    etype sets the asn1 type, either cert or crl.
//
// returns status from SRL_DatabaseAdd call
//
////////////////////////////////////////////////////////////////////////////////////////////////
short CM_Interface::dbFileAdd(Bytes_struct *pCrlData,  int etype)           
{
   short status=0;

	if (pCrlData != NULL)
	{
		status = SRL_DatabaseAdd(this->m_lSrlSessionId, pCrlData, (AsnTypeFlag) etype);
		//cout << getErrorString(status) << endl;
	}

   return status;
}

//
//
long CM_Interface::dbAddCRL(const CSM_Buffer &BufCrl)
{ 
   long lstatus;
   Bytes_struct ACrlByteStruct;

   ACrlByteStruct.data = (unsigned char *)BufCrl.Access();
   ACrlByteStruct.num  = BufCrl.Length();
   lstatus = dbFileAdd(&ACrlByteStruct, SRL_CRL_TYPE);

   return(lstatus);
}     // END CM_Interface::dbAddCRL(...)

//
//
long CM_Interface::dbAddCert(const CSM_Buffer &BufCert)
{
   long lstatus;
   Bytes_struct ACertByteStruct;

   ACertByteStruct.data = (unsigned char *)BufCert.Access();
   ACertByteStruct.num  = BufCert.Length();
   lstatus = dbFileAdd(&ACertByteStruct, SRL_CERT_TYPE);

   return(lstatus);
}     // END CM_Interface::dbAddCRL(...)


//
//
CM_SFLCertificate::~CM_SFLCertificate() 
{    
   if (m_pRID) delete m_pRID; 
   if (m_pCMLCert) delete m_pCMLCert;
   if (m_lpszError) delete m_lpszError;
  // if (m_pCMLCrl) delete m_pCMLCrl; 
}


//
//
void CM_SFLCertificate::SetUserCert(const CSM_Buffer &BufCert)
{
    Bytes_struct ACertByteStruct;
    ACertByteStruct.data = (unsigned char *)BufCert.Access();
    ACertByteStruct.num  = BufCert.Length();
    //CML::Certificate ACMLUserCert(ACertByteStruct);
    this->SetUserCert(ACertByteStruct);
}       // END CM_SFLCertificate::SetUserCert(...)

//
//  This method will attempt to retrieve the user cert based on the information
//  contained in this class instance (e.g. IssuerAndSerialNumber OR SKI) if the dbType 
//  input parameter is set to SRL_DB_CERT; or this method will attempt to retrieve the
//  crl based on the information contained in this class instance if the dbType input parameter
//  is set to SRL_DB_CRL
long CM_SFLCertificate::GetUserCertCrl(DBTypeFlag dbType)
{
   long lstatus=-1;
   //EncCert_LL *pcertificateList=NULL;
   //dbEntryInfo *pentryInfo=NULL;   
   Bytes_struct *pentryData=NULL;
   SRL_CertMatch_struct	*certMatchStruct=NULL;
   SRL_CRLMatch_struct	*crlMatchStruct=NULL;

   SME_SETUP("CM_SFLCertificate::GetUserCert");

   if (m_pRID == NULL && dbType == SRL_DB_CERT)
   {
      SME_THROW(28, "m_pRID identifier not set.", NULL);
   }     // END if m_pRID


   //pentryInfo = (dbEntryInfo *)calloc(1, sizeof(dbEntryInfo));
   //pentryInfo->certs = (dbCertEntryInfo_LL *) calloc(1, sizeof(dbCertEntryInfo_LL));
   const CERT::CSM_IssuerAndSerialNumber *pIssuerSN=m_pRID->AccessIssuerAndSerial();
   const CSM_Buffer *pTmpSKIBuf = m_pRID->AccessSubjectKeyIdentifier();
   CSM_Buffer *pTmpSNBuf=NULL;
   CML::ASN::DN *pTmpIssDN=NULL;
   dbSearch_struct searchInfo;
   memset(&searchInfo, '\0', sizeof(searchInfo));

   if (m_pCMLCert == NULL && dbType == SRL_DB_CERT)
   {           // THEN setup for call to CML CM_RequestCerts(...).
      certMatchStruct=(SRL_CertMatch_struct *)
                            calloc(1, sizeof(SRL_CertMatch_struct));
      searchInfo.dbType = SRL_DB_CERT;
      if (pIssuerSN != NULL)
      {
         pTmpIssDN = ((CSM_IssuerAndSerialNumber *)pIssuerSN)->GetIssuer();
         certMatchStruct->issuerDN = (char *)((const char *)*pTmpIssDN);   //char *; do not delete
         pTmpSNBuf = ((CSM_IssuerAndSerialNumber *)pIssuerSN)->GetSerialNo();
         certMatchStruct->serialNum = (Bytes_struct *) calloc(1, sizeof(Bytes_struct));
         certMatchStruct->serialNum->data = (unsigned char *)pTmpSNBuf->Access();
         certMatchStruct->serialNum->num  = pTmpSNBuf->Length();
      }
      else if (pTmpSKIBuf != NULL)
      {
         certMatchStruct->subjKMID = (Bytes_struct *) calloc(1, sizeof(Bytes_struct));
         certMatchStruct->subjKMID->data = (unsigned char *)pTmpSKIBuf->Access();
         certMatchStruct->subjKMID->num  = pTmpSKIBuf->Length();
      }
      else
      {
         SME_THROW(28, "m_pRID identifier not supported (not IssSN OR SKI).", 
            NULL);
      }     // END if RID type check
      searchInfo.matchInfo.cert = certMatchStruct;

   }        // END if m_pCMLCert
#ifdef NODEF // sib TBD
   else if (m_pCMLCrl == NULL && dbType == SRL_DB_CRL)
   {
      crlMatchStruct=(SRL_CRLMatch_struct *)
                            calloc(1, sizeof(SRL_CRLMatch_struct));

      searchInfo.dbType = SRL_DB_CRL;

      // sib TBD need something to say which crl to get



      if (pIssuerSN != NULL)
      {
         pTmpIssDN = ((CSM_IssuerAndSerialNumber *)pIssuerSN)->GetIssuer();
         // looks like we don't need the rid here just the signature algorithm
      }

      searchInfo.matchInfo.crl = crlMatchStruct;

   }
#endif
   else
      lstatus = 0;

   //lstatus = SRL_DatabaseRetrieve(m_lSrlSessionId, SRL_DB_CERT/*SRL_CERT_TYPE*/,
   //                pentryInfo, &pentryData);  RWC;WANY Search, not Retrieve!
   EncObject_LL *pobjlist=NULL;

   if (dbType == SRL_DB_CERT)
   {
      lstatus = SRL_DatabaseSearch(m_lSrlSessionId, NULL/*CM_DN dn*/, 
                SRL_DB_CERT/*DBTypeFlag dbType*/, &searchInfo, &pobjlist);
   }
#ifdef NODEF // sib TBD
   else if (dbType == SRL_DB_CRL)
   {
      lstatus = SRL_DatabaseSearch(m_lSrlSessionId, NULL/*CM_DN dn*/, 
                SRL_DB_CRL/*DBTypeFlag dbType*/, &searchInfo, &pobjlist);
   }
#endif

   char bufError[1024];
   if (pobjlist == NULL && dbType == SRL_DB_CERT)
   {
      // WE have a problem, more than 1 cert returned.
      sprintf(bufError, "Cert NOT returned from SRL, %s!", certMatchStruct->issuerDN);
      SME_THROW(22, bufError, NULL);
   }     // END if more than 1
   else if (pobjlist->next != NULL && dbType == SRL_DB_CERT)
   {
      // WE have a problem, more than 1 cert returned.
      sprintf(bufError, "MORE than 1 End Entity cert returned from SRL, %s!", 
              certMatchStruct->issuerDN);
	   SRL_FreeObjs(&m_lSrlSessionId, &pobjlist);
      SME_THROW(22, bufError, NULL);
   }     // END if more than 1
   else if (dbType == SRL_DB_CERT)        // FOUND IT, now load it for processing...
   {
      m_pCMLCert = new CM_SFLInternalCertificate/*CML::Certificate*/(pobjlist->encObj, false);
	   SRL_FreeObjs(&m_lSrlSessionId, &pobjlist);
   }     // END if pobjlist

#ifdef NODEF // sib TBD
   else if (pobjlist != NULL && dbType == SRL_DB_CRL)
   {
		EncObject_LL *tmpObj = pobjlist;
		while (tmpObj != NULL)
		{
			
			CML::ASN::Bytes encCRL(tmpObj->encObj);
			CML::CRL thisCRL(encCRL);  // CML's copy of the CRL
         
			tmpObj = tmpObj->next;
		}  // end while

    //  m_pCMLCrl= pobjlist->encObj.data;
	   SRL_FreeObjs(&m_lSrlSessionId, &pobjlist);

   }
#endif

   if (pTmpSNBuf)
      delete pTmpSNBuf;
   if (pTmpIssDN)
      delete pTmpIssDN;
   if (certMatchStruct)
   {
      if (certMatchStruct->serialNum)
         free(certMatchStruct->serialNum);
      free(certMatchStruct);
   }

   if (crlMatchStruct)
   {
      free(crlMatchStruct);
   }

   if (lstatus == 0 && pentryData && dbType == SRL_DB_CERT)
   {
       //ASN::Bytes ACmlBytes();
       m_pCMLCert = new CM_SFLInternalCertificate/*CML::Certificate*/(*pentryData, false);
       //issuerCert.Set(certificateList->encCert.num,certificateList->encCert.data);
       //CM_FreeEncCertList(m_lCmlSessionId, &certificateList);
       CM_FreeBytes(&pentryData);
   }     // END if pentryData

#ifdef NODEF // sib TBD
   else if (lstatus == 0 && pentryData && dbType == SRL_DB_CRL)
   {

      // sib TBD 
      ;
   }
#endif

   SME_FINISH_CATCH

   return(lstatus);
}           // END CM_SFLCertificate::GetUserCert()



/************************************************************************
 FUNCTION:  CM_SFLCertificate::Validate
 
 Description: Calls CML Build And Validate to validate a certificate

 Inputs: 
	CML::ASN::Time*  pTimeStampTime  -  Optional. Points to a date/time that 
                                        must be used when checking revocation
                                        status if present

 Return Value: 
	short result - result of Certificate Validation

*************************************************************************/
short CM_SFLCertificate::Validate(const CML::ASN::Time* pValidationTime)
{
   short sReturn=-1;
   char *pszError=NULL;

   if (m_pCMLCert == NULL)
   {
      sReturn = (short)GetUserCertCrl(SRL_DB_CERT);
   }     // END if    if m_pCMLCert==NULL
   else
      sReturn = 0;

   if (m_pCMLCert != NULL)
   {
       CML::ErrorInfoList Errors;
       sReturn = m_pCMLCert->BuildAndValidate(m_lCmlSessionId, 
		                  m_boundsFlag, &Errors, 0, 
						      NULL, pValidationTime, true );
       if (sReturn != 0)
       {
          pszError = CM_Interface::getErrInfo(&Errors);
          if (m_lpszError != NULL)
          {
			  // Append the CML error string, pszError, to the existing error
             char *ptr=(char*)malloc(strlen(m_lpszError) + 2 + strlen(pszError) + 1);
			 strcpy(ptr, m_lpszError);
			 strcat(ptr, "\n");
			 strcat(ptr, pszError);
             free(m_lpszError);
             free(pszError);
             m_lpszError = ptr;
          }
		  else
			m_lpszError = pszError;
       }
   }        // END if m_pCMLCert

   return(sReturn);
}



_END_SFL_NAMESPACE
#endif  // CML_USED

// END CM_Interface.cpp
