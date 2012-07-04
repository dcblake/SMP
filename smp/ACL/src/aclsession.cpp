//////////////////////////////////////////////////////////////////////////////
// aclsession.cpp
// These routines support the Session Class
// CONSTRUCTOR(s):
//   Session(void)
//   Session(CTIL::CSM_CtilMgr *pCSMIME)
// DESTRUCTOR:
//   ~Session(void)
// MEMBER FUNCTIONS:
//   usingLDAP(void)
//   usingCML(void)
//   usingAutoRetrieve(void)
//   addAC(CTIL::CSM_Buffer &o)
//   addCC(CTIL::CSM_Buffer &o)
//   addSPIF(CTIL::CSM_Buffer &o)
//   enableCML(long session)
//   enableLDAP(char *dllFilename, char *serverName, long portNumber)
//   enableAutoRetrieve(bool bAutoRetrieve)
//   getAC(AC &ac)
//   getAC(MatchInfo &matchInfo)
//   getSPIF(SPIF &spif)
//   getSPIF(MatchInfo &matchInfo)
//   getCC(ClearanceCert &cc)
//   getCC(MatchInfo &matchInfo)
//   getCacheable(Cacheable &cacheable)
//   readConfig(char *pConfigFileName)
//   findTrust(CML::ASN::DN &DN, AsnOid &Id)
//   addTrust(CML::ASN::DN &dn, AsnOid &oid)
//   displayCache(ostream &os)
//   removeCache(Cacheable &item)
//   updateCache(Cacheable &item)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

#if defined(SunOS) || defined(Linux)
#include "dlfcn.h"
#endif

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL



/*class AclCache : public ACL_VList<Cacheable>{}; */

//typedef ACL_VList<acl::Cacheable> AclCache;

extern void CREATE_LDAP_HANDLE(char *dllFilename, char *serverName,
                         long portNumber, ulong **SRLsessionID);
extern void DESTROY_LDAP_HANDLE(ulong *);

Session::Session()
{
   m_pSRLsessionID = NULL;
   m_Internal_CML_Session = 0;
   m_External_CML_Session = 0;
   m_ttl = 0;
   m_dms_mode = false;
   m_disable_validation = true;
   m_disable_trustlist = true;
   m_bSpifSignerAttr = false;
   m_eCacheMode = LOCAL_THEN_REMOTE;
}


// DESTRUCTOR:
//
Session::~Session(void)
{
   if (m_pSRLsessionID != NULL)
   {
      DESTROY_LDAP_HANDLE(m_pSRLsessionID);
      free(m_pSRLsessionID);
      *m_pSRLsessionID = 0;
   }

   // IF an internal CML Session exists destroy it.
   //
   if (m_Internal_CML_Session != 0)
   {
      CM_DestroySession(&m_Internal_CML_Session);
      m_Internal_CML_Session = 0;
   }
} // END OF DESTRUCTOR

// usingLDAP:
// Returns true if LDAP is being used and
// false if it is not.
//
bool Session::usingLDAP(void)
{
   bool lRetVal=false;
   if (m_pSRLsessionID != NULL && m_disable_validation == false)
   {
      lRetVal = true;
   }
   return(lRetVal);
} // END OF MEMBER FUNCTION usingLDAP

// usingCML:
// Returns true if an external CML session is being used and
// false if it is not.
//
bool Session::usingCML(void)
{
   return (m_External_CML_Session != 0);
}
// END OF MEMBER FUNCTION usingCML

// usingAutoRetrieve:
// Returns value true if autoRetrieve is enabled
//
bool Session::usingAutoRetrieve(void)
{
   return(m_bAutoRetrieveFlag);
} // END OF MEMBER FUNCTION usingAutoRetrieve

// addAC:
//   INPUT: CTIL::CSM_Buffer - An encoded Attribute Certificate
//   OUTPUT: NONE
//   RETURN: NONE
//   THIS FUNCTION WILL CHECK CACHE (m_pCache) FOR THE PASSED ITEM THEN,
//   IF IT IS NOT FOUND, WILL ADD THE ITEM TO THE LIST
//
void Session::addAC(const CML::ASN::Bytes &o)
{
   AC newAC(o);
   updateCache(newAC);

} // END OF MEMBER FUNCTION addAC

// addCC:
//   INPUT: CTIL::CSM_Buffer - An encoded Clearance Certificate
//   OUTPUT: NONE
//   RETURN: NONE
//   THIS FUNCTION WILL CHECK CACHE (m_pCache) FOR THE PASSED ITEM THEN,
//   IF IT IS NOT FOUND, WILL ADD THE ITEM TO THE LIST
//
void Session::addCC(const CML::ASN::Bytes &o)
{
   ClearanceCert newCC(o);
   updateCache(newCC);
} // END OF MEMBER FUNCTION addCC

// addSPIF:
//   INPUT: CTIL::CSM_Buffer - An encoded Security Policy Information File
//   OUTPUT: NONE
//   RETURN: NONE
//   THIS FUNCTION WILL CHECK CACHE (m_pCache) FOR THE PASSED ITEM THEN,
//   IF IT IS NOT FOUND, WILL ADD THE ITEM TO THE LIST
//
void Session::addSPIF(const CML::ASN::Bytes &o)
{
   SPIF newSPIF(o);
   updateCache(newSPIF);
} // END OF MEMBER FUNCTION addSPIF

// enableCML:
//
void Session::enableCML(long session)
{
   m_External_CML_Session = session;
} // END OF MEMBER FUNCTION enableCML

// enableLDAP:
//
void Session::enableLDAP(char *dllFilename, char *serverName,
                         long portNumber)
{
   FUNC("Session::enableLDAP");
   try
   {
       if (m_pSRLsessionID)
           SRL_DestroySession(m_pSRLsessionID);

       CREATE_LDAP_HANDLE(dllFilename, serverName,
           portNumber, &m_pSRLsessionID);
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION enableLDAP

// enableAutoRetrieve:
//
void Session::enableAutoRetrieve(bool bAutoRetrieve)
{
   m_bAutoRetrieveFlag = bAutoRetrieve;
} // END OF MEMBER FUNCTION enableAutoRetrieve

// getAC:
//
AC *Session::getAC(AC &ac)
{
   return ((AC *) getCacheable(ac));
} // END OF MEMBER FUNCTION getAC

// getSPIF:
//
SPIF *Session::getSPIF(SPIF &spif)
{
   return ((SPIF *) getCacheable(spif));

} // END OF MEMBER FUNCTION getSPIF

// getCC:
//
ClearanceCert * Session::getCC(ClearanceCert &cc)
{
   return ((ClearanceCert *) getCacheable(cc));
} // END OF MEMBER FUNCTION getCC

// getCacheable:
//
Cacheable * Session::getCacheable(const Cacheable &cacheable)
{
   Cacheable *pRetVal = NULL;
   Cacheable *pCurr = NULL;

   FUNC("Session::getCacheable");
   try
   {
      AclCache::iterator i;
      for (i = m_cache.begin(); i != m_cache.end(); i++)
      {
         if ( cacheable == i->ref())
         {
            pRetVal = i->ref().clone();
            break;
         }
      }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return pRetVal;

} // END OF MEMBER FUNCTION getCacheable

// readConfig:
// GET FLAGS ONLY
//
long Session::readConfig(char *pConfigFileName)
{
   char       *pDefaultConfigFile="acl.cfg";
   char        sConfigFile[ACL_PATH_LEN];
   long        lStatus=ACL_NO_ERROR;
   KwValue     kwValue;
   KwValue     dllNameValue;
   KwValue     serverNameValue;
   KwValue     portNumberValue;
   long        status=0;
   char       *ldapSection = "enableLDAP";  // Search for this section name
   char       *cacheSection = "cache";      // Search for this section name
   char       *errFmtStr =
               "invalid %s Time To Live value (%d)\n\tMust be zero or greater\n";

   FUNC("Session::readConfig");
   try
   {
       if ((strlen(pConfigFileName)) != 0)
       {
          strcpy(sConfigFile, pConfigFileName);
       }
       else
       {
          strcpy(sConfigFile, pDefaultConfigFile);
       }

       ConfigFile CfgObj(sConfigFile);

       if (CfgObj.GetKwValue("dms_mode", kwValue) == 0)
       {
          if (strcmp(kwValue,"true") == 0)
          {
             this->m_dms_mode = true;
          }
       }

       // Look in Cache section for AC, SPIF and ClearanceCertificates TTL
       // (TimeToLive) parameters
       //
       if (CfgObj.GetKwValue("ttl", kwValue, cacheSection) == 0)
       {
          this->m_ttl = atol(kwValue);
          // ENSURE THERE ARE NO TIME TO LIVE VALUES LESS THAN ZERO
          if (this->m_ttl < 0)
          {
             throw ACL_EXCEPT(ACL_CFG_ERROR, "Error parsing time to live field");
          }
       }

       if (CfgObj.GetKwValue("enableAutoRetrieve", kwValue, ldapSection) == 0)
       {
          if (strcmp(kwValue,"true") == 0)
             this->m_bAutoRetrieveFlag = true;
       }

       // Look in the enableLDAP section for the LDAP DLL name
       //
#ifdef WIN32
       status = CfgObj.GetKwValue("windllFilename", dllNameValue, ldapSection);
#else
       status = CfgObj.GetKwValue("unixdllFilename", dllNameValue, ldapSection);
#endif
       if (status != -2) // if section was found
       {
          if (status != 0) // if dllFilename keyword wasn't found
          {
             throw ACL_EXCEPT(ACL_CFG_ERROR,
                "enableLDAP section present but,\n\tmissing dllFilename keyword");
          }

          if (CfgObj.GetKwValue("serverName", serverNameValue, ldapSection) != 0)
          {
             throw ACL_EXCEPT(ACL_CFG_ERROR,
                "enableLDAP section present but,\n\tmissing serverName keyword");
          }

          if (CfgObj.GetKwValue("portNumber", portNumberValue, ldapSection) != 0)
          {
             throw ACL_EXCEPT(ACL_CFG_ERROR,
                "enableLDAP section present but,\n\tmissing portNumber keyword");
          }
          else
          {
             long lPortNumber=0;
             long lRtn=0;
             bool bAlpha=false;

             for (int i=0; i<(int)(strlen(portNumberValue)); i++)
             {
                lRtn = isalpha(portNumberValue[i]);
                if (lRtn != 0)
                {
                   bAlpha = true;
                   break;
                }
             }

             if (bAlpha == false)
             {
                lPortNumber = atol(portNumberValue);
             }

             if ((bAlpha == true) || (lPortNumber == 0))
             {
                throw ACL_EXCEPT(ACL_CFG_ERROR,
                   "invalid LDAP port Number");
             }

             lPortNumber = atol(portNumberValue);

             enableLDAP(dllNameValue, serverNameValue, lPortNumber);
          }

       }

   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return(lStatus);
} // END OF MEMBER FUNCTION readConfig

// findTrust:
//
bool Session::findTrust(const CML::ASN::DN &DN, const AsnOid &Id)
{
   if (m_trustList.size() > 0 && m_disable_trustlist == false)
   {
      TrustList::iterator i;

      for(i = m_trustList.begin(); i != m_trustList.end(); i++)
      {
         if (DN == i->GetDN() && Id == i->GetOid())
         {
               return(true);
         }
      }
   }
   return(false);
} // END OF MEMBER FUNCTION findTrust

// addTrust:
// Add the new DN and OID to the trustlist if the DN and the OID
// do not already exist in the list as a pair
//
int Session::addTrust(const CML::ASN::DN& dn, const AsnOid& oid)
{
   int retval = 0;

   TrustList::iterator i;
   for (i = m_trustList.begin(); i != m_trustList.end(); i++)
   {
      if ((dn == i->GetDN()) && (oid == i->GetOid()))
      {
         return(ACL_TRUST_EXISTS);
      }
   }
   i = m_trustList.insert(m_trustList.end(), Trust());
   i->setOID(oid);
   i->setDN(dn);

   return (retval);
} // END OF MEMBER FUNCTION addTrust

// displayCache:
//
void Session::displayCache(AclString &str)
{
   AclCache::iterator i;

   if (m_cache.size() == 0)
   {
      str << "Nothing in Cache\n";
   }
   else
      for (i = m_cache.begin(); i != m_cache.end(); i++)
      {
         #ifdef _DEBUG
         try {                 //RWC;
         #endif  // _DEBUG
         i->ref().getDescription(str);
         #ifdef _DEBUG
         } catch(...) {};      //RWC;IGNORE bad report(s).
         #endif  // _DEBUG
      }


} // END OF MEMBER FUNCTION displayCache

// removeCache:
//
void Session::removeCache(const Cacheable &item)
{
   AclCache::iterator i;

   i = m_cache.begin();
   while(i != m_cache.end())
   {
      if (i->ref() == item)
      {
         m_cache.erase(i);
         break;
      }
      else
      {
         i++;
      }
   }
} // END OF MEMBER FUNCTION removeCache

// updateCache:
//
void Session::updateCache(const Cacheable &item)
{
   bool found = false;

   FUNC("Session::updateCache");

   // find in cache first
   //
   try
   {
      AclCache::iterator i;

      i = m_cache.begin();
      while(i != m_cache.end())
      {
         if (i->ref() == item)
         {
            // Found in Cache so remove it and add item
            found = true;

            // Remove current element
            m_cache.erase(i);
            AclCache::iterator newNode = m_cache.insert(m_cache.end(), item);
            newNode->ref().updateTTL(m_ttl);
            break;
         }
         else
         {
            i++;
         }
      }

      if (! found)
      {
          AclCache::iterator newNode = m_cache.insert(m_cache.end(), item);
          newNode->ref().updateTTL(m_ttl);
      }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

} // END OF MEMBER FUNCTION updateCache

// updateTTL:
//


ACList * Session::getAC(MatchInfo &matchInfo)
{
   ACList    *retval=NULL;
   long       lFound=0;
   long       lACs=0;
   Cacheable *pTmpCache=NULL;

   // IF cache is not set to remote only then look in cache
   // first
   if (m_eCacheMode != REMOTE)
   {
      AclCache::iterator i;
      for(i = m_cache.begin(); i != m_cache.end(); i++)
      {
         // IS THIS AN ATTRIBUTE CERTIFICATE
         if (i->ref().type == Cacheable::ACERT_ID)
         {
            lACs++;  // INCREMENT THE AC COUNTER
            if (i->ref().matches(matchInfo))
            {
               lFound++;
               if (retval == NULL)
               {
                  retval = new ACList;
               }
               const acl::AC &objRef = (acl::AC &) i->ref();
               retval->push_back(objRef);
            }
         }
      }
   }

   const CML::ASN::DN *pSubjectDN = matchInfo.getSubjectDN();

   // IF THERE IS NO MATCH OF THE PASSED DN AND OPTIONAL POLICYID, THEN NEED
   // TO GET THE AC FROM THE DIRECTORY
   if (lFound == 0 && usingLDAP() && m_eCacheMode != LOCAL && pSubjectDN != NULL)
   {
      CML::ASN::BytesList *pBufList;

      pBufList = LdapRequest((CML::ASN::DN *) pSubjectDN,
          Cacheable::ACERT_ID, m_pSRLsessionID);
      if ((pBufList != NULL) && (pBufList->size() > 0))
      {
         CML::ASN::BytesList::iterator i;
         AC *pTmpAC = NULL;
         for (i = pBufList->begin(); i != pBufList->end(); i++)
         {
            AC tmpAC(*i);

            if (tmpAC.matches(matchInfo))
            {
               if (retval == NULL)
               {
                  retval = new ACList;
               }
               retval->push_back(tmpAC);
               this->updateCache(tmpAC);
            }
         }
      }
   }
   return(retval);
}

SPIFList * Session::getSPIF(MatchInfo &matchInfo)
{
   SPIFList    *retval=NULL;
   long       lFound=0;
   long       lSPIFs=0;
   Cacheable *pTmpCache=NULL;

   // IF cache is not set to remote only then look in cache
   // first
   if (m_eCacheMode != REMOTE)
   {
      AclCache::iterator i;
      for (i = m_cache.begin(); i != m_cache.end(); i++)
      {
         // IS THIS A SPIF
         if (i->ref().type == Cacheable::ACSPIF_ID)
         {
            lSPIFs++;  // INCREMENT THE SPIF COUNTER
            if (i->ref().matches(matchInfo))
            {
               lFound++;
               if (retval == NULL)
               {
                  retval = new SPIFList;
               }
               const SPIF &tmpSPIF = (SPIF &) i->ref();
               retval->push_back(tmpSPIF);
            }
         }
      }
   }

   const CML::ASN::DN *pIssuerDN = matchInfo.getIssuerDN();

   // IF THERE IS NO MATCH OF THE PASSED DN AND OPTIONAL POLICYID, THEN NEED
   // TO GET THE SPIF FROM THE DIRECTORY
   if (lFound == 0 && usingLDAP() && m_eCacheMode != LOCAL && pIssuerDN != NULL)
   {
      CML::ASN::BytesList *pBufList = NULL;
      pBufList = LdapRequest( (CML::ASN::DN *) pIssuerDN,
          Cacheable::ACSPIF_ID, m_pSRLsessionID);
      if ((pBufList != NULL) && (pBufList->size() > 0))
      {
         CML::ASN::BytesList::iterator i;

         for (i = pBufList->begin(); i != pBufList->end(); i++)
         {
            SPIF tmpSPIF(*i);
            if (tmpSPIF.matches(matchInfo))
            {
               if (retval == NULL)
               {
                  retval = new SPIFList;
               }
               retval->push_back(tmpSPIF);
               this->updateCache(tmpSPIF);
            }
         }
      }
   }
   return(retval);
}

CCList * Session::getCC(MatchInfo &matchInfo)
{
   CCList    *retval=NULL;
   long       lFound=0;
   long       lCCs=0;
   Cacheable *pTmpCache=NULL;

   // IF cache is not set to remote only then look in cache
   // first
   if (m_eCacheMode != REMOTE)
   {
      AclCache::iterator i;
      for (i = m_cache.begin(); i != m_cache.end(); i++)
      {
         // IS THIS A CLEARANCE CERTIFICATE
         if (i->ref().type == Cacheable::ACLRCERT_ID)
         {
            lCCs++;  // INCREMENT THE CC COUNTER
            if (i->ref().matches(matchInfo))
            {
               lFound++;
               if (retval == NULL)
               {
                  retval = new CCList;
               }
               const ClearanceCert &cc = (ClearanceCert &) i->ref();
               retval->push_back(cc);
            }
         }
      }
   }

   const CML::ASN::DN *pSubjectDN = matchInfo.getSubjectDN();

   // REN -- 4/16/04 -- If there was not match in the ACL cache, try to
   // retrieve the CC from the local database
   if ((lFound == 0) && (m_eCacheMode == LOCAL_THEN_REMOTE) &&
      (pSubjectDN != NULL))
   {
     // Build the CertMatchData
      CML::CertMatchData cMatchInfo;
      memset(&cMatchInfo, '\0', sizeof(cMatchInfo));
      if (matchInfo.getIssuerDN())
         cMatchInfo.pIssuer = matchInfo.getIssuerDN();
      if (matchInfo.getSerialNo())
         cMatchInfo.pSerialNum = matchInfo.getSerialNo();
      if (matchInfo.getSubjectDN())
         cMatchInfo.pSubjKeyID = matchInfo.getSubjectKeyId();

     // Call the CML to retrieve the issuer certs locally
      CML::ASN::BytesList certList;
      short cml_status = CML::RequestCerts(getCMLHandle(), certList,
         *pSubjectDN, CM_SEARCH_LOCAL, &cMatchInfo);
      if (cml_status == CM_NO_ERROR)
      {
         // Copy the found certs into the resulting list
         CML::ASN::BytesList::const_iterator iEncCert = certList.begin();
         for ( ; iEncCert != certList.end(); ++iEncCert)
         {
            if (retval == NULL)
               retval = new CCList;
            retval->push_back(*iEncCert);
         ++lFound;
         }
      }
   }

   // IF THERE IS NO MATCH OF THE PASSED DN AND OPTIONAL POLICYID, THEN NEED
   // TO GET THE CC FROM THE DIRECTORY
   if (lFound == 0 && usingLDAP() && m_eCacheMode != LOCAL && pSubjectDN != NULL)
   {
      CML::ASN::BytesList *pBufList = NULL;
      pBufList = LdapRequest((CML::ASN::DN *) pSubjectDN,
          Cacheable::ACLRCERT_ID, m_pSRLsessionID);
      if ((pBufList != NULL) && (pBufList->size() > 0))
      {
         CML::ASN::BytesList::iterator i;
         for (i = pBufList->begin(); i != pBufList->end(); i++)
         {
            ClearanceCert tmpCC(*i);
            if (tmpCC.matches(matchInfo))
            {
               if (retval == NULL)
               {
                  retval = new CCList;
               }
               retval->push_back(tmpCC);
            }
         }
      }
   }
   return(retval);
}

unsigned long Session::getCMLHandle(void)
{
   FUNC("getCMLHandle()");
   try
   {
       if (m_External_CML_Session != 0)
          return m_External_CML_Session;
       else if (m_Internal_CML_Session != 0)
          return m_Internal_CML_Session;
       else
          throw ACL_EXCEPT(ACL_CML_ERROR,"No internal CML session present");
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
}
_END_NAMESPACE_ACL

// EOF aclsession.cpp

