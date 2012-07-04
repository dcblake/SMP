
//////////////////////////////////////////////////////////////////////////
//  sm_mabRout.cpp
//  This set of routines support the MSP test address book 
//  identifying the location and DN of binary certificates.
#include <malloc.h>
#ifdef WIN32
#include <conio.h>
#include <stdlib.h>
#endif
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "sm_apiCert.h"

_BEGIN_CERT_NAMESPACE 
using namespace SNACC;

#define MAB_MAX_ENTRY_LEN 2048
#define MAB_PATH_KW "PATH="
#define MAB_ENTRY_KW "ENTRY="
#define MAB_NULL_VALUE "MAB_NULL"
#define MAB_DEFAULT_AB_FN "./certs/mabRecips.dat"
#define MAB_CRL_PATH_KW "CRL_PATH="

//////////////////////////////////////////////////////////////////////////
// convert null terminated string to all upper case
void MABtoupper(char *pszDest, char *pszSrc)
{
   int n;
   for (n=0; n < (int)strlen(pszSrc); n++)
      pszDest[n] = (char)toupper(pszSrc[n]);
   pszDest[n] = '\0';
}

//////////////////////////////////////////////////////////////////////////
//  MABInit
//  This routine initializes access to the address book data structures.
SM_RET_VAL MAB_AB_def::Init(char *pszFileName)
{
   FILE *fp = NULL;
   MAB_Entrydef *pNewEntry;
   char szLine[MAB_MAX_ENTRY_LEN];
   char *pchTmpBuf;
   char tmpBuf2[512];
   char *pszField;  // used in strtok-ing the input line

   SME_SETUP("MAB_AB_def::Init");

   m_szCrlPath[0] = '\0';

   if (pszFileName == NULL)
      SME_THROW(SM_MISSING_PARAM, "No mab file name provided", NULL);

   // the format of this file allows for comments, '#', the format of
   // the entries is as follows:
   // ENTRY=alias:DN:CertFN:PrivateKeyInfo:PrivateKeyOID
   //
   // fields that can be and are null must contain MAB_NULL

   // open the provided address book file
   if ((fp = fopen(pszFileName, "r")) == NULL)
      SME_THROW(SM_MAB_ERROR, "couldn't open mab file", NULL);

   // read the entires
   while (fgets(szLine, MAB_MAX_ENTRY_LEN, fp) != NULL)
   {
      if (szLine[0] != '#') // ignore comment lines
      {
         if (strncmp(szLine, MAB_PATH_KW, strlen(MAB_PATH_KW)) == 0)
         {
            // copy path
            strcpy(m_szGlobalPath, &szLine[(strlen(MAB_PATH_KW))]);
            // remove return
            if (m_szGlobalPath[strlen(m_szGlobalPath)-1] == '\n' ||
                m_szGlobalPath[strlen(m_szGlobalPath)-1] == 0x0d ||
                m_szGlobalPath[strlen(m_szGlobalPath)-1] == 0x0a)
               m_szGlobalPath[strlen(m_szGlobalPath)-1] = '\0';
            if (m_szGlobalPath[strlen(m_szGlobalPath)-1] == '\n' ||
                m_szGlobalPath[strlen(m_szGlobalPath)-1] == 0x0d ||
                m_szGlobalPath[strlen(m_szGlobalPath)-1] == 0x0a)
               m_szGlobalPath[strlen(m_szGlobalPath)-1] = '\0';
         }
         else if (strncmp(szLine, MAB_CRL_PATH_KW, strlen(MAB_CRL_PATH_KW)) == 0)
         {
            // copy path
            strcpy(m_szCrlPath, &szLine[(strlen(MAB_CRL_PATH_KW))]);
            // remove return
            if (m_szCrlPath[strlen(m_szCrlPath)-1] == '\n' ||
                m_szCrlPath[strlen(m_szCrlPath)-1] == 0x0d ||
                m_szCrlPath[strlen(m_szCrlPath)-1] == 0x0a)
                m_szCrlPath[strlen(m_szCrlPath)-1] = '\0';
            if (m_szCrlPath[strlen(m_szCrlPath)-1] == '\n' ||
                m_szCrlPath[strlen(m_szCrlPath)-1] == 0x0d ||
                m_szCrlPath[strlen(m_szCrlPath)-1] == 0x0a)
                m_szCrlPath[strlen(m_szCrlPath)-1] = '\0';
         }
         else if (strncmp(szLine, MAB_ENTRY_KW, strlen(MAB_ENTRY_KW)) 
               == 0)
         {
            // put the entry in the list
            if (m_pEntries == NULL)
               if ((m_pEntries = new List<MAB_Entrydef>) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            // create new entry
            if ((pNewEntry = &(*m_pEntries->append())) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

            // point at first field
            pchTmpBuf = &szLine[strlen(MAB_ENTRY_KW)]; 

            // get the alias field, mandatory
            if ((pszField = strtok(pchTmpBuf, ":")) == NULL)
               SME_THROW(SM_MAB_ERROR, "failed getting alias", NULL);
            if ((pNewEntry->m_pszAlias = strdup(pszField)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

            // get the cert subject dn field, mandatory
            if ((pszField = strtok(NULL, ":")) == NULL)
               SME_THROW(SM_MAB_ERROR, "failed getting subject dn", NULL);
            if ((pNewEntry->m_pszCertificateDN = strdup(pszField)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            // make all X.500 DNs upper case 
            // (case insensitive for compares)
#ifdef SM_CASE_INSENSITIVE
            MABtoupper(pNewEntry->m_pszCertificateDN, 
                  pNewEntry->m_pszCertificateDN);
#endif
            // get the cert file name, mandatory
            if ((pszField = strtok(NULL, ":")) == NULL)
               SME_THROW(SM_MAB_ERROR, "failed getting cert fn", NULL);
            // start with the global path
            strcpy(&tmpBuf2[0], m_szGlobalPath);
            // concatenate cert FN onto temp buffer
            strcat(&tmpBuf2[0], pszField);
            // store cert FN in buffer
            pNewEntry->m_pCertFile = new CSM_Buffer(tmpBuf2);

            // get the private key path, optional
            if ((pszField = strtok(NULL, ":")) != NULL)
            { // RWC;SME_THROW(SM_MAB_ERROR, "failed getting private key", NULL);
              // if private key is not null, store it in a buffer
              if (strcmp(pszField, MAB_NULL_VALUE) != 0)
               if ((pNewEntry->m_pPrivateInfo = new CSM_Buffer(pszField)) 
                     == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            }

            // get the private key oid, optional
            if ((pszField = strtok(NULL, ":")) == NULL)
               SME_THROW(SM_MAB_ERROR, "failed getting private key oid", 
                     NULL);
            // strip off extra char if necessary
            int jj=strlen(pszField)-1;
            if ((pszField[jj] == '\n') ||
                  (pszField[jj] == '\r') ||
                  (pszField[jj] == 0x0a) ||
                  (pszField[jj] == 0x0d))
               pszField[jj] = '\0';
            jj--;       // sometimes there are 2.
            if ((pszField[jj] == '\n') ||
                  (pszField[jj] == '\r') ||
                  (pszField[jj] == 0x0a) ||
                  (pszField[jj] == 0x0d))
               pszField[jj] = '\0';
            // if private key is not null, store it in a buffer
            if (strcmp(pszField, MAB_NULL_VALUE) != 0)
               pNewEntry->m_pPrivateOID = new AsnOid(pszField);

         } // end if MAB_ENTRY_KW handler
      } // end if comment check
   } // end of while loop to read mab file
   
   fclose(fp);

   SME_FINISH
   SME_CATCH_SETUP
      if (fp != NULL)
         fclose(fp);
      // TBD, more catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
MAB_AB_def::MAB_AB_def()
{
   m_pEntries = NULL;
   Init(MAB_DEFAULT_AB_FN);
}

//////////////////////////////////////////////////////////////////////////
MAB_AB_def::MAB_AB_def(char *pszFileName)
{
   m_pEntries = NULL;
   Init(pszFileName);
}

//////////////////////////////////////////////////////////////////////////
MAB_AB_def::MAB_AB_def(MAB_AB_def &mab)
{
   List<MAB_Entrydef>::iterator itEntry;

   SME_SETUP("MAB_AB_def::MAB_AB_def(MAB_AB_def&)");

   m_pEntries = NULL;
   if (mab.m_pEntries)
   {
      for (itEntry =  mab.m_pEntries->begin();
           itEntry  != mab.m_pEntries->end();
           ++itEntry)
      {
         if (m_pEntries == NULL)
            if ((m_pEntries = new List<MAB_Entrydef>) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);

         m_pEntries->append(*itEntry);
      }
   }

   memcpy(&m_szGlobalPath[0], &(mab.m_szGlobalPath[0]), 256);
   memcpy(&m_szCrlPath[0], &(mab.m_szCrlPath[0]), 256);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL MAB_AB_def::FindCertDN(char *pszDN, CSM_Buffer *result)
{
   SM_RET_VAL lStatus = -1;
   MAB_Entrydef *pRec = (MAB_Entrydef *)NULL;

   if ((pRec = FindRecord(pszDN, MABTYPE_DN)) != (MAB_Entrydef *)NULL)
   {
      if (result && pRec->m_pCertFile)
      {
         *result = *pRec->m_pCertFile;
         lStatus = SM_NO_ERROR;
      }
   }
   return lStatus;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL MAB_AB_def::FindCertAlias(char *pszAlias, CSM_Buffer *result)
{
   SM_RET_VAL lStatus = -1;
   MAB_Entrydef *pRec = (MAB_Entrydef *)NULL;

   if ((pRec=FindRecord(pszAlias, MABTYPE_ALIAS)) != (MAB_Entrydef *)NULL)
   {
      if (result && pRec->m_pCertFile)
      {
         *result = *pRec->m_pCertFile;
         lStatus = SM_NO_ERROR;
      }
   }
   return lStatus;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL MAB_AB_def::FindSKI(CSM_Buffer &csmSKI, CSM_Buffer *result)
{
   SM_RET_VAL lStatus = SM_NOT_FOUND;
   List<MAB_Entrydef>::iterator itEntry;
   
   if (m_pEntries)
   {
      for (itEntry =  m_pEntries->begin();
           itEntry != m_pEntries->end();
           ++itEntry)
      {
            CSM_CertificateChoice tmpCert(*itEntry->m_pCertFile);
            CSM_Identifier *ptmpId=tmpCert.GetRid(false);
            if (ptmpId && ptmpId->AccessSubjectKeyIdentifier() &&
                *ptmpId->AccessSubjectKeyIdentifier() == csmSKI)
            {
               *result = *itEntry->m_pCertFile;
               lStatus = SM_NO_ERROR;
               delete ptmpId;
               break;
            }   // END IF ptmpId
      }     // END FOR each entry in list.
   }
   return lStatus;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL MAB_AB_def::FindIssuer(CSM_IssuerAndSerialNumber &csmIssuer, 
                            CSM_Buffer *result)
{
   SM_RET_VAL lStatus = SM_NOT_FOUND;
   List<MAB_Entrydef>::iterator itEntry;
   
   if (m_pEntries)
   {
      for (itEntry =  m_pEntries->begin();
           itEntry != m_pEntries->end();
           ++itEntry)
      {
            CSM_IssuerAndSerialNumber *p2=itEntry->GetIssuer();
            if (p2 && csmIssuer == *p2)
            {
               *result = *itEntry->m_pCertFile;
               lStatus = SM_NO_ERROR;
               break;
            }
      }     // END FOR each entry in list.
   }
   return lStatus;
}

//////////////////////////////////////////////////////////////////////////
MAB_Entrydef *MAB_AB_def::FindRecord(char *pszID, long lType)
{
   MAB_Entrydef *result = NULL;
   long lStat = SM_NOT_FOUND;
   char szUpperID[512];
   List<MAB_Entrydef>::iterator itEntry;

   if (m_pEntries)
   {
#ifdef SM_CASE_INSENSITIVE
      MABtoupper(szUpperID, pszID);
#else
      strcpy(szUpperID, pszID);
#endif
      for (itEntry =  m_pEntries->begin();
           itEntry != m_pEntries->end();
           ++itEntry)
      {
            if (lType == MABTYPE_DN)
               lStat = (long)strcmp(itEntry->m_pszCertificateDN, 
                     szUpperID);
            else if (lType == MABTYPE_ALIAS)
               lStat = (long)strcmp(itEntry->m_pszAlias, szUpperID);
            if (lStat == SM_NO_ERROR)
            {
               result = &(*itEntry);
               break;
            }
      }     // END FOR each entry in list.
   }
   return result;
}


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL MAB_AB_def::FillCertPath(
    CSM_CertificateChoice *pCertToPath,
    CSM_MsgCertCrls *pMsgCertCrls)
{
   int status=0;
   char *pTmpIssuerDN=(char *)calloc(1,4096);
   char *pTmpSubjectDN=(char *)calloc(1,4096);
   CSM_CertificateChoice *pTmpCert = NULL;
   CSM_CertificateChoice *pTmpCert2 = NULL;
   CSM_CertificateChoice *pTmpCertChoice = NULL;
   CSM_DN *pSubjectDN = NULL;
   CSM_DN *pIssuerDN = NULL;

   SME_SETUP("MAB_AB_def::FillCertPath");
      pTmpCertChoice = pCertToPath;    // Assign first cert in list.
      pSubjectDN = pTmpCertChoice->GetSubject();
      pIssuerDN = pTmpCertChoice->GetIssuer();
#ifdef SM_CASE_INSENSITIVE
      char *pTmpIssuerDNString = (char *) calloc(1,4096);
      char *pTmpSubjectDNString = (char *) calloc(1, 4096);

      pTmpIssuerDNString = pIssuerDN->GetDNString();
      pTmpSubjectDNString = pSubjectDN->GetDNString();

      MABtoupper(pTmpIssuerDN, pTmpIssuerDNString);
      MABtoupper(pTmpSubjectDN, pTmpSubjectDNString);

      free(pTmpIssuerDNString);
      free(pTmpSubjectDNString);
#else           // CASE Sensitive for NOW.
      free(pTmpIssuerDN);
      pTmpIssuerDN = (char *)(const char *)*pIssuerDN;
      free(pTmpSubjectDN);
      pTmpSubjectDN = (char *)(const char *)*pSubjectDN;
#endif
      while(pTmpCertChoice && strcmp(pTmpIssuerDN, pTmpSubjectDN) != 0)
      {                   // STOP at root PCA/CA; IssuerDN=SubjectDN.
        List<MAB_Entrydef>::iterator itEntry;
        pTmpCert = NULL;        // FLAG that not found.
        for (itEntry =  m_pEntries->begin();
             itEntry != m_pEntries->begin();
             ++itEntry)
        {
          if (strcmp(pTmpIssuerDN, itEntry->m_pszCertificateDN) == 0)
          {
            CSM_IssuerAndSerialNumber *pTmpIssSN;
            SME(pTmpCert = new CSM_CertificateChoice(
                *itEntry->m_pCertFile));
            SME(pTmpIssSN = 
                new CSM_IssuerAndSerialNumber(itEntry->m_pCertFile));
            pTmpCert2 = pMsgCertCrls->FindCert(*pTmpIssSN);
            if (pTmpCert2 == NULL)
            {
               pMsgCertCrls->AddCert(pTmpCert); // ONLY if not already present
               delete pTmpCert; // sib 9/27/02 AddCert no longer deletes pTmpCert
               pTmpCert = NULL;
            }
            else
            {
                delete pTmpCert2;
                pTmpCert2 = NULL;
                delete pTmpCert;
                pTmpCert = NULL;
            }
            delete pTmpIssSN;

            status = SM_NO_ERROR;
            break;
          }
        }

        // DO NOT DELETE pTmpCert, it is assigned to pMsgCertCrls through 
        //   the CSM_List class Append().
        if (pTmpCert != NULL)             // FOUND one.
        {
          pTmpCertChoice = pTmpCert;
          pSubjectDN = pTmpCertChoice->GetSubject();
          pIssuerDN = pTmpCertChoice->GetIssuer();
#ifdef SM_CASE_INSENSITIVE
      char *pTmpIssuerDNString = (char *) calloc(1,4096);
      char *pTmpSubjectDNString = (char *) calloc(1, 4096);

      pTmpIssuerDNString = pIssuerDN->GetDNString();
      pTmpSubjectDNString = pSubjectDN->GetDNString();

      MABtoupper(pTmpIssuerDN, pTmpIssuerDNString);
      MABtoupper(pTmpSubjectDN, pTmpSubjectDNString);

      free(pTmpIssuerDNString);
      free(pTmpSubjectDNString);
#else           // CASE Sensitive for NOW.
          free(pTmpIssuerDN);
          pTmpIssuerDN = strdup((const char *)*pIssuerDN);
          free(pTmpSubjectDN);
          pTmpSubjectDN = strdup((const char *)*pSubjectDN);
#endif
          delete pSubjectDN;
          delete pIssuerDN;
        }
        else
            pTmpCertChoice = NULL;
      }             // END While certs to process.

      SME_FINISH_CATCH

    return(status);
}


//////////////////////////////////////////////////////////////////////////
MAB_AB_def::~MAB_AB_def()
{
   if (m_pEntries != NULL)
      delete m_pEntries;
}

//////////////////////////////////////////////////////////////////////////
CSM_IssuerAndSerialNumber *MAB_Entrydef::GetIssuer()
{
   if (!m_pIssuer)
      m_pIssuer = new CSM_IssuerAndSerialNumber(m_pCertFile);
   return(m_pIssuer);
}

//////////////////////////////////////////////////////////////////////////
Certificate *MAB_Entrydef::GetCertificate()
{
    SME_SETUP("MAB_Entrydef::GetCertificate");
   if (!m_pCertificate)
   {
      if (m_pCertFile)
      {
         DECODE_BUF(m_pCertificate, m_pCertFile);
      }
   }
    SME_FINISH_CATCH
   return(m_pCertificate);
}

//////////////////////////////////////////////////////////////////////////
MAB_Entrydef::MAB_Entrydef(const MAB_Entrydef &entry)
{
   *this = entry;
}

//////////////////////////////////////////////////////////////////////////
MAB_Entrydef &MAB_Entrydef::operator = (const MAB_Entrydef &entry)
{
   SME_SETUP("MAB_Entrydef::MAB_Entrydef(MAB_Entrydef&)");

   Clear();

   if (entry.m_pszAlias)
      m_pszAlias = strdup(entry.m_pszAlias);
   if (entry.m_pszCertificateDN)
      m_pszCertificateDN = strdup(entry.m_pszCertificateDN);
   if (entry.m_pCertFile)
      m_pCertFile = new CSM_Buffer(*entry.m_pCertFile);
   if (entry.m_pPrivateInfo)
      m_pPrivateInfo = new CSM_Buffer(*entry.m_pPrivateInfo);
   if (entry.m_pPrivateOID)
      m_pPrivateOID = new AsnOid(*entry.m_pPrivateOID);

   SME_FINISH_CATCH
   return(*this);
}

//////////////////////////////////////////////////////////////////////////
MAB_Entrydef::~MAB_Entrydef()
{
   if (m_pCertificate)
      delete m_pCertificate;
   if (m_pIssuer)
      delete m_pIssuer;
   if (m_pszAlias)
      free(m_pszAlias);
   if (m_pszCertificateDN)
      free(m_pszCertificateDN);
   if (m_pCertFile)
      delete m_pCertFile;
   if (m_pPrivateInfo)
      delete m_pPrivateInfo;
   if (m_pPrivateOID)
      delete m_pPrivateOID;
}

_END_CERT_NAMESPACE 

// EOF sm_mabRout.cpp
