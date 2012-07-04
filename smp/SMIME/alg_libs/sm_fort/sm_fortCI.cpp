#include "sm_fort.h"
#include "cryptint.h"
using namespace CERT;
// These classes are for handling Fortezza card card operations.  Like 
// retrieving Personality Lists, Downloading Certificates, etc.. etc..
//

// CSM_FortPersList Functions

CSM_FortezzaCardInfo::CSM_FortezzaCardInfo(int nSocket)
{
   int error = 0;

   SME_SETUP("CSM_FortezzaCardInfo::CSM_FortezzaCardInfo()");

   error = SetSocket(nSocket);
   if (error != CI_OK)
      SME_THROW(error, "SetSocket() failed", NULL);

   LoadPersonalities();

   SME_FINISH_CATCH;
}

long CSM_FortezzaCardInfo::SetSocket(int nSocket)
{
   long error = 0;

   m_nSocket = nSocket;

   error = CI_Open(CI_NULL_FLAG, m_nSocket);
   if (error != CI_OK)
      return error;

   error = CI_GetConfiguration(&m_config);
   if (error != CI_OK)
      return error;

   return error;
}

long CSM_FortezzaCardInfo::SetSocketNoOpen(int nSocket)
{
   long error = 0;

   m_nSocket = nSocket;

   //error = CI_Open(CI_NULL_FLAG, m_nSocket);
   //if (error != CI_OK)
   //   return error;

   error = CI_GetConfiguration(&m_config);
   if (error != CI_OK)
      return error;

   return error;
}

void CSM_FortezzaCardInfo::Set(const CSM_FortezzaCardInfo &o)
{
   m_currIndex = o.m_currIndex;
   m_nSocket = o.m_nSocket;
   memcpy(&m_config, &o.m_config, sizeof(CI_CONFIG));

   if (o.mp_perList != NULL)
   {
      if (mp_perList != NULL)
         free(mp_perList);

      mp_perList = (CI_PERSON *) calloc(1, (sizeof(CI_PERSON) * m_config.CertificateCount));

      memcpy((char *) mp_perList, (char *) o.mp_perList, 
             sizeof(CI_PERSON) * m_config.CertificateCount);
   }
}

void CSM_FortezzaCardInfo::Clear(void)
{
   mp_perList = NULL;
   m_currIndex = -1;
   m_nSocket   = -1;
   memset((char *) &m_config, 0, sizeof(CI_CONFIG));
}




void CSM_FortezzaCardInfo::LoadPersonalities(void)
{
   CI_STATUS_PTR pStatus = new CI_STATUS;
   long error = 0;

   m_currIndex = 0;

   SME_SETUP("CSM_FortezzaCardInfo::LoadPersonalities()");
   
   error = CI_GetStatus(pStatus);
   delete pStatus;   // CLEAR memory under all circumstances.

   if (error != CI_OK)
      SME_THROW(error, "CI_GetStatus() failed", NULL);

   if (!error)
   {
      mp_perList = (CI_PERSON *) calloc(1, (sizeof(CI_PERSON) * m_config.CertificateCount));
      //RWC;7/22/00;CHANGED to be consistent, based no BoundsChecker results
      //RWC;7/22/00;mp_perList = new CI_PERSON[m_config.CertificateCount];
     
      error = CI_GetPersonalityList( m_config.CertificateCount, 
                                     mp_perList);
      if (error != CI_OK)
         SME_THROW(error,"CI_GetPersonalityList() failed", NULL);
   }

   SME_FINISH_CATCH;
}


// NextSlot()
//
// Increment current index by one.
//
// > 0 success < 1 failure
//
// note: no exception handling
//
SM_RET_VAL CSM_FortezzaCardInfo::NextSlot() 
{
   if (m_currIndex < m_config.CertificateCount) 
      return (m_currIndex++); 
   else 
      return -1;
}

// GetSlot()
//
// return certificate index which the current index is
// pointing to.
//
// > 0 success < 1 failure
//
// note: no exception handling
//
SM_RET_VAL CSM_FortezzaCardInfo::GetSlot() 
{ 
  if (mp_perList == NULL)
     LoadPersonalities();
  
  if (m_currIndex < m_config.CertificateCount)
     return mp_perList[m_currIndex].CertificateIndex;
  else 
     return -1;
}


// SetSlot()
//
// Set current index to nSlot.  The index is always one less than
// the slot.
//
//  0 == success, 1 == failure
//
SM_RET_VAL CSM_FortezzaCardInfo::SetSlot(int nSlot)
{
   char errStr[128];

   SME_SETUP("CSM_FortezzaCardInfo::SetSlot()");

   if (nSlot > 0 && nSlot <= m_config.CertificateCount)
   {
      m_currIndex = nSlot - 1;  // index is always one less than slot
      return 0;
   }
   else
   {
      sprintf(errStr,"Invalide slot [%d] specified", nSlot);
      SME_THROW(CI_INV_CERT_INDEX, errStr, NULL);
      return 1;
   }

   SME_FINISH_CATCH;
}


// ParentSlot()
//
// Use the Usage Equipment (UE) specifier to determine the 
// parent index of the current slot.  Then set the current
// index by calling SetSlot().
//
SM_RET_VAL CSM_FortezzaCardInfo::ParentSlot()
{
   char pcszParentSlot[3];
   int  nParentSlot = 0;
   SM_RET_VAL error = 0;

   SME_SETUP("CSM_FortezzaCardInfo::ParentSlot()");

   memset(pcszParentSlot, 0, 3);

   // Copy the parent field from the UE of the label at the 
   // current index.  This method should work for both V1 and V3
   // style certificate labels.
   //
   memcpy(pcszParentSlot, (char *) &mp_perList[m_currIndex].CertLabel[6], 2);

   sscanf(pcszParentSlot, "%2d", &nParentSlot);

   // Is it a valid parent field?
   //
   if ((nParentSlot >= 0) && (nParentSlot <= m_config.CertificateCount))
   {
      // Yep. If it's > 0 then set currentIndex to point
      // to the parent.  Else do nothing because there is
      // no index that points to the root certificate (SLOT 0).
      //
      if (nParentSlot > 0)
         SetSlot(nParentSlot);
      else
         error = -1;
   }
   else
      error = -1;
    
   error = nParentSlot;

   SME_FINISH_CATCH;

   return error;
}

// extend this as necessary
//
// Get Usage Equipement specifier from label and return
// the appropriate LabelType
//
LabelType CSM_FortezzaCardInfo::GetUE( void )
{
   LabelType labelType = BADLABEL;
   char UE[5];

   memset(UE, 0, 5);
   memcpy(UE, mp_perList[m_currIndex].CertLabel, 4);

   if (UE[0] != '\0')
   {
      if (strstr("KEAK", UE) != NULL)
         labelType = V3_KEA;
      else if (strstr("DSAI DSAO", UE) != NULL)
         labelType = V3_DSA;
      else if (strstr("CAX1 ICA1 PCA1 RTXX LAXX", UE) != NULL)
         labelType = CA_DSA;
   }
 
   return labelType;
}

long CSM_FortezzaCardInfo::GetSiblingIndex(void)
{
    char *label=(char *)mp_perList[m_currIndex].CertLabel;
         int siblingSlot = -1;
         char siblingSlotStr[3];
         memset(siblingSlotStr, 0, 3);
         memcpy( siblingSlotStr, label + 4, 2);
         sscanf( siblingSlotStr,"%2x", &siblingSlot);
      

    return(siblingSlot);
}

char * CSM_FortezzaCardInfo::GetCertLabel(void)
{
   char *certLabel = NULL;

   certLabel = strdup( (char *) mp_perList[m_currIndex].CertLabel);
   
   return certLabel;
}

SM_RET_VAL CSM_FortezzaCardInfo::GetUserPath(CTIL::CSM_BufferLst *&pBufferLst, 
        int nUserSlot,
        bool bRootFlag)
{
   CSM_Buffer *pNewNode = NULL;
   CI_CERTIFICATE cert;
   int nParentSlot =0;
   int error = 0;

   SME_SETUP("CSM_FortPerList::GetUserPath()");

   SME(SetSlot(nUserSlot));

   if (pBufferLst != NULL)
      delete pBufferLst;

   pBufferLst = new CTIL::CSM_BufferLst;

   pNewNode = &(*pBufferLst->append());

   error = CI_GetCertificate(nUserSlot, cert);
   if (error != CI_OK)
      SME_THROW(error, "CI_GetCertificate() failed", NULL);

   pNewNode->Set((char *)cert, CI_CERT_SIZE);

   while ( (nParentSlot = this->ParentSlot()) != -1 )
   {
      if (nParentSlot == 0 && bRootFlag == true )
      {
         error = CI_GetCertificate(0, cert);
         if (error != CI_OK)
            SME_THROW(error, "CI_GetCertificate() failed", NULL);

         pNewNode = &(*pBufferLst->append());
         pNewNode->Set( (char *) cert, CI_CERT_SIZE);
         break;
      }
      else
      {
         SetSlot(nParentSlot);
         error = CI_GetCertificate( nParentSlot, cert );
         if (error != CI_OK)
            SME_THROW(error, "CI_GetCertificate()", NULL);
         pNewNode = &(*pBufferLst->append());
         pNewNode->Set( (char *) cert, CI_CERT_SIZE);
      }
   }

   SME_FINISH_CATCH;

   return SM_NO_ERROR;
}

SM_RET_VAL CSM_FortezzaCardInfo::GetCertificate(CSM_Buffer &pBuffer)
{
   int error = 0;
   unsigned char certbuf[CI_CERT_SIZE];


   SME_SETUP("CSM_FortezzaCardInfo::GetCertificate()");

   error = CI_GetCertificate(GetSlot(), &certbuf[0]);
   if (error != CI_OK)
      SME_THROW(error, "CI_GetCertificate() failed", NULL);

   pBuffer.Set( (char *) &certbuf[0], CI_CERT_SIZE);

   return error;

   SME_FINISH_CATCH;
}


// EOF sm_fortCI.cpp
