
#include <string.h>
#include "sm_apiCert.h"
using namespace SNACC;
using namespace CML::ASN;
//using SNACC::SnaccException;
_BEGIN_CERT_NAMESPACE 

//////////////////////////////////////////////////////////////////////////
// sm_GenName.cpp
// implementation of methods from:
//
//   CSM_GeneralName
//     CSM_GeneralName(GeneralName &SNACCgenName):GeneralName()
//     CSM_GeneralName(CSM_DN &dn)
//     CSM_GeneralName(char *buffer, int cid)
//     CSM_GeneralName(CSM_Buffer *pcsmb)
//     GetGenNameString()
//     GetGenNameDN()
//     GetGenNameRFC822()
//     GetGenNameURI()
//     GetGenNameDNS()
//     GetEncodedGenName()
//     SetGenNameDN(CSM_DN &dn)
//     SetGenNameRFC822(char *rfc822)
//     SetGenNameDNS(char *dns)
//     SetGenNameURI(char *uri)
//     SetEncodedGN(CSM_Buffer &encCSMB)
//     m_GetType()
//     operator == (CSM_GeneralName &gn)
//     operator != (CSM_GeneralName &gn)
//
//   CSM_GeneralNames
//     CSM_GeneralNames(GeneralNames &)
//     FindSubjectDN(CSM_CSInst *inst)
//     GetSNACCGeneralNames()
//     SetGeneralNames(GeneralNames &SNACCTmpGNs)
//
//   CSM_ListGeneralNames
//      CSM_ListGeneralNames()
//      SetGeneralNamesList(CSM_GeneralNames &TmpGNs)
//
//////////////////////////////////////////////////////////////////////////

// BEGINNING OF CSM_GeneralName FUNCTION DEFINITIONS

// CONSTRUCTOR FOR CSM_GeneralName
//   use constructor to make a copy of the provided structure
//   and put it into this structure
CSM_GeneralName::CSM_GeneralName(GeneralName &SNACCgenName):GeneralName()
{
   choiceId = SNACCgenName.choiceId;

   switch (SNACCgenName.choiceId)
   {
#ifdef RWC_DISABLED_UNTIL_LATER_FROM_NEW_CML_ASN1
      case otherNameCid:
        otherName = new OtherName;
        *otherName = *SNACCgenName.otherName;
        break;
#endif
      case rfc822NameCid:
        rfc822Name = new IA5String;
        *rfc822Name = *SNACCgenName.rfc822Name;
        break;
      case dNSNameCid:
        dNSName = new IA5String;
        *dNSName = *SNACCgenName.dNSName;
        break;
      case x400AddressCid:
        x400Address = new ORAddress;
        *x400Address = *SNACCgenName.x400Address;
        break;
      case directoryNameCid:
        directoryName = new Name;
        *directoryName = *SNACCgenName.directoryName;
        break;
      case ediPartyNameCid:
        ediPartyName = new EDIPartyName;
        *ediPartyName = *SNACCgenName.ediPartyName;
        break;
      case uniformResourceIdentifierCid:
        uniformResourceIdentifier = new IA5String;
        *uniformResourceIdentifier = *SNACCgenName.uniformResourceIdentifier;
        break;
      case iPAddressCid:
        iPAddress = new AsnOcts;
        *iPAddress = *SNACCgenName.iPAddress;
        break;
      case registeredIDCid:
        registeredID = new AsnOid;
        *registeredID = *SNACCgenName.registeredID;
        break;
   }

} // END OF CONSTRUCTOR FOR CSM_GeneralName

// CONSTRUCTOR FOR CSM_GeneralName
//
CSM_GeneralName::CSM_GeneralName(CSM_DN &dn)
{
   SME_SETUP("CSM_GeneralName::CSM_GeneralName(CSM_DN &)");

   SetGenNameDN(dn);

   SME_FINISH_CATCH
} // END OF CONSTRUCTOR FOR CSM_GeneralName

// CONSTRUCTOR FOR CSM_GeneralName
//
CSM_GeneralName::CSM_GeneralName(char *buffer, int cid)
{
   SME_SETUP("CSM_GeneralName::CSM_GeneralName(char*, int)");

   switch (cid)
   {
      case GeneralName::rfc822NameCid:
         SetGenNameRFC822(buffer);
         break;

     case GeneralName::dNSNameCid:
        SetGenNameDNS(buffer);
        break;

     case GeneralName::uniformResourceIdentifierCid:
        SetGenNameURI(buffer);
        break;

      default:
        SME_THROW(SM_UNKNOWN_CID, NULL, NULL);
   }

   SME_FINISH_CATCH
} // END OF CONSTRUCTOR FOR CSM_GeneralName

// CONSTRUCTOR FOR CSM_GeneralName
//   use this constructor for an encoded blob
CSM_GeneralName::CSM_GeneralName(CSM_Buffer *pcsmb)
{
   SME_SETUP("CSM_GeneralName::CSM_GeneralName(CSM_Buffer *)");

   SetEncodedGN(*pcsmb);

   SME_FINISH_CATCH
} // END OF CONSTRUCTOR FOR CSM_GeneralName

// CMS_GeneralName Get member functions:

// GetGenNameString:
//   returns a char pointer to the general name string
char *CSM_GeneralName::GetGenNameString()
{
   CSM_DN  *pDN=NULL;
   const char    *gnString = NULL;

   SME_SETUP("CSM_GeneralName::GetGenNameString()");

       // check type and get the general name string
      switch(m_GetType())
      {
        case GeneralName::directoryNameCid:
           pDN = GetGenNameDN();
           gnString = strdup(*pDN);
           if (pDN)
              delete pDN;
           break;
        case GeneralName::rfc822NameCid:
           gnString = GetGenNameRFC822();
           break;
        case GeneralName::dNSNameCid:
           gnString = GetGenNameDNS();
           break;
        case GeneralName::uniformResourceIdentifierCid:
           gnString = GetGenNameURI();
           break;
        default:
           SME_THROW(SM_UNKNOWN_CID, NULL, NULL);
      } // end switch

    SME_FINISH_CATCH

    return (char *)gnString;
} // END OF MEMBER FUNCTION GetGenNameString

// GetGenNameDN:
//   returns a pointer to the CSM_DN class  for directoryName
CSM_DN *CSM_GeneralName::GetGenNameDN()
{
   CSM_DN *pDN=NULL;

   SME_SETUP("CSM_GeneralName::GetGenNameDN()");

   if (this != NULL && this->choiceId == directoryNameCid)
   {
      if ((pDN = new CSM_DN((*this->directoryName))) == NULL)
          SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }

    SME_FINISH_CATCH
    return pDN;
} // END OF MEMBER FUNCTION GetGenNameDN

// GetGenNameRFC822:
//   returns a pointer to the char * for RFC822
char *CSM_GeneralName::GetGenNameRFC822()
{
   char *pBuffer=NULL;

   SME_SETUP("CSM_GeneralName::GetGenNameRFC822()");

   if (this != NULL && this->choiceId == rfc822NameCid)
   {
      pBuffer = (char *)calloc(1, this->rfc822Name->length() +1);

      memcpy(pBuffer, this->rfc822Name->c_str(),
         this->rfc822Name->length());
   }

   SME_FINISH_CATCH
   return pBuffer;
} // END OF MEMBER FUNCTION GetGenNameRFC822

// GetGenNameURI:
//   returns a pointer to the char * for Uniform Resource Identifier
char *CSM_GeneralName::GetGenNameURI()
{
   char *pBuffer=NULL;

   SME_SETUP("CSM_GeneralName::GetGenNameURI()");

   if (this != NULL && this->choiceId == uniformResourceIdentifierCid)
   {
      pBuffer = (char *)calloc(1,
         this->uniformResourceIdentifier->length()+1);
      memcpy(pBuffer,
         this->uniformResourceIdentifier->c_str(),
         this->uniformResourceIdentifier->length());
   }

   SME_FINISH_CATCH
   return pBuffer;
} // END OF MEMBER FUNCTION GetGenNameURI

// GetGenNameDNS:
//   returns a pointer to the  char * for dNSName
char *CSM_GeneralName::GetGenNameDNS()
{
   char *pBuffer=NULL;

   SME_SETUP("CSM_GeneralName::GetGenNameDNS()");

   if (this != NULL && this->choiceId == dNSNameCid)
   {
      pBuffer = (char *)calloc(1,this->dNSName->length()+1);
        memcpy(pBuffer,this->dNSName->c_str(),
        this->dNSName->length());
   }

   SME_FINISH_CATCH
   return pBuffer;
} // END OF MEMBER FUNCTION GetGenNameDNS

// GetEncodedGenName:
//   GetEncodedGenName member function
CSM_Buffer *CSM_GeneralName::GetEncodedGenName()
{
    CSM_Buffer *pBuf=NULL;

    SME_SETUP("CSM_GeneralName::GetEncodedGenName");
    if (this != NULL)
    {
        ENCODE_BUF(this, pBuf);
    }

    SME_FINISH_CATCH
    return pBuf;
} // END OF MEMBER FUNCTION GetEncodedGenName

// GetGenNameFormatString:
//   returns a char pointer to the general name string beginning with tag 
char *CSM_GeneralName::GetGenNameFormatString()
{
   CSM_DN  *pDN=NULL;
   char    *gnString = NULL;
   char    *ptmp = NULL;

   SME_SETUP("CSM_GeneralName::GetGenNameFormatString()");

       // check type and get the general name string
      switch(m_GetType())
      {
        case GeneralName::directoryNameCid:
           
           pDN = GetGenNameDN();
           ptmp = strdup(*pDN);
           gnString = (char *) calloc(1,strlen(ptmp) + 4);
           strcat(gnString, "DN:");
           strcat(gnString, ptmp);           
           if (pDN)
              delete pDN;
           if (ptmp)
              free (ptmp);
           break;
        case GeneralName::rfc822NameCid:
           ptmp = GetGenNameRFC822();
           if (ptmp != NULL)
           {
              gnString = (char *) calloc(1,strlen(ptmp) + 8);
              strcat(gnString,"RFC822:");
              strcat(gnString, ptmp);           

              free (ptmp);
           }
           break;
        case GeneralName::dNSNameCid:
           ptmp = GetGenNameDNS();
           if (ptmp != NULL)
           {
              gnString = (char *) calloc(1,strlen(ptmp) + 5);
              strcat(gnString,"DNS:");
              strcat(gnString, ptmp);           

              free (ptmp);
           }           
           break;
        case GeneralName::uniformResourceIdentifierCid:
           ptmp = GetGenNameURI();
           if (ptmp != NULL)
           {
              gnString = (char *) calloc(1,strlen(ptmp) + 5);
              strcat(gnString,"URI:");
              strcat(gnString, ptmp);           

              free (ptmp);
           }                      
           break;
        default:
           SME_THROW(SM_UNKNOWN_CID, NULL, NULL);
      } // end switch

    SME_FINISH_CATCH

    return (char *)gnString;
} // END OF MEMBER FUNCTION GetGenNameFormatString

// CMS_GeneralName Set member functions:

// SetGenNameDN:
//   set this private variable with a CSM_DN dn name
void CSM_GeneralName::SetGenNameDN(CSM_DN &dn)
{
   SME_SETUP("CSM_GeneralName::SetGenNameDN(CSM_DN &");

   choiceId = GeneralName::directoryNameCid;
   directoryName = dn.GetSnacc();

   SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetGenNameDN

// SetGenNameRFC822:
//   set this private variable with a CSM_Buffer rfc822 (IA5String)
void CSM_GeneralName::SetGenNameRFC822(char *rfc822)
{
   SME_SETUP("CSM_GeneralName::SetGenNameRFC822(char *)");

   choiceId = GeneralName::rfc822NameCid;
   if ((rfc822Name = new IA5String(rfc822)) == NULL)
       SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetGenNameRFC822

// SetGenNameDNS:
//   set this private variable with a dns name (IA5String)
void CSM_GeneralName::SetGenNameDNS(char *dns)
{
   SME_SETUP("CSM_GeneralName::SetGenNameDNS(char *)");

   choiceId = GeneralName::dNSNameCid;
   if ((dNSName = new IA5String(dns)) == NULL)
       SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetGenNameDNS

// SetGenNameURI:
//   set this private variable with a uniform resource identifier
//   (IA5String)
void CSM_GeneralName::SetGenNameURI(char *uri)
{
   SME_SETUP("CSM_GeneralName::SetGenNameURI(char *)");

   choiceId = GeneralName::uniformResourceIdentifierCid;
   uniformResourceIdentifier = new IA5String(uri);

   SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetGenNameURI

// SetGenNameOther:
//   set this private variable with an object ID and an IA5string value
//   (IA5String)
void CSM_GeneralName::SetGenNameOther(char *Oid, char *Value)
{
   SME_SETUP("CSM_GeneralName::SetGenNameOther(char *Oid, char* Value)");

   choiceId = GeneralName::otherNameCid;
   otherName = new Other_Name();
   otherName->id = Oid;
   
   UTF8String* pUserPrincipalName = new UTF8String(Value);
   otherName->type.value = pUserPrincipalName;

   SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetGenNameOther

// SetEncodedGN:
//   SetEncodedGN member function
void CSM_GeneralName::SetEncodedGN(CSM_Buffer &encCSMB)
{
   SME_SETUP("CSM_GeneralName::SetEncodedGN");

   DECODE_BUF(this, &encCSMB);

   SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetEncodedGN

// m_GetType:
//   get type of this private name
long CSM_GeneralName::m_GetType()
{
   long gnType;

   SME_SETUP("CSM_GeneralName::m_GetType()");
   if (this != NULL)
   {
      gnType = this->choiceId;
   }
   else
   {
      gnType = SM_UNKNOWN_CID;
   }

   SME_FINISH_CATCH
   return(gnType);
} // END OF MEMBER FUNCTION m_GetType

// == operator:
//   equality member function
bool CSM_GeneralName::operator == (CSM_GeneralName &gn)
{
   bool       bRet = false;
   CSM_DN     *pbuf1 = NULL;
   CSM_DN     *pbuf2 = NULL;

   SME_SETUP("CSM_GeneralName::operator ==");

   if (gn.m_GetType()!= this->m_GetType())
   {
      bRet = false;
   }
   else
   {
     // check rest to determine equality
      switch(this->m_GetType())
      {
        case GeneralName::directoryNameCid:
           pbuf1 = this->GetGenNameDN();
           pbuf2 = gn.GetGenNameDN();
           if (*pbuf1 == *pbuf2)
              bRet = true;
           break;
        case GeneralName::rfc822NameCid:
           if (strcmp(gn.GetGenNameRFC822(),this->GetGenNameRFC822()) == 0)
              bRet = true;
           break;
        case GeneralName::dNSNameCid:
           if (strcmp(gn.GetGenNameDNS(),this->GetGenNameDNS()) == 0)
              bRet = true;
           break;
        case GeneralName::uniformResourceIdentifierCid:
           if (strcmp(gn.GetGenNameURI(),this->GetGenNameURI()) == 0)
              bRet = true;
           break;
        default:
           SME_THROW(SM_UNKNOWN_CID, NULL, NULL);
      } // end switch
   } // end else

   SME_FINISH_CATCH
   return bRet;
} // END OF equality MEMBER FUNCTION

// != operator:
//   Inequality member function
bool CSM_GeneralName::operator != (CSM_GeneralName &gn)
{
   return(!(*this == gn));
} // END OF inequality MEMBER FUNCTION

// END OF CSM_GeneralName FUNCTION DEFINITIONS

// BEGINNING OF CSM_GeneralNames FUNCTION DEFINITIONS

// ALTERNATIVE CONSTRUCTOR FOR CSM_GeneralNames
//
CSM_GeneralNames::CSM_GeneralNames(GeneralNames &SNACCGNs)
{
    SME_SETUP("CSM_GeneralNames::CSM_GeneralNames(GeneralNames &)");

    SetGeneralNames(SNACCGNs);

    SME_FINISH_CATCH
}

// FindSubjectDN:
//
bool CSM_GeneralNames::FindSubjectDN(CSM_CSInst *inst)
{
   CSM_GeneralNameLst::iterator itGeneralName;
   bool            bRet = false;
   CSM_DN          *dn1 = NULL, *dn2 = NULL;

   SME_SETUP("CSM_GeneralName::FindSubjectDN");

   itGeneralName = this->begin();
   if (inst->CSM_CtilInst::AccessID() && strcmp(inst->CSM_CtilInst::AccessID(),
                                                "CommonCTIL") != 0)
   {
   // point to dn in the inst instance
   dn1 = inst->AccessSubjectDN();

   if (dn1)
   {
     // loop through general names list and ccmpare each general name
     // to inst (input) return true if found
     for(; itGeneralName != this->end(); ++itGeneralName)
     {
      // check for a dn, if no dn then continue checking list
      if ((dn2 = itGeneralName->GetGenNameDN()) == NULL)
         continue;

      // did we find the subject dn
      if (*dn2 == *dn1)
      {
         bRet = true;
         delete dn2;
         break;
      }

      // cleanup the dn
      delete dn2;
     }
   }        // END dn1 check (MAY BE NULL login).
   }        // END "CommonCTIL" instance check.

   SME_FINISH_CATCH

   return bRet;
}

// GetSNACCGeneralNames:
//   gets a snacc general name list from this csm general name list
//   and appends a copy to the output parameter gn
void CSM_GeneralNames::GetSNACCGeneralNames(SNACC::GeneralNames &gns)
{

   CSM_GeneralNameLst::iterator itTmpCSMGenName;

   SME_SETUP("CSM_GeneralName::GetSNACCGeneralNames(SNACC::GeneralNames &gns");

   for (itTmpCSMGenName =  this->begin();
        itTmpCSMGenName != this->end();
        ++itTmpCSMGenName)
   {
      gns.append(*itTmpCSMGenName);
   }

   SME_FINISH_CATCH
};

// GetSNACCGeneralNames:
//   gets a snacc general name list from csm general name list
//   by calling GetSNACCGeneralNames member function
//   and returns a pointer to it
SNACC::GeneralNames *CSM_GeneralNames::GetSNACCGeneralNames()
{
   GeneralNames    *pGNsLst = new GeneralNames;

   SME_SETUP("CSM_GeneralName::GetSNACCGeneralNames()");

   GetSNACCGeneralNames(*pGNsLst);

   SME_FINISH_CATCH

   return pGNsLst;
};


// SetGeneralNames:
//   INPUT: SNACC GeneralNames
//   OUTPUT: NONE
//   RETURN: NONE
// TAKES A SNACC LIST OF GENERAL NAMES AND ADDS EACH TO THE CURRENT
// CSM_GENERALNAMES LIST
//
void CSM_GeneralNames::SetGeneralNames(GeneralNames &SNACCTmpGNs)
{
    GeneralNames::iterator itmpSNACCGenName;

    SME_SETUP("CSM_GeneralName::SetGeneralNames");

    // for each GeneralName in list
    for(itmpSNACCGenName =  SNACCTmpGNs.begin();
        itmpSNACCGenName != SNACCTmpGNs.end(); ++itmpSNACCGenName)
    {
        // put GeneralName into a CSM_GeneralName object
        this->append(*itmpSNACCGenName);
    }

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION SetGeneralNames

// END OF CSM_GeneralNames FUNCTION DEFINITIONS


_END_CERT_NAMESPACE 

// EOF sm_GenName.cpp
