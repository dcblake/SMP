
////////////////////////////////////////////////////////////////////////////////
//
// File:  sm_RevocationInfoChoice.cpp

//
// SMIME Specification Requirement RevocationInfoChoices IETF RFC 3852
//
// Description:
//
// This file contains methods to support the CSM_RevocationInfoChoice class.
//
// RevocationInfoChoices class was added to support the SMIME Specification.
// The RevocationInfoChoices give a set of revocation status information 
// sufficient to determine whether the certificates and attr certificates with
// which the set is associated are revoked.  However, there MAY be more 
// revocation status information than necessary or there MAY be less revocation 
// status information than necessary. X.509 Certificate Revocation Lists (CRLs)
// are the primary source of revocation status information, but any other
// revocation information format can be supported.  The OtherRevocationInfoFormat
// alternative is provided to support any other revocation information format
// without further modifications.  
//
////////////////////////////////////////////////////////////////////////////////

#include "sm_apiCert.h"  // for CSM_RevocationInfoChoice class definition
 
using namespace SNACC;
using namespace CTIL;
using namespace CERT;

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name: CSM_RevocationInfoChoice 
//
//  Description:   Constructor function that creates a CSM_RevocationInfoChoice  
//                 instance from the input parameter, a SNACC::AsnAny object.
//
//  Inputs:        const SNACC::AsnAny& rSNACCAny
// 
//  Outputs:       none
//
//  Return Value:  none
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoice::CSM_RevocationInfoChoice(const SNACC::AsnAny& rSNACCAny)
{
   SME_SETUP("CSM_RevocationInfoChoice(const SNACC::AsnAny& asnAny)");

   // set member variables to NULL
   m_pOtherRevInfoFormatId = NULL; 

  	// Check that the encoded AsnBuf is present
	if (rSNACCAny.anyBuf == NULL)
      SME_THROW(SM_MISSING_PARAM, "No Instance Created - anyBuf field is NULL", NULL);

   // save location  
   SNACC::AsnBufLoc location = rSNACCAny.anyBuf->GetReadLoc();

   // step 1.  Decode the tag by calling BDecTag(), passing in the 
   // asnAny::anyBuf member as the buffer.
   AsnLen iBytesDecoded = 0;
   AsnTag tag1 = BDecTag (*rSNACCAny.anyBuf, iBytesDecoded);

   // step 2.  Restore location  
   rSNACCAny.anyBuf->SetReadLoc(location); 

   // step 3.  If the tag is a sequence tag, then copy the encoded CRL by 
   if (tag1 == MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
   {
      std::string tmpData;
      rSNACCAny.anyBuf->GetSeg(tmpData);
      m_encodedRevInfo.Set(tmpData.data(), tmpData.length());
   }
   // step 4.  If the tag is a context-specific 1 tag
   else if (tag1 == MAKE_TAG_ID (CNTX, CONS, 1))
   {
      // 4.1 Construct a temporary RevocationInfoChoice object
      RevocationInfoChoice tmpRevInfoChoice;

      // 4.2 decode the RevocationInfoChoice
      iBytesDecoded=0;
      tmpRevInfoChoice.BDec(*rSNACCAny.anyBuf, iBytesDecoded);

      if ((tmpRevInfoChoice.other == NULL) ||
          (tmpRevInfoChoice.choiceId != RevocationInfoChoice::otherCid))
      {
         SME_THROW(SM_NOT_FOUND, "rSNACCAny decoded data has no Other member",
            NULL);
      }

      // 4.3 Copy the otherRevInfoFormat AsnOid
      m_pOtherRevInfoFormatId = new
         AsnOid(tmpRevInfoChoice.other->otherRevInfoFormat);
      if (m_pOtherRevInfoFormatId == NULL)
      {
         SME_THROW(SM_MEMORY_ERROR, "Memory Error for m_pOtherRevInfoFormatId",
            NULL);
      }

      // 4.4 Encode the ANY into the m_encodedRevInfo in case it's been fully
      // decoded
      if (m_encodedRevInfo.Encode(tmpRevInfoChoice.other->otherRevInfo) == 0)
      {
         SME_THROW(SM_NOT_FOUND, "rSNACCAny decoded data has no Other member",
            NULL);
      }
   }
   else  // Step 5.  If the tag is some other tag, throw appropriate exception
   {
      SME_THROW(SM_UNKNOWN_DATA_TYPE, 
         "Unknown Any - CSM_RevocationInfoChoice instance not created", NULL);
   }

   SME_FINISH_CATCH

}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name: CSM_RevocationInfoChoice(const CML::CRL& rCmlCrl) 
//
//  Description:   Constructor function that creates a CSM_RevocationInfoChoice 
//                 instance by encoding the input parameter rCmlCrl into a Bytes
//                 type.  Then setting the encoded data into the member 
//                 m_encodedRevInfo.
//
//  Inputs:        const CML::CRL &cmlCrl
// 
//  Outputs:       none
//
//  Return Value:  none
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoice::CSM_RevocationInfoChoice(const CML::CRL& rCmlCrl)
{

   SME_SETUP("CSM_RevocationInfoChoice(const CML::CRL& rCmlCrl)");

   SetCrl(rCmlCrl);     

   SME_FINISH_CATCH

}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  CSM_RevocationInfoChoice(const SNACC::AsnOid& rOtherOid,
//                                          const CSM_Buffer& rRevInfoBuf) 
//
//  Description:    Constructor function that creates a CSM_RevocationInfoChoice 
//                  instance by calling SetRevInfo() function and passing the 
//                  input parameters.
//
//  Inputs:         const SNACC::AsnOid& rOtherOid 
//                                       -If not NULL, then pRevInfoBuf
//                                       is an encoded OtherRevocationInfoFormat
//                                       data buffer and pOtherOid corresponds           
//                                       to that data
//                  
//                  const CSM_Buffer& rRevInfoBuf Contains a data buffer
//                                                that represents otherRevInfo
//                                                which is defined by rOtherOid                             
// 
//  Outputs:        None
//
//  Return Value:   None
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoice::CSM_RevocationInfoChoice(
   const SNACC::AsnOid& rOtherOid,
   const CSM_Buffer& rRevInfoBuf)
{
   SME_SETUP("CSM_RevocationInfoChoice(const SNACC::AsnOid& const CSM_Buffer&)");

   // set member variables to NULL
   m_pOtherRevInfoFormatId = NULL; 

   // call to set the members with the input parameters
   SetEncodedRevInfo(rOtherOid, rRevInfoBuf);

   SME_FINISH_CATCH
}


////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  CSM_RevocationInfoChoice(const CSM_Buffer& rRevInfo)
//
//  Description:    Constructor function to create a CSM_RevocationInfoChoice
//                  from a CSM_Buffer&. Function assigns the input data into the
//                  member m_encodedRevInfo and sets m_pOtherRevInfoFormatId to 
//                  NULL.
//                 
//  Inputs:         const CSM_Buffer& rCRLs
// 
//  Outputs:        NONE
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoice::CSM_RevocationInfoChoice(const CSM_Buffer& rRevInfo)

{

   SME_SETUP("CSM_RevocationInfoChoice(const CSM_Buffer& rRevInfo)");

   // set member variables to NULL
   m_pOtherRevInfoFormatId = NULL; 

   if (rRevInfo.Length() == 0)
   {
      SME_THROW(SM_MISSING_PARAM, "Error with input data", NULL);
   }

   m_encodedRevInfo = rRevInfo;
       
   SME_FINISH_CATCH
}


////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  CSM_RevocationInfoChoice(const CSM_RevocationInfoChoice 
//                                          & rRevInfoChoice) 
//
//  Description:    Copy constructor that copies the data of the input 
//                  parameter into the member variables of this new instance.
//
//  Inputs:         const CSM_RevocationInfoChoice& rRevInfoChoice 
// 
//  Outputs:        NONE
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoice::CSM_RevocationInfoChoice(
   const CSM_RevocationInfoChoice& rRevInfoChoice) : m_encodedRevInfo(rRevInfoChoice.
   m_encodedRevInfo)
{
   SME_SETUP("CSM_RevocationInfoChoice(CSM_RevocationInfoChoice& )");

   // set member variables to NULL
   m_pOtherRevInfoFormatId = NULL; 

   if (rRevInfoChoice.AccessOtherOid() != NULL)
   {
      // assign the other oid with a copy
      // set member variables to NULL
      m_pOtherRevInfoFormatId = new SNACC::AsnOid(*rRevInfoChoice.AccessOtherOid());
      if (m_pOtherRevInfoFormatId == NULL)
         SME_THROW(SM_MEMORY_ERROR,"Memory Error for m_pOtherRevInfoFormatId",NULL);
   }

   SME_FINISH_CATCH

}


////////////////////////////////////////////////////////////////////////////////
//
//  Function Name: ~CSM_RevocationInfoChoice 
//
//  Description:   Destructor function that calls Clear() to delete memory 
//                 allocated to this instance.
//
//  Inputs:        None
// 
//  Outputs:       None
//
//  Return Value:  NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoice::~CSM_RevocationInfoChoice()
{
   // nothing special to be done
   Clear();
}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name: Clear() 
//
//  Description:  Function to delete memory of the private members and set the 
//                member variables to NULL.
//
//  Inputs:       NONE
// 
//  Outputs:      NONE
//
//  Return Value: NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_RevocationInfoChoice::Clear()
{
   SME_SETUP("Clear()");

   if (m_pOtherRevInfoFormatId != NULL)
   {
      delete m_pOtherRevInfoFormatId;
      m_pOtherRevInfoFormatId = NULL;
   }

   SME_FINISH_CATCH

}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  SetCrl(const CML::CRL& rCmlCrl) 
//
//  Description:    This function will use the input parameter, cmlCrl, to set 
//                  the member variable m_encodedRevInfo.  The cmlCrl is 
//                  already encoded as type CML::CRL and gets assigned into the
//                  member m_encodedRevInfo
//
//  Inputs:         const CML::CRL& rCmlCrl
// 
//  Outputs:        NONE 
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_RevocationInfoChoice::SetCrl(const CML::CRL& rCmlCrl)
{
   SME_SETUP("CSM_RevocationInfoChoice(const CML::CRL& rCmlCrl)");

   Clear();

   const CML::ASN::Bytes& crlBytes = rCmlCrl;
  
   m_encodedRevInfo.Set((const char *)crlBytes.GetData(), crlBytes.Len());

   SME_FINISH_CATCH

}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  SetEncodedRevInfo(SNACC::AsnOid& rOtherOid, 
//                             const CSM_Buffer& rEncodedRevInfo) 
//
//  Description:    This function will set the input parameters' data into the
//                  member variables.
//
//  Inputs:         SNACC::AsnOid& otherOid  - AsnOid of rEncodedRevInfo 
//                                             
//
//                  const CSM_Buffer& rEncodedRevInfo  - Contains an encoded
//                                              OtherRevInfoFormat object
// 
//  Outputs:        NONE
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_RevocationInfoChoice::SetEncodedRevInfo(const SNACC::AsnOid& rOtherOid, 
   const CSM_Buffer& rEncodedRevInfo)
{
   int oidLen = 0;
   int revInfoLen = 0;
   
   SME_SETUP("SetEncodedRevInfo(const SNACC::AsnOid& const CSM_Buffer& )");

   Clear();

   // check parameters
   oidLen = rOtherOid.Len();
   if (oidLen == 0)
   {
      SME_THROW(SM_MISSING_PARAM,"otherOid parameter missing data", NULL);
   }
    
   revInfoLen = rEncodedRevInfo.Length();
   if (revInfoLen == 0)
   {
      SME_THROW(SM_MISSING_PARAM,"encodedRevInfo parameter missing data", NULL);
   }

   m_pOtherRevInfoFormatId = new SNACC::AsnOid(rOtherOid);
   if (m_pOtherRevInfoFormatId == NULL)
   {
      SME_THROW(SM_MEMORY_ERROR,"Memory Error Assigning OtherOid", NULL);
   }
   
   m_encodedRevInfo.Set(rEncodedRevInfo.Access(), rEncodedRevInfo.Length());

   SME_FINISH_CATCH

}


////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  FillSnaccAny(SNACC::AsnAny& rSnaccAny) const
//
//  Description:    Function that encodes the contents and copies the 
//                  encoded content into a SNACC::AsnAny
//                  If m_pOtherRevInfoFormatId member is present, the function
//                  will return an encoded AsnAny that contains the data in an
//                  RevocationInfoChoice object, otherwise the function
//                  copies the m_encodedRevInfo into the SNACC::AsnAny to be 
//                  returned. 
//
//  Inputs:         None
// 
//  Outputs:        SNACC::AsnAny& snaccAny filled in with data from this object
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_RevocationInfoChoice::FillSnaccAny(SNACC::AsnAny& rSnaccAny) const
{
   SME_SETUP("CSM_RevocationInfoChoiceFillSnaccAny(SNACC::AsnAny&)");

   if (m_pOtherRevInfoFormatId != NULL)
   {
      // create a RevocationInfoChoice and make assignment to other
      RevocationInfoChoice tmpRevInfoChoice;

      tmpRevInfoChoice.choiceId = RevocationInfoChoice::otherCid; 

      // create a SNACC::OtherRevocationInfoFormat object
      tmpRevInfoChoice.other = new SNACC::OtherRevocationInfoFormat;
      
      // copy the encoded m_encodedRevInfo CSM_Buffer member into a 
      // new SNACC::AsnBuf that is stored in the SNACC object
      SM_ASSIGN_ANYBUF(&m_encodedRevInfo, &tmpRevInfoChoice.other->otherRevInfo);

      // copy the other OID into the temporary SNACC object
      tmpRevInfoChoice.other->otherRevInfoFormat = *m_pOtherRevInfoFormatId;

      CSM_Buffer tmpBuf;
      tmpBuf.Encode(tmpRevInfoChoice);
      SM_ASSIGN_ANYBUF(&tmpBuf, &rSnaccAny);
   }
   else
   {
      // otherwise, copy the m_encodedRevInfo CSM_Buffer containing the 
      // encoded CRL into the SNACC::AsnAny::anyBuf
      SM_ASSIGN_ANYBUF(&m_encodedRevInfo, &rSnaccAny);
   }

   SME_FINISH_CATCH

}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  AccessOtherOid() const
//
//  Description:    This function returns a const pointer to member
//                  m_pOtherRevInfoFormatId
//
//  Inputs:         None
// 
//  Outputs:        None
//
//  Return Value:   AsnOid* m_pOtherRevInfoFormatId
//
////////////////////////////////////////////////////////////////////////////////
const AsnOid* CSM_RevocationInfoChoice::AccessOtherOid() const 
{ 
   return m_pOtherRevInfoFormatId;
}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  GetEncodedCrl() const
//
//  Description:    This function returns a CML::CRL if there 
//                  is CRL data present.
//
//  Inputs:         NONE
// 
//  Outputs:        NONE
//                       
//  Return Value:   CML::CRL * - pointer to a CRL instance 
//
////////////////////////////////////////////////////////////////////////////////
CML::CRL* CSM_RevocationInfoChoice::GetCRL() const
{
   CML::CRL* pCrl = NULL;

   SME_SETUP("CSM_RevocationInfoChoice::GetCRL()");

   // if there is data stored and it is a crl
   if (m_encodedRevInfo.Length() > 0 &&
       IsCrlPresent() == true)
   {
      // Copy the encoded CRL into a Bytes object
      CML::ASN::Bytes encCRL(m_encodedRevInfo.Length(),
         (const uchar*)m_encodedRevInfo.Access());

      // Construct a new CML::CRL from the encoded CRL
      pCrl = new CML::CRL(encCRL);
      if (pCrl == NULL)
      {
         SME_THROW(SM_MEMORY_ERROR,
            "Memory error with SNACC::RevocationInfoChoice", NULL);
      }
   } // end if 


   SME_FINISH
   SME_CATCH_SETUP

      // local cleanup logic
      if (pCrl)
         delete pCrl;

   SME_CATCH_FINISH

   return pCrl;

}  // end GetCRL()

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  GetSNACCRevInfoChoice() 
//
//  Description:    This function returns a SNACC::RevocationInfoChoice if there 
//                  is data present.
//
//  Inputs:         NONE
// 
//  Outputs:        NONE
//                       
//  Return Value:   SNACC::RevocationInfoChoice 
//
////////////////////////////////////////////////////////////////////////////////
SNACC::RevocationInfoChoice* CSM_RevocationInfoChoice::GetSNACCRevInfoChoice() const
{
   SNACC::RevocationInfoChoice* pSNACCRevInfoChoice = NULL;

   SME_SETUP("CSM_RevocationInfoChoice::GetEncodedRevInfoChoice()");

   // if there is data stored
   if (m_encodedRevInfo.Length() > 0)
   {
      pSNACCRevInfoChoice = new SNACC::RevocationInfoChoice();
      if (pSNACCRevInfoChoice == NULL)
      {
         SME_THROW(SM_MEMORY_ERROR, 
                   "Memory error with SNACC::RevocationInfoChoice", NULL);
      }

      if (m_pOtherRevInfoFormatId != NULL)
      {
         // we have an otherFormat  set the choice to be other
         pSNACCRevInfoChoice->choiceId = RevocationInfoChoice::otherCid;

         pSNACCRevInfoChoice->other = new SNACC::OtherRevocationInfoFormat;
         if (pSNACCRevInfoChoice->other == NULL)
         {
            SME_THROW(SM_MEMORY_ERROR, 
                      "Memory error with SNACC::OtherRevocationInfoFormat", NULL);
         }

         // Set the otherRevInfoFormat from the member
         pSNACCRevInfoChoice->other->otherRevInfoFormat = *m_pOtherRevInfoFormatId;

         // Call SetTypeByOid() so that the AnyInfo is properly set
         pSNACCRevInfoChoice->other->otherRevInfo.
            SetTypeByOid(*m_pOtherRevInfoFormatId);

         // Call CSM_Buffer.Decode() to decode the contents of the buffer
         m_encodedRevInfo.Decode(pSNACCRevInfoChoice->other->otherRevInfo);
      }
      else
      {
         // we have a CertificateList
         pSNACCRevInfoChoice->choiceId = SNACC::RevocationInfoChoice::crlCid;
         pSNACCRevInfoChoice->crl = new SNACC::CertificateList;
         if (pSNACCRevInfoChoice->crl == NULL)
         {
            SME_THROW(SM_MEMORY_ERROR,
               "Memory error with SNACC::CertificateList", NULL);
         }

         // Call CSM_Buffer.Decode() to decode the contents of the buffer
         m_encodedRevInfo.Decode(*pSNACCRevInfoChoice->crl);
      }
   } // end if 


   SME_FINISH
   SME_CATCH_SETUP

      // local cleanup logic
      if (pSNACCRevInfoChoice)
         delete pSNACCRevInfoChoice;

   SME_CATCH_FINISH

   return pSNACCRevInfoChoice;

}  // end



////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  IsCrlPresent() const
//
//  Description:    This function returns true if there is data present in 
//                  m_encodedRevInfo and if there is data in m_pEncodedRevInfo 
//                  and m_pOtherRevInfoFormatId is NULL then the data should
//                  contain a CRL.
//
//  Inputs:         NONE
// 
//  Outputs:        bool true  if CRL present
//                       false if no CRL present
//
//  Return Value:   bool 
//
////////////////////////////////////////////////////////////////////////////////
bool CSM_RevocationInfoChoice::IsCrlPresent() const
{
   if (m_encodedRevInfo.Length() > 0 && 
       m_pOtherRevInfoFormatId == NULL)
      return true;
   else
      return false;  
}



////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  CSM_RevocationInfoChoice::operator = 
//
//  Description:    This operator= function deletes any data from this instance
//                  and copies the new data from the input parameter thatRevchoice.
//                  to the member variables m_encodedRevInfo and 
//                  m_pOtherRevInfoFormatId.
//
//  Inputs:         const CSM_RevocationInfoChoice &thatRevChoice
// 
//  Outputs:        NONE
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoice &CSM_RevocationInfoChoice::operator = (
                                     const CSM_RevocationInfoChoice &rThatRevChoice)
{
   SME_SETUP("SetEncodedRevInfo(const SNACC::AsnOid& const CSM_Buffer& )");

   // delete data from instance in preparation for assignments
   Clear();
    
   // copy encodedRevInfo if there is data in thatRevChoice
   if (rThatRevChoice.m_encodedRevInfo.Length() > 0)
   {
      m_encodedRevInfo.Set(rThatRevChoice.m_encodedRevInfo.Access(),
                           rThatRevChoice.m_encodedRevInfo.Length());
   }

   // copy OtherRevInfoFormatId if there is data in thatRevChoice
   if (rThatRevChoice.m_pOtherRevInfoFormatId)
   {
      m_pOtherRevInfoFormatId = new SNACC::AsnOid(
                                        *rThatRevChoice.m_pOtherRevInfoFormatId);
      if (m_pOtherRevInfoFormatId == NULL)
      {
         SME_THROW(SM_MEMORY_ERROR,
                   "Memory Error Assigning m_pOtherRevInfoFormatId", NULL);
      }
   }

   SME_FINISH_CATCH
    
   return(*this);
}


// EOF sm_RevocationInfoChoice.cpp
