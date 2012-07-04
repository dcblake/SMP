
////////////////////////////////////////////////////////////////////////////////
//
// File:  sm_RevocationInfoChoices.cpp
//
// SMIME Specification Requirement RevocationInfoChoices IETF RFC 3852
//
// Description:
//
//
// RevocationInfoChoices class was added to support the SMIME Specification.
// The RevocationInfoChoices is defined as a Set of RevocationInfoChoice.  
// However, the SFL basically doesn't do anything with the CRLs, therefore the 
// class is defined to be:  RevocationInfoChoices ::= SET OF ANY.  This 
// CSM_RevocationInfoChoices was added to support the RevocationInfoChoices
// set of ANY class.  CSM_RevocationInfoChoices class will be publicly-inherited
// from an instantiation of the std::list<CMS_RevocationInfoChoice> template.
// It has no member variables.
//
// This file contains methods to support the CSM_RevocationInfoChoices class.
//
////////////////////////////////////////////////////////////////////////////////

#include "sm_apiCert.h"       // for CSM_RevocationInfoChoices class definition

using namespace SNACC;
using namespace CTIL;
using namespace CERT;

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  CSM_RevocationInfoChoices(const SNACC::RevocationInfoChoices 
//                                            &revInfoChoices);
//
//  Description:    Constructor function to create from a SNACC::
//                  RevocationInfoChoices. Calls std::list::push_back() for 
//                  each SNACC::AsnAny in the std::list, passing the AsnAny
//                  to push_back().
//
//  Inputs:         const CSM_RevocationInfoChoices &revInfoChoices
// 
//  Outputs:        NONE
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoices::CSM_RevocationInfoChoices(const 
   SNACC::RevocationInfoChoices& rRevInfoChoice)

{
   SME_SETUP("CSM_RevocationInfoChoices(const SNACC::RevocationInfoChoices)");

   SNACC::RevocationInfoChoices::const_iterator i;  // iterator for list 
 
   for (i = rRevInfoChoice.begin(); i != rRevInfoChoice.end(); ++i)
   {
      this->push_back(*i);
   }

   SME_FINISH
   SME_CATCH_SETUP
      // local cleanup logic
   SME_CATCH_FINISH

} // end CSM_RevocationInfoChoices constructor




////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  CSM_RevocationInfoChoices(const CSM_BufferLst& rBufLst)
//
//  Description:    Constructor function to create a CSM_RevocationInfoChoices
//                  from a CSM_BufferLst.  The CSM_BufferLst contains a 
//                  list of CSM_Buffers each of which contain an encoded 
//                  CSM_RevocationInfoChoice.
//                 
//
//  Inputs:         const CSM_BufferLst *rBufLst
// 
//  Outputs:        NONE
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_RevocationInfoChoices::CSM_RevocationInfoChoices(const 
   CSM_BufferLst& rBufLst)

{
   List<CTIL::CSM_Buffer>::const_iterator i;  // iterator for list 

   SME_SETUP("CSM_RevocationInfoChoices(const CSM_BufferLst&)");

   // check input parameter
   if (rBufLst.size() == 0)
   {
      SME_THROW(SM_MISSING_PARAM, "Error with input data", NULL);
   }

   // for every CSM_Buffer in the List
   for (i = rBufLst.begin(); i != rBufLst.end(); ++i)
   {
      push_back(*i);                      // add the CSM_Buffer to the list
   } // end for


   SME_FINISH
   SME_CATCH_SETUP
      // local cleanup logic
      // clean up

   SME_CATCH_FINISH

} // end CSM_RevocationInfoChoices(const CSM_BufferLst& rBufLst)

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  GetSNACCRevInfoChoices();
//
//  Description:    This function returns a copy of the list as a pointer to a 
//                  SNACC::RevocationInfoChoices.
//
//  Inputs:         NONE
// 
//  Outputs:        NONE
//
//  Return Value:   SNACC::RevocationInfoChoices*
//
////////////////////////////////////////////////////////////////////////////////
SNACC::RevocationInfoChoices* CSM_RevocationInfoChoices::GetSNACCRevInfoChoices()
{

   SNACC::RevocationInfoChoices*            pSNACCRevInfoList = NULL;
   List<CSM_RevocationInfoChoice>::iterator iRevInfo; // iterator for list 

   SME_SETUP("CSM_Revocation");


   // allocate memory for the resulting SNACC::RevocationInfoChoices
   pSNACCRevInfoList = new SNACC::RevocationInfoChoices;
   if (pSNACCRevInfoList == NULL)
   {
      SME_THROW(SM_MEMORY_ERROR, "Memory Error for SNACC::RevInfoList", NULL);
   }

   // For each CSM_RevocationInfoChoice in the list, call the fill function to
   // fill in a newly-appended SNACC::AsnAny
   for (iRevInfo = begin(); iRevInfo != end(); iRevInfo++)
   {    
       iRevInfo->FillSnaccAny(*pSNACCRevInfoList->append());       
   }
   
   SME_FINISH
   SME_CATCH_SETUP
      // local cleanup logic
   SME_CATCH_FINISH

   return pSNACCRevInfoList;

} // end GetSNACCRevInfoChoices()


// EOF sm_RevocationInfoChoices.cpp
