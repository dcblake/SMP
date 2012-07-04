/****************************************************************************
 * File:      CM_certPolicies.cpp
 * Project:   Certificate Management Library
 * Contents:  Contains the PolicyTable class implementation and low-level
 *            functions used to process certificate policies.
 * Req Ref:  
 *
 * Created:   24 October 2000
 * Author:    Rich Nicholas <Richard.Nicholas@it.baesystems.com>
 *
 * $Revision: 1.26 $
 * $Date: 2005/03/11 20:05:53 $
 *
 ****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include "CM_cache.h"



// Using declarations
using namespace CML;
using CML::Internal::PolicyTable;
using ASN::CertPolicy;
using ASN::CertPolicyList;



//////////////////////////////////////
// PolicyTable class implementation //
//////////////////////////////////////
const SNACC::AsnOid PolicyTable::kAnyPolicy(SNACC::anyPolicy);

void PolicyTable::Init(int numCerts)
{
	const int kNUM_INITIAL_ROWS = 10;

	if (numCerts < 1)
		throw CML_ERR(CM_INVALID_PARAMETER);

	m_depth = ushort(numCerts);

	m_table.reserve(kNUM_INITIAL_ROWS);
	PolicyArray::iterator iRow = m_table.insert(m_table.end(),CML::Internal::PolicyTable::PolicyRow());
	iRow->insert(iRow->end(), m_depth + 1, kAnyPolicy);
}

bool PolicyTable::IsEmpty() const
{
	if ((m_depth == 0) || (m_table.size() == 0))
		return true;
	else
		return false;
}

bool PolicyTable::IsUserPolicySetEmpty(const ASN::CertPolicyList& initialPolicySet) const
{
	// Get the authority-constrained-policy-set
	CertPolicyList authoritySet;
	GetAuthPolicySet(authoritySet);

	// Return true if the authority-constrained-policy-set is empty
	if (authoritySet.empty())
		return true;

	// Return false if any policy in the authority set matches one of the
	// initial policies or if the special anyPolicy is present in either set
	CertPolicyList::const_iterator i;
	for (i = authoritySet.begin(); i != authoritySet.end(); ++i)
	{
		if (*i == kAnyPolicy)
			return false;

		ASN::CertPolicyList::const_iterator j;
		for (j = initialPolicySet.begin(); j != initialPolicySet.end(); ++j)
		{
			if ((i->policyId == j->policyId) || (*j == kAnyPolicy))
				return false;
		}
	}

	// Nothing matched, so return true
	return true;
}


/****************************************************************************
 * FUNCTION: PolicyTable::GetAuthPolicySet()
 *
 * Description:  Determines the authority-constrained-policy-set from this
 * PolicyTable and returns the resulting set in the authSet parameter.
 *
 * Parameters:
 * (O) authSet    List of certificate policies that comprise the authority-
 *                constrained-policy-set for this PolicyTable.
 *
 * No return variable.
 ****************************************************************************/
void PolicyTable::GetAuthPolicySet(CertPolicyList& authSet) const
{
   // Clear the authSet parameter
   authSet.clear();

   // If the table is empty, just return
   if (IsEmpty())
      return;

   // Per X.509:  If the authorities-constrained-policy-set[0, path-depth] is
   // any-policy, the the authorities-constrained-policy-set is any-policy.
   // Otherwise, the policy-set is, for each row in the table, the value in
   // the left-most cell which does not contain any-policy.
   if (m_table[0][m_depth] == kAnyPolicy)
   {
      authSet.push_back(m_table[0][m_depth]);

      // Now append any qualifiers present in the columns to the left
      for (unsigned int iCol = m_depth - 1; iCol > 0; iCol--)
         authSet.back() |= m_table[0][iCol].qualifiers;
   }
   else
   {
      for (unsigned int iRow = 0; iRow < m_table.size(); iRow++)
      {
         bool policyAdded = false;
         for (unsigned int iCol = 0; iCol < m_table[iRow].size(); iCol++)
         {
            // If this row's policy was already addded to the authSet,
            // append the qualifiers from the other column's policies
            // Else if the policy isn't the any-policy, add it to the authSet
            if (policyAdded)
            {
               authSet.back() |= m_table[iRow][iCol].qualifiers;
            }
            else if (m_table[iRow][iCol] != kAnyPolicy)
            {
               authSet.push_back(m_table[iRow][iCol]);
               policyAdded = true;
            }
            // else try the policy in the next column
         }
      }
   }
}


/************************************************************************
 FUNCTION:  PolicyTable::ProcessMappings()
 
 Description: This function performs the X.509 cert path processing of
 the supplied cert policy mappings extension for the current path depth.
 Any mappings that are processed are added to the mapping history.
 An exception is thrown if an error occurs.
*************************************************************************/
void PolicyTable::ProcessMappings(const ASN::PolicyMappingList* pMappings,
								  ushort nDepth, bool inhibitMapping,
								  ASN::PolicyMappingList& mappingDetails)
{
	// If the policy table is empty, just return
	if (IsEmpty())
		return;

	// Check that the table size won't be exceeded
	if (nDepth > m_depth - 1)
		throw CML_ERR(CM_UNKNOWN_ERROR);

	// If the policy-mapping-inhibit-indicator is set
	if (inhibitMapping)
	{
		// For each mapping present in the extension, locate all rows in the
		// table whose nDepth column contains the mapping's issuer domain
		// policy, and delete the row
		if (pMappings != NULL)
		{
			ASN::PolicyMappingList::const_iterator iMap;
			for (iMap = pMappings->begin(); iMap != pMappings->end(); ++iMap)
			{
				// If either the issuer or subject domain policy is any-policy,
				// empty the policy table and return. According to X.509
				// clause 8.2.2.7, policies shall not be mapped to or from
				// the special any-policy
				if ((iMap->issuerPolicy == kAnyPolicy) ||
					(iMap->subjectPolicy == kAnyPolicy))
				{
					m_table.clear();
					return;
				};

				PolicyArray::iterator iRow = m_table.begin();
				while (iRow != m_table.end())
				{
					if (iRow->at(nDepth).policyId == iMap->issuerPolicy)
						iRow = m_table.erase(iRow);
					else
						++iRow;
				}
			}
		}
	}
	else // the policy-mapping-inhibit-indicator is not set
	{
		// For each mapping present in the extension, locate all rows in the
		// table whose nDepth column contains the mapping's issuer domain
		// policy, and write the subject domain policy in the nDepth+1 column
		// of the same row.
		if (pMappings != NULL)
		{
			ASN::PolicyMappingList::const_iterator iMap;
			for (iMap = pMappings->begin(); iMap != pMappings->end(); ++iMap)
			{
				// If either the issuer or subject domain policy is any-policy,
				// empty the policy table and return. According to X.509
				// clause 8.2.2.7, policies shall not be mapped to or from
				// the special any-policy
				if ((iMap->issuerPolicy == kAnyPolicy) ||
					(iMap->subjectPolicy == kAnyPolicy))
				{
					m_table.clear();
					return;
				};

				bool matchFound = false;
				PolicyArray::iterator iRow;
				for (iRow = m_table.begin(); iRow != m_table.end(); ++iRow)
				{
					if (iRow->at(nDepth).policyId == iMap->issuerPolicy)
					{
						matchFound = true;

						// If the extension maps this issuer policy to more
						// than one subject policy, copy the previously mapped
						// row, and then map the new row
						if (iRow->at(nDepth + 1) != kAnyPolicy)
							iRow = m_table.insert(m_table.end(), *iRow);

						iRow->at(nDepth + 1).policyId = iMap->subjectPolicy;
						iRow->at(nDepth + 1).qualifiers =
							iRow->at(nDepth).qualifiers;

						mappingDetails.push_back(*iMap);
					}
				}

				// If a match wasn't found and if the first row of the nDepth
				// column is any-policy, write the issuer domain policy in
				// the policy mappings extension into the nDepth column, adding
				// rows as necessary, and retaining any qualifiers
				if (!matchFound && (m_table[0][nDepth] == kAnyPolicy))
				{
					// Insert row
					PolicyArray::iterator iNewRow =
						m_table.insert(m_table.end(),
						CML::Internal::PolicyTable::PolicyRow());
					iNewRow->insert(iNewRow->end(), m_depth + 1,
						kAnyPolicy);

					// Add the issuer policy to the nDepth column of the new row
					iNewRow->at(nDepth).policyId = iMap->issuerPolicy;
					iNewRow->at(nDepth).qualifiers =
						m_table[0][nDepth].qualifiers;

					// Add the subject policy mapping to the nDepth+1 column
					iNewRow->at(nDepth + 1).policyId = iMap->subjectPolicy;
					iNewRow->at(nDepth + 1).qualifiers =
						iNewRow->at(nDepth).qualifiers;

					mappingDetails.push_back(*iMap);
				}
			}
		}
	}

	// For any row not modified above, copy the policy from the nDepth column
	// into the nDepth+1 column of the same row
	for (unsigned int i = 0; i < m_table.size(); ++i)
	{
		if (m_table[i][nDepth + 1] == kAnyPolicy)
			m_table[i][nDepth + 1] = m_table[i][nDepth];
	}
}


/****************************************************************************
 * FUNCTION: PolicyTable::ProcessPolicies()
 *
 * Description:  This function updates this PolicyTable by performing the
 * X.509 cert path processing of the supplied certificate policies at the
 * specified path depth.
 *
 * Parameters:
 * (I) pPolicies         The contents of the certificate policies extension
 *                       in the cert
 * (I) nDepth            Integer indicating the current depth in the path
 * (I) inhibitAnyPolicy  The inhibit-any-policy-indicator flag
 * (I) isSelfIssuedCA    Flag indicating if this cert is a self-issued CA
 *
 * No return variable.  An exception is thrown if an error occurs.
 ****************************************************************************/
void PolicyTable::ProcessPolicies(const CertPolicyList* pPolicies,
                                  ushort nDepth, bool inhibitAnyPolicy,
                                  bool isSelfIssuedCA)
{
   // If the policy table is empty, just return
   if (IsEmpty())
      return;

   // Check that the table size hasn't been exceeded
   if (nDepth > m_depth)
      throw CML_ERR(CM_UNKNOWN_ERROR);

   // If the certificate policies are absent, set the the authorities-
   // constrained-policy-set to NULL
   if (pPolicies == NULL)
   {
      // Delete all rows in the table
      m_table.clear();
      m_depth = 0;
      return;
   }

   // For each policy in the extension...
   CertPolicyList::const_iterator iPolicy;
   for (iPolicy = pPolicies->begin(); iPolicy != pPolicies->end(); ++iPolicy)
   {
      if (iPolicy->policyId != kAnyPolicy)
      {
         // For policies other than any-policy, find the policies in the 
         // nDepth column that match this policy and attach the qualifiers
         // to the policies in that row
         bool matchFound = false;
         for (unsigned int iRow = 0; iRow < m_table.size(); ++iRow)
         {
            if (iPolicy->policyId == m_table[iRow][nDepth].policyId)
            {
               matchFound = true;
               m_table[iRow][nDepth] |= iPolicy->qualifiers;
            }
         }

         // If policy isn't present in the table, and the first policy
         // in the nDepth column is any-policy, then add a new row to the
         // table by duplicating the zeroth row and setting the nDepth column
         // to the policy and attaching its qualifiers
         if (!matchFound &&
            (m_table[0][nDepth].policyId == kAnyPolicy))
         {
            PolicyArray::iterator iNewRow = m_table.insert(m_table.end(),
               m_table[0]);
            iNewRow->at(nDepth).policyId = iPolicy->policyId;
            iNewRow->at(nDepth) |= iPolicy->qualifiers;
         }
      }
   }

   // If the special any-policy value is not present in the extension or if
   // the inhibit-any-policy flag is set and the cert is not a self-issued
   // intermediate cert, delete the row containing the any-policy (if present)
   // and any row containing a policy not present in the policy extension
   CertPolicyList::const_iterator iAnyPolicy = pPolicies->Find(kAnyPolicy);
   if ((iAnyPolicy == pPolicies->end()) ||
      (inhibitAnyPolicy && !isSelfIssuedCA))
   {
      // For each policy row in the nDepth column...
      PolicyArray::iterator iRow = m_table.begin();
      while (iRow != m_table.end())
      {
         CertPolicy& policy = iRow->at(nDepth);
         if ((policy.policyId == kAnyPolicy) ||
            (pPolicies->Find(policy.policyId) == pPolicies->end()))
         {
            iRow = m_table.erase(iRow);
         }
         else
            ++iRow;
      }
   }
   // Else, attach any qualifiers on the any-policy to each row in the table
   // whose nDepth column contains either any-policy or a policy that does not
   // appear in the extension.
   else if (!iAnyPolicy->qualifiers.empty())
   {
      // For each policy row in the nDepth column...
      PolicyArray::iterator iRow;
      for (iRow = m_table.begin(); iRow != m_table.end(); ++iRow)
      {
         CertPolicy& policy = iRow->at(nDepth);
         if ((policy.policyId == kAnyPolicy) ||
            (pPolicies->Find(policy.policyId) == pPolicies->end()))
         {
            policy |= iAnyPolicy->qualifiers;
         }
      }
   }
}


///////////////////////////////////////////////////////////////////////////////
// Function:      HasInvalidMappings()
// Description:   Check for an invalid policy mapping in the policy mappings
//                certificate extension
// Inputs:        pPolicyMappings
// Outputs:       (none)
// Return value:  true if the policy mappings extension does have an invalid
//                policy mapping, otherwise false is returned.
///////////////////////////////////////////////////////////////////////////////
bool CML::Internal::HasInvalidMappings(const ASN::PolicyMappingList& policyMappings)
{
   ASN::PolicyMappingList::const_iterator iMap;
   for (iMap = policyMappings.begin(); iMap != policyMappings.end(); ++iMap)
   {
      // Return true if either the issuer or subject domain policy is any-policy,
      // According to X.509 clause 8.2.2.7, policies shall not be mapped to or from
      // the special any-policy
      if ((iMap->issuerPolicy == SNACC::anyPolicy) ||
          (iMap->subjectPolicy == SNACC::anyPolicy))
      {
         // An invalid policy mapping was found.
         return true;
      }
   }

   // no invalid policy mappings were found
   return false;
}


// end of CM_certPolicies.cpp
