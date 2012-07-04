//////////////////////////////////////////////////////////////////////////////
// aclcacheable.cpp
// These routines support the Cacheable Class
// CONSTRUCTOR(s):
//   Cacheable()
// DESTRUCTOR:
//   ~Cacheable()
// MEMBER FUNCTIONS:
//   operator ==(Cacheable &that)
//   operator =(Cacheable &that)
//   validate(Session *pSession, PublicKeyInfo &pubKeyInfo)
//   isValid()
//   validate(Session *pSession, CSM_BufferLst *issuerPath)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
Cacheable::Cacheable(const CacheType &cacheType)
{
   type = cacheType;
   m_isValidFlag = NOT_VALID;

   // CATCH ALL default TTL
   // PIERCE: TDB make sure this gets reset based on
   //         ac_ttl and spif_ttl from Session when
   //         adding to cache.
   //
   // default m_ttl to 48 hours
   //   AclSysTime defaultTTL(48);
   //CML::ASN::Time defaultTTL(time(NULL) + 48*60*60);
   //m_ttl = defaultTTL;
   m_hash.Clear();

} // END OF CONSTRUCTOR

bool Cacheable::validate(Session *s)
{
	FUNC("Cacheable::validate()");
	
	// Return true if the object is already valid
	if (isValid())
		return true;
	
	// Set the mode to first search locally, then search remote
	s->setCacheMode(Session::LOCAL_THEN_REMOTE);
	
	// Construct the match info for this object's issuer
	acl::MatchInfo mi;
	getIssuerInfo(mi);
	
	// Find this object's issuer (clearance cert)
	CCList *pCCList = s->getCC(mi);
	if (pCCList == NULL)
    {
        char lpszBuf[2048];
        strcpy(lpszBuf, "Issuer not found");
        if (mi.getSubjectDN())
        {
            strcat(lpszBuf, ", ");
            strcat(lpszBuf, *mi.getSubjectDN());
        }
		throw ACL_EXCEPT(ACL_AC_VAL_ERROR, lpszBuf);
    }       // END IF pCCList (no issuer(s))
	
	// Create auto_ptr to automatically free the list
	std::auto_ptr<CCList> apCCList(pCCList);
	
	// If more than one issuer is returned, throw an exception
	if (pCCList->size() > 1)
    {
		char errorBuf[1024];
        strcpy(errorBuf, "Multiple issuers found");
        if (mi.getSubjectDN())
        {
            strcat(errorBuf, ", ");
            strcat(errorBuf, *mi.getSubjectDN());
        }
		throw ACL_EXCEPT(ACL_AC_VAL_ERROR, errorBuf);
    }
	
	// Validate the issuer's clearance cert
	CML::ValidatedKey validKey;
    CML::ErrorInfoList Errors;

	CML::CertPath certPath(pCCList->front().getEncodedCC(), false);
	short cml_status = certPath.BuildAndValidate(s->getCMLHandle(),
        CM_SEARCH_UNTIL_FOUND, &Errors, 0, &validKey);
	if (cml_status != CM_NO_ERROR)
	{
		char errorBuf[1024];
		sprintf(errorBuf, "Issuer failed to validate: CML error %d: %s",
			cml_status, CMU_GetErrorString(cml_status));
        if (mi.getSubjectDN())
        {
            strcat(errorBuf, ", ");
            strcat(errorBuf, *mi.getSubjectDN());
        }
		throw ACL_EXCEPT(ACL_VAL_ERROR, errorBuf);
	}
	
	// Perform any object specific path validation logic first
	vPathRules(s, certPath.base());
	
	// Validate the object
	return validate(s, validKey.pubKeyInfo());
}


// validate:
//
bool Cacheable::validate(Session *pSession, const CML::ASN::PublicKeyInfo &pubKeyInfo)
{
	FUNC("Cacheable::validate");
		
	// If this object has been validated or validation has been disabled,
	// return true
	if (isValid() || (pSession->m_disable_validation == true))
		return true;

	try
	{
		// Check the validity of the object being validated
		//
		if (! checkValidity())
		{
			AclString errStr;
			errStr << "Object has Expired\n";
			getDescription(errStr);
			
			m_isValidFlag = NOT_VALID;
			pSession->removeCache(*this);
			
			throw ACL_EXCEPT(ACL_VAL_ERROR, errStr.str());
		}
		
		// Finally verify signature on cacheable object.
		//
		CML::SignedAsnObj spifSignedObj(m_origObject);
		if (spifSignedObj.VerifySignature(pSession->getCMLHandle(),
			pubKeyInfo) != CM_NO_ERROR)
			throw ACL_EXCEPT(ACL_VAL_ERROR, "Invalid signature");
		
		// Set state flag to valid
		//
		m_isValidFlag = VALID;
		
		// UpdateCache
		pSession->updateCache(*this);
		
		return true;
	}
	catch (SnaccException &e)
	{
		e.push(STACK_ENTRY);
		throw;
	}
} // END OF MEMBER FUNCTION validate

// isValid:
//
bool Cacheable::isValid()
{
    if (isExpired())
       return false;

    if (this->m_isValidFlag == VALID)
        return true;
    else
        return false;
} // END OF MEMBER FUNCTION isValid

// isExpired:
//
bool Cacheable::isExpired()
{
    CML::ASN::Time sysTime;

    if (sysTime > this->m_expireTime )
    {
        this->m_isValidFlag = TTL_EXPIRED;
        return true;
    }
    return false;
} // END OF MEMBER FUNCTION isExpired

// getHash:
//
const CML::ASN::Bytes & Cacheable::getHash(void)
{
   FUNC("Cacheable::getHash");
   try
   {
       if (m_hash.Len() < 1)
       {
          if (this->m_origObject.Len() < 1)
          {
             char errStr[256];
             sprintf(errStr, "Can not cache objects that%s",
                "\n\tdo not originate from CML::ASN::Bytes");
             throw ACL_EXCEPT(ACL_CACHE_ERROR, &errStr[0]);
          }
          this->m_origObject.Hash(m_hash);
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return m_hash;
} // END OF MEMBER FUNCTION getHash

// operator ==:
//
bool Cacheable::operator ==(const Cacheable &that) const
{
   if ((type == that.type) &&
       (m_hash == that.m_hash))
       return true;
   else
      return false;
} // END OF OPERATOR OVERLOAD ==

// operator =:
//
Cacheable & Cacheable::operator =(const Cacheable &that)
{
   this->m_hash = that.m_hash;
   this->m_isValidFlag = that.m_isValidFlag;
   this->m_origObject = that.m_origObject;
   return (*this);
} // END OF OPERATOR OVERLOAD =

void Cacheable::updateTTL(unsigned long ttl) const
{
   time_t currtime;
   time(&currtime);
   m_expireTime = (currtime + (ttl * 60 * 60)); 
} // END OF MEMBER FUNCTION updateTTL

_END_NAMESPACE_ACL

// EOF aclcacheable.cpp

