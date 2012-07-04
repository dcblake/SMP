/************************ PKCS #11 Object Management Functions ************************
 *
 * This source file contains the following functions:
 * + C_CreateObject
 * + C_CopyObject
 * + C_DestroyObject
 * + C_GetObjectSize
 * + C_GetAttributeValue
 * + C_SetAttributeValue
 * + C_FindObjectsInit
 * + C_FindObjects
 * + C_FindObjectsFinal
 */

#include "p11cryptopp_internal.h"


/* C_CreateObject 
 * creates a new object. hSession is the session’s handle; pTemplate points to
 * the object’s template; ulCount is the number of attributes in the template; phObject points to
 * the location that receives the new object’s handle.
 */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
		CK_ULONG          ulCount,     /* attributes in template */
		CK_OBJECT_HANDLE_PTR phObject)  /* gets new object's handle. */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check for invalid arguments
	if ((pTemplate == NULL) || (ulCount == 0) || (phObject == NULL))
		return CKR_ARGUMENTS_BAD;

	// Find the session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	CKObject* pObject = NULL;
	try {
		// Construct the object
		pObject = CKObject::Construct(pTemplate, ulCount);

		// Add the newly created object to the object map
		*phObject = pSession->AddObject(pObject);

		return CKR_OK;
	}
	catch (CK_RV err) {
		if (pObject != NULL)
			delete pObject;
		return err;
	}

#ifdef _OLD_CODE
	CKObjectMap::iterator j;
	bool isKey = false;
	
	/* for our implementation the CKA_CLASS must be first and always present */
	if (pTemplate[0].type != CKA_CLASS)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}

	/* traverse template to figure out what we are creating */
	
	CK_ULONG n;
	n=0;

    /* handle public key objects */	
	if  (((CK_ULONG *)pTemplate[n].pValue)[0] == CKO_PUBLIC_KEY ||
		 ((CK_ULONG *)pTemplate[n].pValue)[0] == CKO_PRIVATE_KEY)
		isKey = true;
	else if (((CK_ULONG *)pTemplate[n].pValue)[0] == CKO_DOMAIN_PARAMETERS)
	    isKey = false;
	else
		return CKR_TEMPLATE_INCONSISTENT;
	
	n++;
	/* the next template argument must be a CKA_KEY_TYPE */
	if (pTemplate[n].type != CKA_KEY_TYPE)
		return CKR_TEMPLATE_INCONSISTENT;

	/* if this a DSA key or domain parameters */
	if (((CK_ULONG *)pTemplate[n].pValue)[0] == CKK_RSA)
	{
		/* check template */
		CKObjectPair objPair;
		*phObject = objPair.first = i->second.m_objectMap.size() + 1;
		j = i->second.m_objectMap.insert(i->second.m_objectMap.end(), objPair);
		j->second.pObject = new CKGenericObject();
	}
	else if (((CK_ULONG *)pTemplate[n].pValue)[0] == CKK_DSA)
	{
		n++;
		std::string p,q,g,key;

		/* the following fields are required
			look for CKA_PRIME (P), CKA_SUBPRIME (Q), CKA_BASE (G), and CKA_VALUE (Y) 
		*/
		for (; n < ulCount; n++)
		{
			switch(pTemplate[n].type)
			{
				case CKA_PRIME:
               if (p.length() > 0)
                  return CKR_TEMPLATE_INCONSISTENT;
					p.insert(0,(char *)pTemplate[n].pValue, pTemplate[n].ulValueLen);
					break;
				case CKA_SUBPRIME:
               if (q.length() > 0)
                  return CKR_TEMPLATE_INCONSISTENT;
					q.insert(0,(char *)pTemplate[n].pValue, pTemplate[n].ulValueLen);
					break;
				case CKA_BASE:
					if (g.length() > 0)
                  return CKR_TEMPLATE_INCONSISTENT;
               g.insert(0,(char *)pTemplate[n].pValue, pTemplate[n].ulValueLen);
					break;
				case CKA_VALUE:
               if (key.length() > 0)
                  return CKR_TEMPLATE_INCONSISTENT;
					key.insert(0,(char *)pTemplate[n].pValue, pTemplate[n].ulValueLen);
					break;
			}
		}

		/* PIERCE: P,Q,G required regardless of whether or not your a generating domain parameters
		 *         or a public key?
		 */
		if (p.length() == 0 || q.length() == 0 || g.length() == 0)
			return CKR_TEMPLATE_INCONSISTENT;

		CKObjectPair objPair;

		if (isKey &&  key.length() != 0)
		{
			/* create public key object with parameters */
			
			*phObject = objPair.first = i->second.m_objectMap.size() + 1;
			j = i->second.m_objectMap.insert(i->second.m_objectMap.end(), objPair);
			j->second.pObject = new CKDSAPublicKeyObject(p,q,g,key);
		}
		else if (!isKey)
		{
			/* create domain parameters */
			*phObject = objPair.first = i->second.m_objectMap.size() + 1;
			j = i->second.m_objectMap.insert(i->second.m_objectMap.end(), objPair);
			j->second.pObject = new CKDSAPublicKeyObject(p,q,g);
		}
		else
			return CKR_TEMPLATE_INCONSISTENT;
	}
	else
	{
		return CKR_TEMPLATE_INCONSISTENT;
		
	}
	i->second.m_objectMap[*phObject].setTemplate(pTemplate, ulCount);
#endif // _OLD_CODE
}


/* C_CopyObject
 * copies an object, creating a new object for the copy. hSession is the session’s
 * handle; hObject is the object’s handle; pTemplate points to the template for the new object;
 * ulCount is the number of attributes in the template; phNewObject points to the location that
 * receives the handle for the copy of the object. 
 */
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(
		CK_SESSION_HANDLE    hSession,    /* the session's handle */
		CK_OBJECT_HANDLE     hObject,     /* the object's handle */
		CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
		CK_ULONG             ulCount,     /* attributes in template */
		CK_OBJECT_HANDLE_PTR phNewObject)  /* receives handle of copy */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DestroyObject 
 * destroys an object. hSession is the session’s handle; and hObject is the
 * object’s handle. 
 */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject)    /* the object's handle */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Find the session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Find the requested object
	CKObjectMap::iterator obj = pSession->m_objectMap.find(hObject);
	if (obj == pSession->m_objectMap.end())
		return CKR_OBJECT_HANDLE_INVALID;

	// Delete the object and erase its entry in the map
	delete obj->second;
	pSession->m_objectMap.erase(obj);

	return CKR_OK;
}


/* C_GetObjectSize
 * gets the size of an object in bytes. hSession is the session’s handle;
 * hObject is the object’s handle; pulSize points to the location that receives the size
 * in bytes of the object.
 */
CK_DEFINE_FUNCTION(CK_RV,C_GetObjectSize)(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize)    /* receives size of object */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_GetAttributeValue
 * obtains the value of one or more attributes of an object. hSession is
 * the session’s handle; hObject is the object’s handle; pTemplate points to a template that
 * specifies which attribute values are to be obtained, and receives the attribute values; 
 * ulCount is the number of attributes in the template. 
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount)     /* attributes in template */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check for invalid arguments
	if ((pTemplate == NULL) || (ulCount == 0))
		return CKR_ARGUMENTS_BAD;

	// Find the session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Find the requested object
	CKObjectMap::iterator obj = pSession->m_objectMap.find(hObject);
	if (obj == pSession->m_objectMap.end())
		return CKR_OBJECT_HANDLE_INVALID;
	if (obj->second == NULL)
		return CKR_GENERAL_ERROR;

	// Find each of the requested attribute values in the template
	CK_RV rv = CKR_OK;
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		CK_RV attribResult = obj->second->GetAttributeValue(pTemplate[i]);
		if (attribResult == CKR_ATTRIBUTE_SENSITIVE)
			rv = attribResult;
		else if ((attribResult == CKR_ATTRIBUTE_TYPE_INVALID) &&
			(rv != CKR_ATTRIBUTE_SENSITIVE))
			rv = attribResult;
		else if ((attribResult == CKR_BUFFER_TOO_SMALL) &&
			(rv != CKR_ATTRIBUTE_SENSITIVE) && (rv != CKR_ATTRIBUTE_TYPE_INVALID))
			rv = attribResult;
		else if (attribResult != CKR_OK)	// Return the fatal error
			return attribResult;
	}

	return rv;
}


/* C_SetAttributeValue
 * modifies the value of one or more attributes of an object. hSession is
 * the session’s handle; hObject is the object’s handle; pTemplate points to a template that
 * specifies which attribute values are to be modified and their new values; ulCount is the 
 * number of attributes in the template.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount)     /* attributes in template */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_FindObjectsInit
 * initializes a search for token and session objects that match a template.
 * hSession is the session’s handle; pTemplate points to a search template that specifies the
 * attribute values to match; ulCount is the number of attributes in the search template. The
 * matching criterion is an exact byte-for-byte match with all attributes in the template. To 
 * find all objects, set ulCount to 0.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount)     /* attrs in search template */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_FindObjects
 * continues a search for token and session objects that match a template,
 * obtaining additional object handles. hSession is the session’s handle; phObject points to the
 * location that receives the list (array) of additional object handles; ulMaxObjectCount is the
 * maximum number of object handles to be returned; pulObjectCount points to the location that
 * receives the actual number of object handles returned.
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount)     /* actual # returned */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_FindObjectsFinal
 * terminates a search for token and session objects. hSession is the
 * session’s handle.
 */
CK_DEFINE_FUNCTION(CK_RV,C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession)  /* the session's handle */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
