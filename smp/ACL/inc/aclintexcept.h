

// internal exceptions
class InternalAclException
{
public:
  InternalAclException() { m_pErrMsg = NULL; }
  InternalAclException(const InternalAclException &that) { m_pErrMsg = NULL;  operator=(that); }
  virtual ~InternalAclException(void) 
  {
    if (m_pErrMsg) 
    {
      free(m_pErrMsg);
      m_pErrMsg = NULL;
    }
  }
  InternalAclException & operator=(const InternalAclException &that)
  {
     if (m_pErrMsg)
		  free(m_pErrMsg);
	  if (that.m_pErrMsg)
		  m_pErrMsg = strdup(that.m_pErrMsg);
	  return *this;
  }
  void setMsg(const char *errMsg) { m_pErrMsg = strdup(errMsg);}
  
  const char * getMsg(void) { return(m_pErrMsg); }

private:
  char *m_pErrMsg;
};

class EmptyList : public InternalAclException
{
public:
  EmptyList(char *errMsg) { setMsg(errMsg);}
};

