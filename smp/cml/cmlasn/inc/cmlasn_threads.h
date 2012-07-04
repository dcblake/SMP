/****************************************************************************
File:     cmlasn_threads.h
Project:  Certificate Management ASN.1 Library
Contents: Header file for the Mutex and Thread classes

Created:  30 April 2003
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	2 September 2003

Version:  2.3

*****************************************************************************/
#ifndef _CMLASN_THREADS_H
#define _CMLASN_THREADS_H

#ifdef WIN32
#pragma warning(disable: 4512)	// Disable assignment operator warning
#endif

// Begin CML namespace
namespace CML {

// Begin nested ASN namespace
namespace ASN {

	
///////////////////////
// Class Definitions //
///////////////////////

// Forward declarations
class Mutex;
class ReadWriteMutex;
class ReadLock;


class CM_API MutexLock
{
public:
	// Copy constructor
	MutexLock(const MutexLock& that);
	// Destructor
	virtual ~MutexLock()							{ Release(); }

	// Release the lock prior to its destruction
	virtual void Release();

protected:
	// Protected constructor
	MutexLock(const Mutex& mutex) : m_mutex(mutex)	{ m_isReleased = false; }
	// Protected assignment operator
	MutexLock& operator=(const MutexLock& that);

	// Member variables
	mutable bool m_isReleased;	// Indicates if the lock has been released
	const Mutex& m_mutex;		// Mutex associated with this lock

	// Friend class
	friend class Mutex;
	friend class ReadWriteMutex;
};


class CM_API Mutex
{
public:
	// Constructor/Destructor
	Mutex(const char* mutexName = NULL);
	virtual ~Mutex();

	// Methods
	virtual MutexLock AcquireLock() const;

	// Copy constructor and assignment operator
	Mutex(const Mutex& that);

protected:
#ifndef NOTHREADS
#ifdef WIN32
	mutable HANDLE m_winHandle;
	mutable HANDLE m_winWriteEvent;
	mutable HANDLE m_winReadEvent;
#else
	pthread_mutex_t m_mutex;
	pthread_cond_t m_WriteCondition;
	pthread_cond_t m_ReadCondition;
#endif
#endif

private:
	mutable bool m_wasCopied;				// Flag specifing whether or not this mutex instance 
											// was copied. If set, we do not close the operating system
											// mutex handles when this instance is destroyed.
	virtual void ReleaseLock() const		{ ReleaseMutex(); }
	void ReleaseMutex() const;
    Mutex& operator=(const Mutex&);

	// Friend classes
	friend class ReadLock;
	// Friend functions
	friend void MutexLock::Release();
};


class CM_API ReadWriteMutex : public Mutex
{
public:
	// Constructor
	ReadWriteMutex(const char* mutexName = NULL, unsigned int maxReadThreads = 0);

	// Methods
	virtual MutexLock AcquireLock() const;	// Used for writing
	ReadLock AcquireReadLock() const;		// Used for reading

	// Returns true if referenced
	bool IsReferenced(void) const			{ return (m_nReads != 0); }

private:
	virtual void ReleaseLock() const;

	mutable unsigned int m_nReads;		// Number of threads currently reading
	unsigned int m_maxReads;			// Maximum number of concurrent threads
};


class CM_API ReadLock : public MutexLock
{
public:
	// Copy constructor
	ReadLock(const ReadLock& that);
	// Destructor
	virtual ~ReadLock()										{ Release(); }
	// Release the lock prior to its destruction
	virtual void Release();

private:
	// Private constructor
	ReadLock(const ReadWriteMutex& mutex) : MutexLock(mutex)	{}

	// Friend class
	friend class ReadWriteMutex;
};


} // end of nested ASN namespace

} // end of CML namespace


#endif // _CMLASN_THREADS_H
