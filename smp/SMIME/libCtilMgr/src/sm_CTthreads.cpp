// sm_CTthreads.cpp
// The following "NOTHREADS" define allows the application/lib code that 
//  uses threads to not require this define (cleaner).  In this source module
//  the thread lock logic is disabled (there is some slight performance loss
//  in the wasted no-op call to the thread lock/unlock, but the logic is
//  cleaner).  This technique also has the advantage that only this source
//  file needs the "NOTHREADS" definition to turn thread locking off.

#include "asn-incl.h"

#ifndef NOTHREADS

#ifndef WIN32
#define _GNU_SOURCE     // __USE_GNU
#include <pthread.h>
#ifdef SunOS
pthread_mutexattr_t GLOBALmutex_attr;
#else
pthread_mutex_t GLOBALmutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#endif //SunOS
#else
#include <windows.h>
#endif      // WIN32
#endif      // NOTHREADS
#include "sm_apiCtilMgr.h"


_BEGIN_CTIL_NAMESPACE 

//
//
CSM_ThreadLock::~CSM_ThreadLock()
{
#ifndef NOTHREADS
    if (m_pThreadLock)
    {
    #ifdef WIN32
        CRITICAL_SECTION *pcriticalSection = (CRITICAL_SECTION *)m_pThreadLock;
        DeleteCriticalSection(pcriticalSection);
        delete pcriticalSection;
    #else	//UNIX
        pthread_mutex_t *pm_mutex = (pthread_mutex_t *)m_pThreadLock;
		#ifdef SunOS
			pthread_mutex_destroy(pm_mutex);
		#endif
        delete pm_mutex;
    #endif  //WIN32
    }
#endif
}
//
//
CSM_ThreadLock::CSM_ThreadLock()
{
    m_lRefCount = 0;
   //m_bHangOnCriticalSection = bHangOnCriticalSection;
#ifndef NOTHREADS
    #ifdef WIN32
        CRITICAL_SECTION/*CCriticalSection*/ *pcriticalSection = 
            new CRITICAL_SECTION;
        //static CSingleLock singleLock(&criticalSection);
        InitializeCriticalSection(pcriticalSection);
        m_pThreadLock = pcriticalSection;
    #else	//UNIX
        // DEFAULT will deadlock an app if called 2ce w/in same thread.
        pthread_mutex_t *pm_mutex = new pthread_mutex_t;
		#ifdef SunOS
			pthread_mutexattr_init(&GLOBALmutex_attr);
			pthread_mutexattr_settype(&GLOBALmutex_attr, PTHREAD_MUTEX_RECURSIVE);
			pthread_mutex_init(pm_mutex, &GLOBALmutex_attr);
		#else
			*pm_mutex = GLOBALmutex;
		#endif //SunOS		
        m_pThreadLock = pm_mutex;
    #endif  //WIN32
#endif //NOTHREADS
}

//
//
void CSM_ThreadLock::threadLock()
{
#ifndef NOTHREADS
    #ifdef WIN32
    //bool bResult=true;
    CRITICAL_SECTION *pcriticalSection = (CRITICAL_SECTION *)m_pThreadLock;

    //if (this->m_bHangOnCriticalSection)
       EnterCriticalSection(pcriticalSection);
    //else
    /* ONLY ON WIN2k   bResult = TryEnterCriticalSection(pcriticalSection);
    if (!bResult)
    {
       SME_THROW(22, "threadLock critical section access failed", NULL);
    }*/
    //singleLock.Lock();  // Attempt to lock the shared resource
    //if (singleLock.IsLocked())  // Resource has been locked
    #else //UNIX
    pthread_mutex_t *pm_mutex = (pthread_mutex_t *)m_pThreadLock;
    pthread_mutex_lock(pm_mutex);
    #endif  // WIN32
    m_lRefCount++;
#endif  //NOTHREADS
}

//
//
void CSM_ThreadLock::threadUnlock()
{
#ifndef NOTHREADS
    if (m_lRefCount > 0)
    {
        #ifdef WIN32
        CRITICAL_SECTION *pcriticalSection = (CRITICAL_SECTION *)m_pThreadLock;
        LeaveCriticalSection(pcriticalSection);
        //singleLock.Unlock();
        #else   //UNIX
        pthread_mutex_t *pm_mutex = (pthread_mutex_t *)m_pThreadLock;
        pthread_mutex_unlock(pm_mutex);
        #endif  //WIN32
        m_lRefCount--;
    }
#endif  //NOTHREADS
}

_END_CTIL_NAMESPACE 

// EOF sm_CTthreads.cpp
