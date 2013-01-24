/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:07 (EST)
  Function:
*/

#ifndef __acdns_lock_h_
#define __acdns_lock_h_

#include <defs.h>
#include <pthread.h>

class Mutex {
private:
    pthread_mutex_t _mutex;

public:
    Mutex();
    ~Mutex();
    void lock(void);
    void unlock(void);
    int trylock(void);

private:
    DISALLOW_COPY(Mutex);
};

// ################################################################

class SpinLock {
private:
    pthread_spinlock_t _spin;

public:
    SpinLock();
    ~SpinLock();
    void lock(void);
    void unlock(void);
    int trylock(void);

private:
    DISALLOW_COPY(SpinLock);
};

// ################################################################

class RWLock {
private:
    pthread_rwlock_t _rwlock;

public:
    RWLock();
    ~RWLock();
    // do, or do not, there is no try
    void r_lock(void);
    void r_unlock(void);
    void w_lock(void);
    void w_unlock(void);

private:
    DISALLOW_COPY(RWLock);
};


#endif //__acdns_lock_h_
