/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:18 (EST)
  Function: mutexes
*/

#include "defs.h"
#include "thread.h"
#include "lock.h"


class Mutex_Attr {
public:
    pthread_mutexattr_t attr;
    Mutex_Attr();
};

Mutex_Attr::Mutex_Attr() {
    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_NORMAL );
}

static Mutex_Attr *default_mutex_attr = 0;

//################################################################

Mutex::Mutex(){
    if( ! default_mutex_attr ){
        default_mutex_attr = new Mutex_Attr;
    }
    pthread_mutex_init( &_mutex, &default_mutex_attr->attr );
}

Mutex::~Mutex(){
    trylock();
    unlock();
    pthread_mutex_destroy( &_mutex );
}

void
Mutex::lock(void){
    pthread_mutex_lock( &_mutex );
}

void
Mutex::unlock(void){
    pthread_mutex_unlock( &_mutex );
}

// 0 = got the lock
int
Mutex::trylock(void){
    return pthread_mutex_trylock( &_mutex );
}

//################################################################


SpinLock::SpinLock(){

    pthread_spin_init( &_spin, PTHREAD_PROCESS_SHARED );
}

SpinLock::~SpinLock(){
    trylock();
    unlock();
    pthread_spin_destroy( &_spin );
}

void
SpinLock::lock(void){
    pthread_spin_lock( &_spin );
}

void
SpinLock::unlock(void){
    pthread_spin_unlock( &_spin );
}

int
SpinLock::trylock(void){
    return pthread_spin_trylock( &_spin );
}

//################################################################

class RWLock_Attr {
public:
    pthread_rwlockattr_t attr;
    RWLock_Attr();
};

RWLock_Attr::RWLock_Attr() {
    pthread_rwlockattr_init( &attr );
}

static RWLock_Attr *default_rwlock_attr = 0;

//################################################################

RWLock::RWLock(){
    if( ! default_rwlock_attr ){
        default_rwlock_attr = new RWLock_Attr;
    }
    pthread_rwlock_init( &_rwlock, &default_rwlock_attr->attr );
}

RWLock::~RWLock(){
    w_lock();
    w_unlock();
    pthread_rwlock_destroy( &_rwlock );
}

void
RWLock::r_lock(void){
    pthread_rwlock_rdlock( &_rwlock );
}

void
RWLock::r_unlock(void){
    pthread_rwlock_unlock( &_rwlock );
}

void
RWLock::w_lock(void){
    pthread_rwlock_wrlock( &_rwlock );
}

void
RWLock::w_unlock(void){
    pthread_rwlock_unlock( &_rwlock );
}

