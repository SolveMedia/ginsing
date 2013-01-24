/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:10 (EST)
  Function: threads
*/

#ifndef __acdns_thread_h_
#define __acdns_thread_h_

#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <pthread.h>

int start_thread(void *(*func)(void*), void *arg);


#endif // __acdns_thread_h_
