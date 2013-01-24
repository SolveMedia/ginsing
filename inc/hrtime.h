/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:05 (EST)
  Function: high-resolution time
*/

#ifndef __acdns_hrtime_h_
#define __acdns_hrtime_h_

#include <sys/time.h>

#ifndef HAVE_HRTIME
typedef long long hrtime_t;
inline hrtime_t gethrtime(void){
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (hrtime_t)( (long long)tv.tv_sec * 1000000LL + (long long)tv.tv_usec) * 1000LL;
}
#endif

#define hr_now()	gethrtime()
#define lr_now()	time(0)

#define ONE_SECOND_HR	1000000000LL
#define ONE_MSEC_HR	1000000LL

#endif // __acdns_hrtime_h_
