/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:08 (EST)
  Function: 
*/


#ifndef __acdns_misc_h_
#define __acdns_misc_h_

#include <stdlib.h>

#define ELEMENTSIN(T) (sizeof(T)/sizeof(T[0]))

#define MAX(a,b)	(((a)<(b)) ? (b) : (a))
#define MIN(a,b)	(((a)<(b)) ? (a) : (b))
#define ABS(x)		(((x) < 0) ? -(x) : (x))
#define BOUND(x,min,max) MAX(MIN((x),(max)),(min))

inline int with_probability(float p){ return random() < p * 0x7FFFFFFF; }



#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8
#  define ATOMIC_SET32(a,b)		((a)  = (b))	// QQQ - are these safe?
#  define ATOMIC_SET64(a,b)		((a)  = (b))
#  define ATOMIC_ADD32(a,b)  		__sync_fetch_and_add((uint32_t*)&a, b )
#  define ATOMIC_ADD64(a,b)  		__sync_fetch_and_add((uint64_t*)&a, b )

#elif defined(__sun__) || defined(__NetBSD__)
#  include <atomic.h>
#  define ATOMIC_SET32(a,b)		atomic_swap_32( (uint32_t*)&a, b )
#  define ATOMIC_SET64(a,b)		atomic_swap_64( (uint64_t*)&a, b )
#  define ATOMIC_ADD32(a,b)		atomic_add_32(  (uint32_t*)&a, b )
#  define ATOMIC_ADD64(a,b)		atomic_add_64(  (uint64_t*)&a, b )

#else
#  error "how should I do atomic ops?"
// RSN - macosx: man atomic
#if 0
#  define ATOMIC_SET32(a,b)		((a)  = (b))
#  define ATOMIC_SET64(a,b)		((a)  = (b))
#  define ATOMIC_ADD32(a,b)		((a) += (b))
#  define ATOMIC_ADD64(a,b)		((a) += (b))
#endif
#endif


#define ATOMIC_SETPTR(a,b)		((a) = (b))



#endif // __acdns_misc_h_
