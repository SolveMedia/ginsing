/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:08 (EST)
  Function: 
*/

#ifndef __acdns_defs_h_
#define __acdns_defs_h_


typedef unsigned char uchar;


#define DEBUGING	1

#define DISALLOW_COPY(T) \
	T(const T &);	\
	void operator=(const T&)

#endif // __acdns_defs_h_
