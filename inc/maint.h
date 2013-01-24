/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-22 17:12 (EST)
  Function: track datacenter maintenance
*/

#ifndef __acdns_maint_h_
#define __acdns_maint_h_


extern bool maint_set(const char *, bool);
extern bool maint_get(const char *);
extern void maint_register(const char *);


#endif // __acdns_maint_h_
