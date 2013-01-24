/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:05 (EST)
  Function: 
*/

#ifndef __acdns_daemon_h_
#define __acdns_daemon_h_

extern int  daemonize(int, const char *, int, char **);
extern void daemon_siginit(void);
void install_handler(int sig, void(*func)(int));

#endif //  __acdns_daemon_h_

