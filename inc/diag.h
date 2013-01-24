/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:06 (EST)
  Function: diagnostic messages
*/

#ifndef __acdns_diag_h_
#define __acdns_diag_h_

#ifndef CURRENT_SUBSYSTEM
#define CURRENT_SUBSYSTEM	0
#endif

extern int debug_enabled;
extern void diag_init(void);
extern void diag(int level, const char *file, const char *func, int line, int system, const char *fmt, ...);

#ifdef __SUNPRO_CC
#  define __FUNCTION__	__func__
#endif

#define _DIAG_F_F_L_CS		__FILE__, __FUNCTION__, __LINE__, CURRENT_SUBSYSTEM

#define DIAG_LOG_DEBUG0      0
#define DIAG_LOG_DEBUG1      1
#define DIAG_LOG_DEBUG7      7

#define DIAG_LOG_INFO        8
// sends email:
#define DIAG_LOG_WARN        9
// sends email + stack trace
#define DIAG_LOG_BUG         10
// sends email, stack trace + aborts
#define DIAG_LOG_FATAL       99

#ifdef __SUNPRO_CC
#  ifdef DEBUGING
#    define DEBUG(...)		if(debug_enabled) diag(DIAG_LOG_DEBUG7, _DIAG_F_F_L_CS, __VA_ARGS__)
#    define DEBUG1(...)		if(debug_enabled) diag(DIAG_LOG_DEBUG1, _DIAG_F_F_L_CS, __VA_ARGS__)
#    define TRACE(...)		if(debug_enabled) diag(DIAG_LOG_DEBUG0, _DIAG_F_F_L_CS, __VA_ARGS__)
#  else
#    define DEBUG(...)
#    define DEBUG1(...)
#    define TRACE(...)
#  endif
#  define VERBOSE(...)		diag(DIAG_LOG_INFO,  _DIAG_F_F_L_CS, __VA_ARGS__)
#  define PROBLEM(...)		diag(DIAG_LOG_WARN,  _DIAG_F_F_L_CS, __VA_ARGS__)
#  define FATAL(...)		diag(DIAG_LOG_FATAL, _DIAG_F_F_L_CS, __VA_ARGS__)
#  define BUG(...)		diag(DIAG_LOG_BUG,   _DIAG_F_F_L_CS, __VA_ARGS__)
#else
#  ifdef DEBUGING
#    define DEBUG(args...)	if(debug_enabled) diag(DIAG_LOG_DEBUG7, _DIAG_F_F_L_CS, args)
#    define DEBUG1(args...)	if(debug_enabled) diag(DIAG_LOG_DEBUG1, _DIAG_F_F_L_CS, args)
#    define TRACE(args...)	if(debug_enabled) diag(DIAG_LOG_DEBUG0, _DIAG_F_F_L_CS, args)
#  else
#    define DEBUG(args...)
#    define DEBUG1(args...)
#    define TRACE(args...)
#  endif
#  define VERBOSE(args...)	diag(DIAG_LOG_INFO,  _DIAG_F_F_L_CS, args)
#  define PROBLEM(args...)	diag(DIAG_LOG_WARN,  _DIAG_F_F_L_CS, args)
#  define FATAL(args...)	diag(DIAG_LOG_FATAL, _DIAG_F_F_L_CS, args)
#  define BUG(args...)		diag(DIAG_LOG_BUG,   _DIAG_F_F_L_CS, args)
#endif

#endif // __acdns_diag_h_

