/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:16 (EST)
  Function: diagnostics

*/

#include "defs.h"
#include "diag.h"
#include "misc.h"
#include "config.h"
#include "hrtime.h"
#include "thread.h"
#include "runmode.h"
#include "console.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static void send_error_email(const char*, int, int);

extern int flag_debugall;
extern int flag_foreground;

int debug_enabled = 0;		// at least one debug is enabled
static char hostname[256];	// for email

struct LevelConf {
    int syslogprio;
    int to_stderr;
    int to_console;
    int to_email;
    int with_info;
    int with_trace;
    int is_fatal;
};

struct LevelConf logconf[] = {
    // syslog        to_         with_   fatal
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },		// debug
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },
    { LOG_DEBUG,     1, 0, 0,    1, 0,    0, },
    { LOG_INFO,      1, 1, 0,    0, 0,    0, },		// verbose
    { LOG_WARNING,   1, 1, 1,    1, 0,    0, },		// problem
    { LOG_ERR,       1, 1, 1,    1, 1,    0, },		// bug
    { LOG_ERR,       1, 1, 1,    1, 1,    1  },		// fatal
};

void
diag_init(void){

    gethostname(hostname, sizeof(hostname));

    openlog( MYNAME, LOG_NDELAY|LOG_PID, LOG_DAEMON);
}


void
diag(int level, const char *file, const char *func, int line, int system, const char *fmt, ...){
    char buf[1024];
    pthread_t tid = pthread_self();
    struct LevelConf *lcf;
    int l = 0;
    int p;
    va_list ap;

    if( level < 8 && !flag_debugall ){
	// is debugging enabled for this message?

	// if config is not yet loaded, only debug via -d
	if( !config ) return ;

	// debugging enabled at this level
	if( level < (8 - config->debuglevel) ) return;

	// for this subsystem
	system &= 0xFF;
	if( level ){
            if( ! config->debug_is_set(system) ) return;
	}else{
            if( ! config->trace_is_set(system) ) return;
	}
    }

    if( level < 0 || level >= ELEMENTSIN(logconf) ){
        lcf = & logconf[ ELEMENTSIN(logconf) - 1 ];
    }else{
        lcf = & logconf[ level ];
    }

    va_start(ap, fmt);

    // add boilerplate info
    buf[0] = 0;

    if( lcf->with_info ){
	snprintf(buf, sizeof(buf), "tid:%x %s:%d in %s(): ", tid, file, line, func);
	l = strlen(buf);
    }

    // messages
    vsnprintf(buf + l, sizeof(buf) - l, fmt, ap);
    l = strlen(buf);
    va_end(ap);

    // terminate
    if( l >= sizeof(buf) - 2 ) l = sizeof(buf) - 2;
    buf[l++] = '\n';
    buf[l]   = 0;

    // stderr
    if( flag_foreground && lcf->to_stderr )
	write(2, buf, l);

    // syslog
    p = lcf->syslogprio;
    syslog(p, "%s", buf);

    // consoles
    if( lcf->to_console )
        Console::broadcast(level, buf, l);

    // email
    if( lcf->to_email && (!flag_foreground || lcf->with_trace) )
	send_error_email( buf, l, lcf->with_trace );

    if( lcf->is_fatal ){
	// fatal - abort
	exit(EXIT_ERROR_RESTART);
    }
}

static void
send_error_email( const char *msg, int len, int with_trace ){
    FILE *f, *p;
    char cmd[128];
    const char *mailto;

    if( config->error_mailto.empty() ) return;

    snprintf(cmd, sizeof(cmd), "env PATH=/usr/lib:/usr/libexec:/usr/sbin:/usr/bin sendmail -t -f '%s'",
	     config->error_mailfrom.c_str());

    f = popen(cmd, "w");
    if(!f) return;

    fprintf(f, "To: %s\nFrom: %s\nSubject: %s DNS daemon error\n\n",
	    config->error_mailto.c_str(), config->error_mailfrom.c_str(), MYNAME);
    fprintf(f, "an error was detected in %s\n\n", MYNAME);

    fprintf(f, "host: %s\npid:  %d\n\nerror:\n%s\n", hostname, getpid(), msg);

    // stack trace?
    if( with_trace ){
#ifdef __sun__
        // non-portability alert! pstack is solaris only
        snprintf(cmd, sizeof(cmd), "/usr/bin/pstack %d", getpid());
        p = popen(cmd, "r");
        if(p){
            char buf[32];

            fputs("\ntrace:\n", f);
            while(1){
                int i = fread(buf, 1, sizeof(buf), p);
                if( i <= 0 ) break;
                fwrite(buf, 1, i, f);
            }

            pclose(p);
        }
#endif
    }

    pclose(f);

}
