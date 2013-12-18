/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-21 13:00 (EST)
  Function: service monitoring - bottom half
*/

#define CURRENT_SUBSYSTEM	'M'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "lock.h"
#include "hrtime.h"
#include "daemon.h"
#include "runmode.h"
#include "thread.h"
#include "zdb.h"
#include "mon.h"

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>


#define MAXFAILS	2
#define MAXRUNNING	20
#define TIMEOUT		30

static int running = 0;

inline bool
Monitor::too_long(time_t now) const{
    return pid && t_started + TIMEOUT < now;
}

void
Monitor::maybe_start(time_t now){
    if( t_next <= now ) start(now);
}

void
Monitor::start(time_t now){

    if( running >= MAXRUNNING ){
        t_next += 2;
        return;
    }

    // fork + exec
    int p = fork();
    if( p == -1 ){
        PROBLEM("cannot fork: %s", strerror(errno));
        sleep(5);
        return;
    }
    if( p ){
        // parent
        t_last = t_started = now;
        pid    = p;
        DEBUG("started mon %s pid %d", prog.c_str(), p);
        return;
    }

    // child
    // build argv + exec
    string cmd = config->mon_path + "/" + prog;
    const char **eargv = (const char**)malloc( (argv.size() + 3) * sizeof(char*) );

    eargv[0] = cmd.c_str();
    eargv[1] = address.c_str();

    for(int i=0; i<argv.size(); i++){
        eargv[i+2] = argv[i].c_str();
    }

    eargv[ argv.size() + 2 ] = 0;

    DEBUG("running %s", cmd.c_str(), argv.size());
    execv( cmd.c_str(), (char *const*)eargv );

    PROBLEM("execv %s failed: %s", cmd.c_str(), strerror(errno));
    exit(-1);
}

void
Monitor::set_status(bool st, int idx){

    if( st ){
        if( ++fail_count <= MAXFAILS ) return;
        status = 0;

    }else{
        status = 1;
        fail_count = 0;
    }

    // tell parent process
    // NB: stdout is a pipe connected to the console
    DEBUG("send status %d %d %d", idx, uid, status);
    printf("probestatus %d %d %d\n", idx, uid, status);
    fflush(stdout);

    // (non-blockingly) empty the buffer of any recvd data
    char buf[16];
    fcntl(1, F_SETFL, O_NDELAY);
    read(1, buf, sizeof(buf));
    fcntl(1, F_SETFL, 0);

}

void
Monitor::wait(int idx, time_t now){
    int status = 1;

    int w = waitpid(pid, &status, WNOHANG);
    if( !w ) return;	// still running
    if( errno == EINTR ) return;

    DEBUG("pid %d finished %d", pid, status);
    pid = 0;
    running --;

    // update status
    set_status(status, idx);

    // reschedule
    t_next += freq;
    if( t_next <= now )
        t_next = now + random() % freq;

}

void
Monitor::abort(){
    DEBUG("killing pid %d", pid);
    kill( pid, (kills++ > 2) ? 9 : 15 );
}

void
mon_exit(int sig){
    exit(0);
}

// we start here:
void
mon_run(void){
    running = 0;

    install_handler(SIGPIPE,  SIG_DFL);
    install_handler(SIGHUP,   SIG_DFL);
    install_handler(SIGINT,   SIG_DFL);
    install_handler(SIGQUIT,  SIG_DFL);
    install_handler(SIGTERM,  mon_exit);

    DEBUG("starting");

    // close any open files
    for(int i=4; i<256; i++) close(i);

    while(1){
        time_t now = lr_now();
        int len    = zdb->monitored.size();
        int rx     = len ? random() % len : 0;

        for(int i=0; i<len; i++){
            int n = (i + rx) % len;
            RR *rr = zdb->monitored[n];
            if( !rr ) continue;
            Monitor *mon = rr->probe;
            if( !mon ) continue;

            if( mon->is_running() ){
                // finished?
                mon->wait(n, now);
                // running too long? kill
                if( mon->too_long(now) ) mon->abort();
            }else{
                // time to start?
                mon->maybe_start(now);
            }
        }

        sleep(1);
    }

    exit(0);
}

