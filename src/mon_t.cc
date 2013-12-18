/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-21 13:00 (EST)
  Function: service monitoring - top half
*/

#define CURRENT_SUBSYSTEM	'M'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "lock.h"
#include "hrtime.h"
#include "runmode.h"
#include "thread.h"
#include "mon.h"

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

static int restart_requested = 0;
static int monpid  = 0;

static void *mon_manage(void*);
extern void mon_run(void);
extern void *console_run(void*);

Monitor::Monitor(int f, string *ad, string *p, string *a){

    freq       = f;
    prog       = *p;
    address    = *ad;
    fail_count = 0;
    pid        = 0;
    uid        = random();
    status     = 1;
    t_last     = 0;
    t_started  = 0;
    t_next     = lr_now() + random() % freq;

    // split args
    // RSN - handle ""s, etc?
    int s = 0, e = 0;
    int l = a->length();
    while(s < l){
        e = a->find(' ', s);
        if( e == -1 ) e = l;
        argv.push_back( a->substr(s, e-s) );
        s = e + 1;
    }
}

void
mon_restart(void){
    restart_requested = 1;
}

void
mon_init(void){
    start_thread(mon_manage, 0);
}

static void
mon_problem(const char *m, int e){
    PROBLEM(m, strerror(e));
    restart_requested = 1;
    sleep(10);
}

static void*
mon_console(void *fd){
    console_run(fd);
    close( (int)(long)fd );
    DEBUG("thread finished");
}

static void
mon_start(void){
    int pfd[2];

    // connect pipe from mon process to console
    // mon process will send status updates to its stdout

    int pe = pipe(pfd);
    if( pe == -1 ){
        mon_problem("cannot create pipe: %s", errno);
        return;
    }

    int pid = fork();

    if( pid == -1 ){
        // uh oh!
        mon_problem("cannot fork: %s", errno);
        return;
    }
    if( pid == 0 ){
        // child
        // cnnect stdout to pipe
        int de = dup2(pfd[1], 1);
        if( de == -1 ){
            PROBLEM("cannot dup2: %s", strerror(errno));
            exit(-1);
        }
        close(pfd[0]);
        close(pfd[1]);
        mon_run();
        exit(0);
    }

    // parent
    monpid = pid;
    DEBUG("started mon proc pid %d", pid);

    // connect pipe to console
    close(pfd[1]);
    start_thread( mon_console, (void*)(long)pfd[0] );
}

// run as thread in main process. start/restart child process to do monitoring
static void *
mon_manage(void* x){
    int kills;

    while(1){
        // kill if requested, restart if needed
        if( restart_requested ){
            if( monpid ){
                kill( monpid, (kills++ > 4) ? 9 : 15 );
            }else{
                restart_requested = 0;
                mon_start();
            }
        }

        // did it die?
        if( monpid ){
            int status;
            int w = waitpid(monpid, &status, WNOHANG);
            if( w == monpid ){
                DEBUG("mon proc exited %d", status);
                if( status )
                    VERBOSE("mon process exited abnormally");
                monpid = 0;
                kills  = 0;
                restart_requested = 1;
            }
        }

        sleep(1);
    }
}
