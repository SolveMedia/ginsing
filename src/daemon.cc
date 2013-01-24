/*
  Copyright (c) 2008 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2008-Dec-28 11:05 (EST)
  Function: daemonize

  $Id$

*/

#define CURRENT_SUBSYSTEM	'd'

#include "defs.h"
#include "diag.h"
#include "hrtime.h"
#include "runmode.h"

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>

static int i_am_parent = 1;
static int childpid = 0;
static char pidfile[64];

static void
finish(void){
    int status;
    int i;

    DEBUG("finishing");

    if( childpid > 1 ){
	DEBUG("killing child");
	kill(childpid, 15);
        while(1){
            i = wait(&status);
            if( i == -1 && errno == EINTR ) continue;
            break;
        }
    }
    if( i_am_parent ){
        unlink(pidfile);
    }
}

static void
sigexit(int sig){
    VERBOSE("caught signal %d - exiting", sig);

    if( !i_am_parent && sig == 15 ){
	// in child. exit
        runmode.shutdown();
	return;
    }

    exit(EXIT_NORMAL_EXIT);
    // NB - parent will kill child in finish()
}

static void
sigrestart(int sig){
    int status;

    if( i_am_parent ){
        if( childpid > 1 ){
            VERBOSE("caught sig hup - restarting child");
            kill(childpid, 1);
        }
    }else{
	// in child. exit gracefully
	VERBOSE("caught sig hup - restarting");
        runmode.winddown_and_restart();
	return;
    }
}

void
install_handler(int sig, void(*func)(int)){
    struct sigaction sigi;

    sigi.sa_handler = func;
    sigi.sa_flags = 0;
    sigemptyset( & sigi.sa_mask );
    sigaction(sig, &sigi, 0);
}

void
daemon_siginit(void){

    // sig handlers
    install_handler(SIGHUP,   sigrestart);
    install_handler(SIGINT,   sigexit);
    install_handler(SIGQUIT,  sigexit);
    install_handler(SIGTERM,  sigexit);
    install_handler(SIGPIPE,  SIG_IGN);

}


int
daemonize(int to, const char *name, int argc, char **argv){
    int status = 0;
    FILE *pf;
    int i;

    // background
    if( fork() ) exit(0);

    // close fd
    close(0);  open("/dev/null", O_RDWR);
    close(1);  open("/dev/null", O_RDWR);
#ifndef DEBUGING
    close(2);  open("/dev/null", O_RDWR);
#endif

    setsid();

    daemon_siginit();

    // pidfile
    snprintf(pidfile, sizeof(pidfile), "/var/run/%s.pid", name);
    pf = fopen(pidfile, "w");
    if( !pf ){
	FATAL("cannot open pid file");
    }
    fprintf(pf, "%d\n", getpid());
    fprintf(pf, "#");

    for(i=1;i<argc;i++){
        fprintf(pf, " %s", argv[i]);
    }
    fprintf(pf, "\n");

    fclose(pf);

    atexit(finish);

    // watcher proc
    while(1){
	DEBUG("forking");
	childpid = fork();
	if( childpid == -1 ){
	    FATAL("cannot fork");
	}
	if( childpid ){
	    // parent
            while(1){
                i = wait(&status);
                if( i == -1 && errno == EINTR ) continue;
                break;
            }
	    childpid = 0;
	    DEBUG("child exited with %d", status);
	    if( !status ){
		VERBOSE("exiting");
		exit(EXIT_NORMAL_EXIT);
	    }
            // otherwise, pause + restart
	    sleep(to);
	}else{
	    // child
            i_am_parent = 0;
	    return status;
	}
    }
}

