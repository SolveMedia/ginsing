/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-04 10:49 (EST)
  Function: main
*/

#include "defs.h"
#include "diag.h"
#include "daemon.h"
#include "config.h"
#include "hrtime.h"
#include "thread.h"
#include "runmode.h"
#include "zdb.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>


int flag_foreground   = 0;
int flag_debugall     = 0;
int force_reload      = 0;
char *filename_config = 0;
RunMode runmode;

static void* runmode_manage(void*);
static void *reload_config(void*);
void network_init(void);
void network_manage(void);
void dns_init(void);
void console_init(void);
void mmdb_init(void);
void zdb_init(void);
void mon_init(void);

void
usage(void){
    fprintf(stderr, MYNAME " [options]\n"
	    "  -f    foreground\n"
	    "  -d    enable debugging\n"
            "  -C    check config + exit\n"
	    "  -c config file\n");
    exit(0);
}

int
main(int argc, char **argv){
     extern char *optarg;
     extern int optind;
     int prev_status = 0;
     int save_argc = argc;
     char **save_argv = argv;
     int checkonly = 0;
     int c;

     srandom( time(0) );

     // parse command line
     while( (c = getopt(argc, argv, "c:Cdfh")) != -1 ){
	 switch(c){
	 case 'f':
	     flag_foreground = 1;
	     break;
	 case 'd':
	     flag_debugall = 1;
             debug_enabled = 1;
	     break;
	 case 'c':
	     filename_config = optarg;
	     break;
	 case 'h':
	     usage();
	     break;
         case 'C':
             checkonly = 1;
             flag_foreground = 1;
             break;
	 }
     }
     argc -= optind;
     argv += optind;

     if( !filename_config ){
	 fprintf(stderr, "no config specified!\ntry -c config\n");
         exit(-1);
     }

     //	init logging
     diag_init();

     // daemonize
     if( flag_foreground){
	 daemon_siginit();
     }else{
	 prev_status = daemonize(10, MYNAME "d", save_argc, save_argv);
     }

     VERBOSE( "starting." );

     // read config files + databases
     if( read_config(filename_config) ){
	 FATAL("cannot read config file");
     }

     mmdb_init();
     zdb_init();

     if( checkonly ) exit(0);

     if( prev_status && prev_status != (EXIT_NORMAL_RESTART<<8) ){
         // previous dancr restarted due to an error - send an email
         PROBLEM("previous %sd restarted due to an error (%d)", MYNAME, prev_status);
     }

     start_thread( runmode_manage, 0 );
     start_thread( reload_config, (void*)filename_config );

     // init subsystems
     mon_init();
     console_init();
     dns_init();
     network_init();


     VERBOSE("running.");

     // manage threads
     // this does not return until we shutdown
     network_manage();

     VERBOSE("exiting");
     exit(runmode.final_exit_value());

}

static void *
reload_config(void *file){
    struct stat sb;
    time_t lastmod = lr_now();
    int    lastino = 0;

    while(1){
        sleep(15);

	// watch config file
	int i = stat((char*)file, &sb);
	if( i == -1 ){
	    VERBOSE("cannot stat config file '%s': %s", file, strerror(errno));
	    continue;
	}

        if( !lastino ) lastino = sb.st_ino;

        if( sb.st_mtime > lastmod || force_reload || sb.st_ino != lastino ){
            lastmod = sb.st_mtime;
            force_reload = 0;
            VERBOSE("config changed, reloading");
            read_config( (char*)file );
            load_zdb();
        }
    }
}


// normal exit:
//   network_manage finishes + returns to main
//   main exits
///
// normal winddown:
//   puds janitor causes runmode transition windown=>exiting

// runmode_manage handles shutting down in the cases
// where the normal processes are hung

// !!! - this thread must not do anything which could ever hang
//   - no locks, no mallocs, no i/o, no std::string, std::...
//   - no debug, no verbose, ...


#define TIME_LIMIT	60
#define WIND_LIMIT	300

static void*
runmode_manage(void*){
    time_t texit=0, twind=0, terrd=0;
    time_t nowt;

    while(1){
        nowt = lr_now();

        switch(runmode.mode()){
        case RUN_MODE_EXITING:
	    if( !texit ) texit = nowt + TIME_LIMIT;
	    if( texit < nowt ) _exit(runmode.final_exit_value());
            break;

        case RUN_MODE_WINDDOWN:
            if( !twind ) twind = nowt + WIND_LIMIT;
            if( twind < nowt ) _exit(runmode.final_exit_value());
            break;

        case RUN_MODE_ERRORED:
            if( !terrd ) terrd = nowt + TIME_LIMIT;
            if( terrd < nowt ) _exit(EXIT_ERROR_RESTART);
            break;

        default:
            twind = texit = terrd = 0;		// shutdown canceled, reset
        }

        sleep(5);

    }
    return 0;
}

