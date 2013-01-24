/*
  Copyright (c) 2009 by Jeff Weisberg
  Author: Jeff Weisberg <jaw @ tcp4me.com>
  Created: 2009-Jan-23 10:02 (EST)
  Function: console commands

  $Id$

*/
#define CURRENT_SUBSYSTEM	'C'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "hrtime.h"
#include "thread.h"
#include "config.h"
#include "console.h"
#include "network.h"
#include "lock.h"
#include "runmode.h"
#include "maint.h"
#include "zdb.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>


static int cmd_exit(Console *, const char *, int);
static int cmd_echo(Console *, const char *, int);
static int cmd_none(Console *, const char *, int);
static int cmd_debug(Console *, const char *, int);
static int cmd_shut(Console *, const char *, int);
static int cmd_load(Console *, const char *, int);
static int cmd_reqs(Console *, const char *, int);
static int cmd_rps(Console *, const char *, int);
static int cmd_status(Console *, const char *, int);
static int cmd_help(Console *, const char *, int);
static int cmd_reload(Console *, const char *, int);
static int cmd_maint(Console *, const char *, int);
static int cmd_probe(Console *, const char *, int);
static int cmd_stats(Console *, const char *, int);


static struct {
    const char *name;
    int visible;
    int (*func)(Console *, const char *, int);
} commands[] = {
    { "",               0, cmd_none },
    { "exit",		1, cmd_exit },
    { "echo", 		1, cmd_echo },
    { "mon", 		1, cmd_debug },
    { "shutdown",       1, cmd_shut },
    { "status",         1, cmd_status },
    { "load",           1, cmd_load },	// load
    { "reqs",           1, cmd_reqs },	// number of requests handled
    { "rps", 		1, cmd_rps  },	// requests per second
    { "reload",         1, cmd_reload },
    { "maint",		1, cmd_maint },
    { "probestatus",    0, cmd_probe },	// used by monitor process to update statuses
    { "stats",		1, cmd_stats },
    { "help",           1, cmd_help },
    { "?",              0, cmd_help },
};

extern DNS_Stats net_stats;
static struct {
    const char *name;
    const char  fmt;
    const void *data;
} statscmd[] = {
#include "stats_cmd.h"
};


static int
cmd_none(Console *con, const char *cmd, int len){
    return 1;
}

static int
cmd_exit(Console *con, const char *cmd, int len){
    return 0;
}

static int
cmd_echo(Console *con, const char *cmd, int len){

    con->output(cmd);
    return 1;
}

static int
cmd_reload(Console *con, const char *cmd, int len){
    extern int force_reload;
    force_reload = 1;
    con->output("OK\n");
    return 1;
}


static int
cmd_load(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%.4f\n", net_utiliz);
    con->output(buf);
    return 1;
}


static int
cmd_reqs(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%lld\n", net_requests);
    con->output(buf);
    return 1;
}

static int
cmd_rps(Console *con, const char *cmd, int len){
    char buf[32];

    snprintf(buf, sizeof(buf), "%.4f\n", net_req_per_sec);
    con->output(buf);
    return 1;
}

static void
output_stat(Console *con, int idx, bool align){
    char buf[32];
    const char *v;

    switch(statscmd[idx].fmt){
    case 's':
        v = (char*) statscmd[idx].data;
        break;
    case 'f':
        snprintf(buf, sizeof(buf), "%.6f", * (float*)statscmd[idx].data);
        v = buf;
        break;
    case 'd':
        snprintf(buf, sizeof(buf), "%d", * (int*)statscmd[idx].data);
        v = buf;
        break;
    case 'q':
        snprintf(buf, sizeof(buf), "%lld", * (int64_t*)statscmd[idx].data);
        v = buf;
        break;
    default:
        BUG("corrupt stats table");
        return;
    }

    con->output(statscmd[idx].name);

    if( align ){
        int l = strlen(statscmd[idx].name);
        for(int i=l; i<24; i++) con->output(" ");
    }

    con->output(" ");
    con->output(v);
    con->output("\n");
}

static int
cmd_stats(Console *con, const char *cmd, int len){

    while( len && isspace(*cmd) ){ cmd++; len--; }	// eat white
    bool all = ! strcmp(cmd, "all");
    bool ok  = 0;

    for(int i=0; i<ELEMENTSIN(statscmd); i++){
        if( all || !strcmp(cmd, statscmd[i].name) ){
            output_stat(con, i, all);
            ok = 1;
        }
    }

    if( !ok )
        con->output("no such stat\n");

    return 1;
}

static int
cmd_probe(Console *con, const char *cmd, int len){
    // probestatus index uid status
    int idx  = 0;
    int uid  = 0;
    int stat = 0;

    ZDB *z = zdb;

    sscanf(cmd, "%d %d %d", &idx, &uid, &stat);
    if( idx < 0 || idx >= z->monitored.size() ) return 1;

    RR* rr = z->monitored[idx];
    if( !rr->probe || rr->probe->uid != uid ) return 1;

    DEBUG("probe status %d %d => %d", idx, uid, stat);

    if( !stat ){
        VERBOSE("%s is DOWN", rr->name.c_str());
    }

    rr->probe_ok = stat;

    return 1;
}

static int
cmd_maint(Console *con, const char *cmd, int len){
    bool stat;
    const char *dc;

    // maint online|offline datacenter

    while( len && isspace(*cmd) ){ cmd++; len--; }	// eat white
    dc = cmd;
    while( *dc && !isspace(*dc) ) dc ++;		// find datacenter
    if( *dc ) dc ++;

    if( !strncmp(cmd, "online", 6) ){
        stat = 0;
    }
    else if( !strncmp(cmd, "offline", 7) ){
        stat = 1;
    }
    else{
        con->output("? maint online|offline datacenter\n");
        return 1;
    }

    if( !maint_set(dc, stat) ){
        con->output("invalid datacenter\n");
        return 1;
    }

    VERBOSE("datacenter %s %s", dc, stat? "OFFLINE" : "ONLINE");
    return 1;
}

// debug <number>
// debug off
static int
cmd_debug(Console *con, const char *cmd, int len){
    char *ep;
    int n;

    // eat white
    while( len && isspace(*cmd) ){ cmd++; len--; }

    n = strtol(cmd, &ep, 10);

    if( ep != cmd ){
	con->set_loglevel(n);
    }else if( !strncmp(cmd, "on", 2) ){
	con->set_loglevel(8);
    }else if(  !strncmp(cmd, "off", 3) ){
	con->set_loglevel(-1);
    }else{
	con->output("? mon on|off|<number>\n");
    }

    return 1;
}

static int
cmd_shut(Console *con, const char *cmd, int len){
    time_t now = lr_now();

    // eat white
    while( len && isspace(*cmd) ){ cmd++; len--; }

    if( !strncmp(cmd, "immediate", 9) ){
	VERBOSE("immediate shutdown initiated");
	con->output("shutting down\n");
        runmode.shutdown();

    }else if( !strncmp(cmd, "graceful", 8) ){
	VERBOSE("graceful shutdown initiated");
	con->output("winding down\n");
        runmode.winddown();

    }else if( !strncmp(cmd, "restart", 7) ){
	VERBOSE("shutdown + restart initiated");
	con->output("winding down\n");
        runmode.winddown_and_restart();

    }else if( !strncmp(cmd, "crash", 5) ){
        // in case the system is hung hard (but we can somehow get to the console)
	VERBOSE("crash hard + restart initiated");
	con->output("crashing\n");
        _exit(EXIT_ERROR_RESTART);

    }else if( !strncmp(cmd, "cancel", 6) ){
        VERBOSE("canceling shutdown");
        con->output("canceling shutdown\n");
        // NB: there is a race condition here
        runmode.cancel();

    }else{
	con->output("? shutdown graceful|immediate|restart|crash|cancel\n");
    }

    return 1;
}

static int
cmd_status(Console *con, const char *cmd, int len){

    switch( runmode.mode() ){
    case RUN_LOLA_RUN:
        con->output("running OK\n");
        break;
    case RUN_MODE_WINDDOWN:
        if( runmode.final_exit_value() ){
            con->output("graceful restart underway\n");
        }else{
            con->output("graceful shutdown underway\n");
        }
        break;
    case RUN_MODE_EXITING:
        if( runmode.final_exit_value() ){
            con->output("restart underway\n");
        }else{
            con->output("shutdown underway\n");
        }
        break;
    case RUN_MODE_ERRORED:
        con->output("error recovery underway\n");
        break;
    default:
        con->output("confused\n");
        break;
    }

    return 1;
}

static int
cmd_help(Console *con, const char *cmd, int len){

    con->output("commands:");
    for(int i=0; i<ELEMENTSIN(commands); i++){
        if( !commands[i].visible ) continue;
        con->output(" ");
        con->output(commands[i].name);
    }
    con->output("\n");
    return 1;
}


//################################################################
static int
match(const char *c, const char *s, int l){
    int p = 0;

    while( 1 ){
	if( !*c ){
	    if( p == l )      return p;	// full match
	    if( isspace(*s) ) return p; // match plus more
	    return -1;			// no match
	}
	if( p == l )   return -1;	// end of input
	if( *c != *s ) return -1;	// no match

	c++;
	s++;
	p++;
    }
    return -1;
}

int
run_command(Console *con, const char *cmd, int len){

    for(int i=0; i<ELEMENTSIN(commands); i++){
	int o = match(commands[i].name, cmd, len);
	if( o != -1 ){
	    return commands[i].func(con, cmd + o, len - o);
	}
    }

    con->output("command not found\n");
    return 1;
}


