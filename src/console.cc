/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-10 16:09 (EST)
  Function: interactive console
*/


// one listening thread + one thread per connection

#define CURRENT_SUBSYSTEM	'C'

#include "defs.h"
#include "diag.h"
#include "thread.h"
#include "config.h"
#include "console.h"
#include "network.h"
#include "lock.h"
#include "runmode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT	6789
#define MAXCON	10

extern int run_command(Console *, const char *, int);

static Mutex nconsmtx;
static int   ncons = 0;

static RWLock  queue_lock;
list<Console*> console_queue;

void *
console_run(void *xfd){
    int fd = (long)xfd;
    Console cons(fd);
    char buf[1024];
    int i, b;

    while(1){
	cons.output( & cons.prompt );

        b = 0;
        while(1){
            i = read(fd, buf+b, 1);
            if( i < 1 ) break;
            buf[++b] = 0;
            if( b >= sizeof(buf) - 1) break;

            if( buf[b-1] == '\n' || buf[b-1] == ';' ){
                buf[--b] = 0;
                if( buf[b-1] == '\r' ) buf[--b] = 0;
                break;
            }
        }
	if( i < 1 ) break;

        DEBUG("read %s", buf);
	i = run_command(&cons, buf, b);
	if( i < 1 ) break;

	if( runmode.mode() == RUN_MODE_EXITING ){
	    cons.output("system shutting down\n");
	    break;
	}

    }

    DEBUG("console finished");
    nconsmtx.lock();
    ncons --;
    nconsmtx.unlock();

    return 0;
}


void *
console_accept(void *xfd){
    struct sockaddr_in sa;
    socklen_t l = sizeof(sa);
    int fd = (long)xfd;
    int nfd;

    DEBUG("waiting for console connections");

    while(1){
	if( runmode.mode() == RUN_MODE_EXITING ) break;

	nfd = accept(fd, (sockaddr *)&sa, &l);
	if(nfd == -1){
	    DEBUG("accept failed");
	    continue;
	}

	if( !config->check_acl( (sockaddr*)&sa ) ){
	    // QQQ - is inet_ntoa thread safe? on solaris - yes (buffer is per thread)
	    VERBOSE("console connection refused from %s", inet_ntoa(sa.sin_addr) );
	    close(nfd);
	    continue;
	}

	if( ncons >= MAXCON ){
	    VERBOSE("maximum number of consoles exceeded. dropping connection");
	    close(nfd);
	    continue;
	}

	nconsmtx.lock();
	ncons ++;
	nconsmtx.unlock();

	DEBUG("console connection from %s", inet_ntoa(sa.sin_addr) );

	start_thread( console_run, (void*)(long)nfd );
    }

    close(fd);
    return 0;
}


void
console_init(void){
    struct sockaddr_in sa;
    int fd, i, p;

    p = config->port_console;
    if(!p) return;

    // open socket
    fd = socket(PF_INET, SOCK_STREAM, 6);
    if( fd == -1 ){
	FATAL("cannot create socket: %s", strerror(errno));
    }

    sa.sin_family = AF_INET;
    sa.sin_port   = htons(p);
    sa.sin_addr.s_addr = INADDR_ANY;

    i = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    i = bind(fd, (sockaddr*)&sa, sizeof(sa));
    if( i == -1 ){
	FATAL("cannot bind to port: %s", strerror(errno));
    }
    listen(fd, 10);

    VERBOSE("starting console on tcp/%d", p);

    // start thread

    start_thread( console_accept, (void*)(long)fd );

}

//################################################################

Console::Console(int fd) : prompt("? ") {

    _fd = fd;
    _loglevel = 0;
    _onlogq = 0;
    y2_b = 0;
}


Console::~Console(){

    close(_fd);

    // remove from diag console queue
    queue_lock.w_lock();
    console_queue.remove(this);
    queue_lock.w_unlock();
}

void
Console::set_loglevel(int l){

    _loglevel = l;

    queue_lock.w_lock();

    if( l == -1 ){
	// disable
	console_queue.remove(this);
	_onlogq = 0;
    }else if( !_onlogq ){
	// add to queue
        console_queue.push_back(this);
	_onlogq = 1;
    }

    queue_lock.w_unlock();

}

void
Console::output(const string *s){

    _mutex.lock();
    write( _fd, s->c_str(), s->length() );
    _mutex.unlock();
}

void
Console::output(const char *s){

    _mutex.lock();
    write( _fd, s, strlen(s) );
    _mutex.unlock();
}

void
Console::broadcast(int level, const char *msg, int len){

    queue_lock.r_lock();

    list<Console*>::iterator final=console_queue.end(), it;

    for(it=console_queue.begin(); it != final; it++){
	Console *c = *it;

	if( level < c->_loglevel ) continue;
	if( c->_mutex.trylock() )  continue;

	fcntl( c->_fd, F_SETFL, O_NDELAY);
	write( c->_fd, msg, len);
	fcntl( c->_fd, F_SETFL, 0);

	c->_mutex.unlock();
    }

    queue_lock.r_unlock();
}

