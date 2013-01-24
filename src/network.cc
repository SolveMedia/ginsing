/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:20 (EST)
  Function: network requests
*/

#define CURRENT_SUBSYSTEM	'N'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "thread.h"
#include "config.h"
#include "lock.h"
#include "hrtime.h"
#include "network.h"
#include "runmode.h"
#include "dns.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#define TIMEOUT		10
#define ALPHA		0.75


extern void install_handler(int, void(*)(int));


class Thread_Stats {
public:
    int       busy;
    float     util;
    time_t    timeout;
    time_t    time_update;
    pthread_t pid;
    jmp_buf   jmp_abort;
    DNS_Stats stats;

    Thread_Stats(){ busy = 0; util = 0; timeout = 0; pid = 0; time_update = 0; }

};
static Thread_Stats *thread_stat;


// statistics
float net_utiliz       = 0;
float net_req_per_sec  = 0;
int64_t net_requests   = 0;
DNS_Stats net_stats;

// sigalarm
long net_timeouts   = 0;
time_t last_timeout = 0;

int net_udp, net_tcp;
Mutex nthreadmtx;
int nthreadcf;			// number configured
int nthread       = 0;		// number running

// where am I? for heartbeats
int myport = 0;
char hostname[256];

void
hexdump(const uchar *d, int l){

    for(int i=0; i<l; i++){
        fprintf(stderr, " %02X", d[i]);
        if( (i%16)==15 && i!=l-1 ) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}


static void
sigalarm(int sig){
    int i;
    pthread_t self = pthread_self();
    time_t nowt = lr_now();

    DEBUG("timeout");

    // if a lot of things are timing out, something might be hung
    // put the system into a fast windown+restart
    // if we are not hung, puds::janitor will cancel the shutdown

    if( last_timeout + 60 < nowt ){
        // been a while, reset
        net_timeouts = 0;
    }

    net_timeouts ++;
    last_timeout = nowt;

    if( net_timeouts > 10 ){
        runmode.errored();
    }

    for(i=0; i<nthread; i++){
        if( thread_stat[i].pid == self ){
            DEBUG("aborting request");
            longjmp( thread_stat[i].jmp_abort, 1 );
        }
    }
}

static void
sigsegv(int sig){
    int i;
    pthread_t self = pthread_self();

    DEBUG("caught segv");

    // attempt to abort the thread and continue

    // if there is a lock being held, we are f***ed.
    // if we winddown+restart, we could end up with no running dancrs (aka f***ed)

    // put the system into a fast windown+restart
    // if we are not hung, puds::janitor will cancel the shutdown

    runmode.errored();

    for(i=0; i<nthread; i++){
        if( thread_stat[i].pid == self ){
            BUG("segv in thread %d", thread_stat[i].pid);
            thread_stat[i].timeout = 0;
            longjmp( thread_stat[i].jmp_abort, 1 );
        }
    }
}

static void
sigother(int sig){
    int i;
    pthread_t self = pthread_self();

    DEBUG("caught sig %d", sig);

    for(i=0; i<nthread; i++){
        if( thread_stat[i].pid == self ){
            BUG("signal %d in thread %d", sig, thread_stat[i].pid);
            thread_stat[i].timeout = 0;
            longjmp( thread_stat[i].jmp_abort, 1 );
        }
    }
}

static void
calc_util(int thno, hrtime_t t0, hrtime_t t1, hrtime_t t2){
    Thread_Stats *mystat = thread_stat + thno;
    time_t lnow = lr_now();

    // t0..t1  => time spent waiting
    // t1..t2  => time spent working

    float b = (t2 == t0) ? 0 : ((float)(t2 - t1)) / ((float)(t2 - t0));

    if( mystat->time_update > lnow - 2 ){
        mystat->util = (mystat->util + b) / 2;
    }else{
        mystat->util = b;
    }

    mystat->time_update = lnow;

    DEBUG("request took %lld ns", (t2 - t1));
}

static int
network_read_tcp(NTD * ntd){
    int i;
    int fd;
    uint16_t lenbuf;

    fd = ntd->fd;

    DEBUG("reading network request");

    // read  some
    i = read(fd, &lenbuf, 2);
    DEBUG("read %d", i);
    if( i < 2 ) return 0;

    ntd->querb.datalen = 0;
    int plen = ntohs( lenbuf );

    while( ntd->querb.datalen < plen ){
        int dlen  = ntd->querb.datalen;
        int avail = ntd->querb.bufsize - dlen;
        if( !avail ) return 0;
        i = read(fd, ntd->querb.buf + dlen, avail);
        DEBUG("read %d", i);

        if( i > 0 ) ntd->querb.datalen += i;
        if( !i ) return 0; // eof
        if( i < 1 ){
            if( errno == EINTR ) continue;
            DEBUG("read error");
            return 0;
        }
    }
    DEBUG("ok");
    return 1;
}


static void *
network_accept_tcp(void *xthno){
    NTD *ntd;
    struct sockaddr_in sa;
    socklen_t l = sizeof(sa);
    int fd = net_tcp;
    int thno = (long)xthno, nfd, i;
    hrtime_t t0=0, t1=0, t2=hr_now();
    Thread_Stats *mystat = thread_stat + thno;
    iovec iov[2];

    // pre allocate things
    ntd = new NTD (TCPBUFSIZ);
    ntd->thno  = thno;
    ntd->stats = & mystat->stats;

    nthreadmtx.lock();
    nthread++;
    nthreadmtx.unlock();
    mystat->pid = pthread_self();

    while(1){
	if( runmode.mode() == RUN_MODE_EXITING ) break;
        mystat->busy    = 0;
        mystat->timeout = 0;
        t0 = t2;
	nfd = accept(fd, (sockaddr *)&sa, &l);
        t1 = hr_now();
        ntd->fd = nfd;

	if(nfd == -1){
	    DEBUG("accept failed");
	    continue;
	}

        mystat->busy = 1;
        mystat->stats.n_tcp ++;
        ntd->reset(MAXTCP);
        ntd->sa    = (sockaddr*)&sa;
        ntd->salen = l;

	DEBUG("new connection %d", thno);

        if( ! setjmp( thread_stat[thno].jmp_abort ) ){

            // disable nagle
            i = 1;
            setsockopt(nfd, IPPROTO_TCP, TCP_NODELAY, &i, sizeof(i));
            mystat->timeout = lr_now() + TIMEOUT;

            if( network_read_tcp(ntd) ){
                mystat->timeout = lr_now() + TIMEOUT;
                int rl = dns_process(ntd);
                DEBUG("response %d", rl);
                if( config->trace_is_set('N') )
                    hexdump(ntd->respb.buf, rl);
                unsigned short tl = htons( rl );
                if( rl ){
                    iov[0].iov_base = &tl;
                    iov[0].iov_len  = 2;
                    iov[1].iov_base = ntd->respb.buf;
                    iov[1].iov_len  = rl;
                    writev(nfd, iov, 2);
                }
            }
        }else{
            // got a timeout | segv
            VERBOSE("aborted processing request");
        }

        mystat->timeout = 0;
	close(nfd);
        t2 = hr_now();
        calc_util(thno, t0, t1, t2);
    }

    // unallocate things
    delete ntd;

    nthreadmtx.lock();
    nthread--;
    nthreadmtx.unlock();

    return 0;
}


static void *
network_accept_udp(void *xthno){
    NTD *ntd;
    struct sockaddr_in sa;
    socklen_t l = sizeof(sa);
    int fd = net_udp;
    int thno = (long)xthno, nfd, i;
    hrtime_t t0=0, t1=0, t2=hr_now();
    Thread_Stats *mystat = thread_stat + thno;

    // pre allocate things
    ntd = new NTD (UDPBUFSIZ);
    ntd->thno  = thno;
    ntd->fd    = net_udp;
    ntd->stats = & mystat->stats;

    nthreadmtx.lock();
    nthread++;
    nthreadmtx.unlock();
    mystat->pid = pthread_self();

    while(1){
	if( runmode.mode() == RUN_MODE_EXITING ) break;
        mystat->busy    = 0;
        mystat->timeout = 0;
        t0 = t2;
        i = recvfrom(fd, ntd->querb.buf, UDPBUFSIZ, 0, (sockaddr*)&sa, &l);
        t1 = hr_now();

        if( !i ) continue;
        if( i < 0 ){
	    DEBUG("recv failed");
	    continue;
	}

        ntd->reset(MAXUDP);
        ntd->querb.datalen = i;
        ntd->sa    = (sockaddr*)&sa;
        ntd->salen = l;
        mystat->busy = 1;

	DEBUG("new udp request %d, l=%d", thno, i);

        if( config->trace_is_set('N') )
            hexdump(ntd->querb.buf, ntd->querb.datalen);

        if( ! setjmp( mystat->jmp_abort ) ){

            mystat->timeout = lr_now() + TIMEOUT;

            int rl = dns_process(ntd);
            if( rl ) sendto(fd, ntd->respb.buf, rl, 0, (sockaddr*)&sa, sizeof(sa));

            if( config->trace_is_set('N') )
                hexdump(ntd->respb.buf, rl);
        }else{
            // got a timeout | segv
            VERBOSE("aborted processing request");
        }

        mystat->timeout = 0;
        t2 = hr_now();
        calc_util(thno, t0, t1, t2);
    }

    // unallocate things
    delete ntd;

    nthreadmtx.lock();
    nthread--;
    nthreadmtx.unlock();

    return 0;
}


void
network_init(void){
    struct sockaddr_in sa;
    struct hostent *he;
    int udp, tcp, i;

    nthreadcf = config->udp_threads + config->tcp_threads;
    if(!nthreadcf){
	FATAL("no threads configured");
    }
    thread_stat = new Thread_Stats[ nthreadcf ];

    myport = config->port_dns;
    if( !myport ){
	FATAL("cannot determine port to use");
    }
    gethostname( hostname, sizeof(hostname));


    // open sockets
    tcp = socket(PF_INET, SOCK_STREAM, 6);
    if( tcp == -1 ){
	FATAL("cannot create socket");
    }

    sa.sin_family = AF_INET;
    sa.sin_port   = htons(myport);
    sa.sin_addr.s_addr = INADDR_ANY;

    i = 1;
    setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    i = bind(tcp, (sockaddr*)&sa, sizeof(sa));
    if( i == -1 ){
	FATAL("cannot bind to port");
    }
    listen(tcp, 10);

    udp = socket(PF_INET, SOCK_DGRAM, 17);
    if( udp == -1 ){
	FATAL("cannot create socket");
    }
    i = bind(udp, (sockaddr*)&sa, sizeof(sa));
    if( i == -1 ){
	FATAL("cannot bind to port");
    }

    net_tcp = tcp;
    net_udp = udp;

    // install handlers
    install_handler( SIGALRM, sigalarm );
    install_handler( SIGSEGV, sigsegv  );
    install_handler( SIGABRT, sigother );

    VERBOSE("starting network on port %d (%s)", myport, config->environment.c_str());

    // start threads
    DEBUG("starting %d network threads", nthreadcf);

    for(i=0; i<config->udp_threads; i++){
	start_thread( network_accept_udp, (void*)(long)i );
    }
    for( ;i<nthreadcf; i++){
	start_thread( network_accept_tcp, (void*)(long)i );
    }
}

static void
check_threads(time_t nowt){

    // kill any hung threads
    for(int i=0; i<nthread; i++){
        if( thread_stat[i].timeout && thread_stat[i].timeout < nowt ){
            BUG("notifying unresponsive thread %d", thread_stat[i].pid);
            thread_stat[i].timeout = 0;
            pthread_kill(thread_stat[i].pid, SIGALRM);
        }
    }
}

static void
thread_stats(time_t nowt,  int *nbusy, int *nactive, float *tutil){

    DEBUG("nt %d, now %lld", nthread, nowt);

    for(int i=0; i<nthread; i++){
        *nbusy += thread_stat[i].busy;

        if( thread_stat[i].time_update > nowt - 5 ){
            *tutil += thread_stat[i].util;
            (*nactive) ++;
        }
    }

    // sum stats
    for(int j=0; j<sizeof(DNS_Stats)/sizeof(int64_t); j++){
        int64_t tot = 0;
        for(int i=0; i<nthread; i++){
            int64_t s = ((int64_t*)(&thread_stat[i].stats))[ j ];
            tot += s;
        }
        int64_t *t = (int64_t*)&net_stats + j;
        ATOMIC_SETPTR(*t, tot);
    }
}

static int
runmode_check(){
    static int64_t net_requests_init = 0;
    static int err_iter = 0;

    switch( runmode.mode() ){
    case RUN_MODE_ERRORED:
        // skip the first few iterations, while things finish or hang
        if( err_iter++ == 2*TIMEOUT )
            net_requests_init = net_requests;

        // have we completed requests?
        if( net_requests - net_requests_init > 10 )
            runmode.cancel();
        break;

    case RUN_MODE_WINDDOWN:
        // just exit...
    case RUN_MODE_EXITING:
        if( net_tcp ){
            // tell network_accept threads to finish
            DEBUG("shutting network down");
            shutdown(net_tcp, SHUT_RDWR);
            close(net_tcp);
            close(net_udp);
            net_tcp = net_udp = 0;
        }
        // wait until they all finish
        if( ! nthread ){
            DEBUG("network finished");
            return 0;
        }
        // fall through
    default:
        err_iter = 0;
        break;
    }

    return 1;
}


void
network_manage(void){
    time_t prevt = lr_now(), nowt;
    int64_t preq = 0;

    while(1){
        nowt = lr_now();

	// measure idle/busy/stats/...
	if( nthread ){
            int nt = nthread;
	    float tutil = 0;
            int nactive = 0;
            int nbusy   = 0;

            thread_stats( nowt, &nbusy, &nactive, &tutil );

            int64_t nreq = net_stats.n_requests;
	    net_requests = nreq;

	    // track decaying average of utilization
            float u = nactive ? tutil / nactive : 0;
	    net_utiliz = ALPHA * net_utiliz + (1.0 - ALPHA) * u;
            DEBUG("nb %d, nact %d, tutlz %f, u %f, nut %f", nbusy, nactive, tutil, u, net_utiliz);

            if( nowt != prevt ){
                float rps = (nreq - preq) / (float)(nowt - prevt);
                net_req_per_sec = ALPHA * net_req_per_sec + (1.0 - ALPHA) * rps;
                DEBUG("rps: nreq %lld, preq %lld, rps %.4f => %.4f", nreq, preq, rps, net_req_per_sec);
                prevt = nowt;
                preq  = nreq;
            }

	    DEBUG("network thread status: %d threads, %d busy, %.2f load, %f rps",
                  nt, nbusy, net_utiliz, net_req_per_sec);

            check_threads(nowt);

	}else{
            net_utiliz      = 0;
            net_req_per_sec = 0;
	}

        if( ! runmode_check() ) return;

	sleep(1);
    }
}

//################################################################
