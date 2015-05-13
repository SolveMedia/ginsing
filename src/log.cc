/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-23 11:58 (EST)
  Function: log queries to file
*/

#define CURRENT_SUBSYSTEM	'L'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "lock.h"
#include "hrtime.h"
#include "network.h"
#include "runmode.h"
#include "dns.h"
#include "zdb.h"
#include "version.h"

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

static Mutex loglock;

static void
out_ipv4(FILE *f, uchar *addr){
    fprintf(f, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
}

static void
out_ipv6(FILE *f, uint16_t *addr){
    fprintf(f, "%04X:%04X:%04X:%04X:",
            htons(addr[0]), htons(addr[1]), htons(addr[2]), htons(addr[3]));

    if( !addr[4] && !addr[5] && !addr[6] && addr[7] )
        fprintf(f, ":%04X", htons(addr[7]) );

    else if( addr[4] || addr[5] || addr[6] || addr[7] )
        fprintf(f, "%04X:%04X:%04X:%04X",
                htons(addr[4]), htons(addr[5]), htons(addr[6]), htons(addr[7]));
}


// srcaddr question rf size edns-client

void
log_request(NTD *ntd){
    FILE *f;
    sockaddr_in *si;
    sockaddr_in6 *ss;
    uchar *addr;
    time_t now = lr_now();
    char buf[24];

    if( config->logfile.empty() ) return;

    // try to get lock, skip logging if someone else has it
    if( loglock.trylock() ) return;

    f = fopen(config->logfile.c_str(), "a");
    if( !f ){
        PROBLEM("cannot open %s", config->logfile.c_str());
        loglock.unlock();
        return;
    }

    // NB: gmtime is thread safe on solaris
    strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ ", gmtime(&now));
    fputs(buf, f);

    switch( ntd->sa->sa_family ){
    case AF_INET:
        si = (sockaddr_in*)ntd->sa;
        out_ipv4(f, (uchar*)& si->sin_addr);
        break;
    case AF_INET6:
        ss = (sockaddr_in6*)ntd->sa;
        out_ipv6(f, (uint16_t*)& ss->sin6_addr);
        break;
    }


    fprintf(f, " %s %s/%d-%d %x %d",
            (ntd->querb.bufsize == UDPBUFSIZ) ? "udp" : "tcp",
            ntd->querd.name, ntd->querd.klass, ntd->querd.type,
            ntd->respd.flags & ~FLAG_RESPONSE, ntd->respb.datalen);

    if( ntd->edns.udpsize ){
        fprintf(f, " edns %d ", ntd->edns.udpsize);
    }

    switch( ntd->edns.addr_family ){
    case EDNS0_FAMILY_IPV4:
        out_ipv4(f, ntd->edns.addr);
        fprintf(f, "/%d/%d", ntd->edns.src_masklen, ntd->edns.scope_masklen);
        break;
    case EDNS0_FAMILY_IPV6:
        out_ipv6(f, (uint16_t*)ntd->edns.addr);
        fprintf(f, "/%d/%d", ntd->edns.src_masklen, ntd->edns.scope_masklen);
        break;
    }


    // anything else?
    int mmflag = ntd->mmd.logflags;
    if( mmflag & GLBMM_F_NOLOC )    fprintf(f, " noloc");
    if( mmflag & GLBMM_F_FAIL  )    fprintf(f, " glbf/o");
    if( mmflag & GLBMM_F_FAILFAIL ) fprintf(f, " glbf/o/f");

    fprintf(f, "\n");
    fclose(f);

    // release the lock
    loglock.unlock();
}


