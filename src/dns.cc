/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-04 14:45 (EST)
  Function: domain name system
*/


#define CURRENT_SUBSYSTEM	'D'

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

extern void log_request(NTD*);

#define error_invalid(n) error_without_copy(n, RCODE_FORMAT)
#define error_notimp(n)  error_with_copy(n, RCODE_NOTIMP)
#define error_refused(n) error_with_copy(n, RCODE_REFUSED)
#define error_mybad(n)   error_with_copy(n, RCODE_IFAIL)

int mypid;

void
dns_init(void){ mypid = getpid(); }

inline void
maybe_log(NTD *ntd){
    if( with_probability(config->logpercent / 100.0) )
        log_request(ntd);
}

static int
error_drop(NTD *ntd){
    DEBUG("dropping");
    INCSTAT(ntd, n_drop);
    return 0;
}

static int
error_without_copy(NTD *ntd, int rcode){
    DNS_Hdr *resp = (DNS_Hdr*) ntd->respb.buf;
    DNS_Hdr *qury = (DNS_Hdr*) ntd->querb.buf;

    DEBUG("sending error %d", rcode);
    INCSTAT(ntd, n_rcode[rcode]);

    memset( ntd->respb.buf, 0, sizeof(DNS_Hdr) );

    // 1035 4.1.1 - Recursion Desired - [...] and is copied into the response
    int rd = ntohs(qury->flags) & FLAG_RD;

    resp->id    = qury->id;
    resp->flags = htons( (rcode << RCODE_SHIFT) | FLAG_RESPONSE | rd );

    return ntd->respb.datalen = sizeof(DNS_Hdr);
}

static int
error_with_copy(NTD *ntd, int rcode){
    DNS_Hdr *resp = (DNS_Hdr*) ntd->respb.buf;
    DNS_Hdr *qury = (DNS_Hdr*) ntd->querb.buf;

    DEBUG("sending error %d", rcode);
    INCSTAT(ntd, n_rcode[rcode]);

    memset( ntd->respb.buf, 0, sizeof(DNS_Hdr) );
    ntd->copy_question();

    ntd->respd.flags |= rcode << RCODE_SHIFT;
    ntd->fill_header();

    maybe_log(ntd);

    return ntd->respb.datalen;
}

static int
status_reply(NTD *ntd){
    DNS_Hdr *resp = (DNS_Hdr*) ntd->respb.buf;
    DNS_Hdr *qury = (DNS_Hdr*) ntd->querb.buf;

    DEBUG("status reply");
    INCSTAT(ntd, n_status);
    memset( ntd->respb.buf, 0, sizeof(DNS_Hdr) );

    int rd = ntohs(qury->flags) & FLAG_RD;
    resp->id    = qury->id;
    resp->flags = htons( (OPCODE_STATUS << OPCODE_SHIFT) | FLAG_RESPONSE | rd );

    return ntd->respb.datalen = sizeof(DNS_Hdr);
}

//################################################################

void
NTD::copy_question(void){
    DNS_Hdr *qury = (DNS_Hdr*) querb.buf;
    DNS_Hdr *resp = (DNS_Hdr*) respb.buf;

    if( ! qury->qdcount ) return;
    resp->qdcount = htons(1);
    DEBUG("qlen %d", querd.qdlen);
    memcpy( respb.buf + sizeof(DNS_Hdr), querb.buf + sizeof(DNS_Hdr), querd.qdlen );
    respb.datalen = sizeof(DNS_Hdr) + querd.qdlen;
}

void
NTD::fill_header(void){
    DNS_Hdr *qury = (DNS_Hdr*) querb.buf;
    DNS_Hdr *resp = (DNS_Hdr*) respb.buf;

    int rd = ntohs(qury->flags) & FLAG_RD;
    respd.flags  |= FLAG_RESPONSE | rd;

    resp->id      = qury->id;
    resp->flags   = htons( respd.flags );
    resp->ancount = htons( respd.ancount );
    resp->nscount = htons( respd.nscount );
    resp->arcount = htons( respd.arcount );
}


//################################################################

static uint16_t
get_short(uchar *src){
    uint16_t val = src[0] << 8 | src[1];
    return val;
}

//################################################################

// qname, qtype, qclass
// fill in querd.klass,type,name, querd.qdlen
static int
parse_question(NTD *ntd){
    DNS_Hdr *qury = (DNS_Hdr*) ntd->querb.buf;
    int dlen  = ntd->querb.datalen;
    uchar *qs = (uchar*) ntd->querb.buf + sizeof(DNS_Hdr);
    uchar *qe = (uchar*) ntd->querb.buf + dlen - 1;
    uchar *qp = qs;
    int dpos  = 0;

    // process qname
    while(qp <= qe && dpos <= MAXNAME){
        int lablen = *qp ++;
        if( ! lablen ) break;	// done parsing name

        if( lablen < 0 || lablen > MAXLABEL ) return 0;
        if( qp + lablen > qe )                return 0;
        if( dpos + lablen + 1 > MAXNAME )     return 0;

        for(int i=0; i<lablen; i++){
            ntd->querd.name[dpos++] = tolower(*qp++);
        }

        ntd->querd.name[dpos++] = '.';
    }

    if( !dpos )
        ntd->querd.name[dpos++] = '.';

    ntd->querd.name[dpos] = 0;

    // process type/class
    if( qe - qp + 1 < 4 ) return 0;
    ntd->querd.type    = get_short( qp );	qp += 2;
    ntd->querd.klass   = get_short( qp );	qp += 2;
    ntd->querd.qdlen   = qp - qs;
    ntd->querd.namelen = dpos;

    if( ntd->querd.klass == CLASS_ANY ) ntd->querd.klass = CLASS_IN;

    DEBUG("question c=%d t=%d q=%s namelen=%d dlen=%d ",
          ntd->querd.klass, ntd->querd.type, ntd->querd.name, dpos, ntd->querd.qdlen);

    return 1;
}

//################################################################

// draft-vandergaast-edns-client-subnet
static int
parse_client_subnet(NTD *ntd, uchar *qs, int optlen){

    if( optlen < 4 ) return 0;

    int family = get_short( qs );	qs += 2;
    int srcml  = *qs ++;
    int scpml  = *qs ++;

    // how many bytes of address are there?
    int alen = (srcml + 7) / 8;
    if( alen > optlen - 4 ) return 0;

    switch(family){
    case EDNS0_FAMILY_IPV4:
        if( srcml < 8  || srcml > 32 )  return 0;
        INCSTAT(ntd, n_client_subnet_ipv4);
        break;
    case EDNS0_FAMILY_IPV6:
        if( srcml < 16 || srcml > 128 ) return 0;
        INCSTAT(ntd, n_client_subnet_ipv4);
        break;
    default:
        return 0;
    }

    ntd->edns.addr_family = family;
    ntd->edns.src_masklen = srcml;
    memcpy(ntd->edns.addr, qs, alen);

    DEBUG("edns0-client-subnet");

    return 1;
}

// 2671
static int
parse_edns(NTD *ntd){

    int dlen   = ntd->querb.datalen;
    int estart = sizeof(DNS_Hdr) + ntd->querd.qdlen;

    if( estart + 1 + DNS_RR_HDR_SIZE > dlen ) return 0;

    uchar *qs = (uchar*) ntd->querb.buf + estart;
    uchar *qz = (uchar*) ntd->querb.buf + dlen;

    // XXX - we only look at the first thing after the question

    // name should be null
    if( *qs ++ ) return 0;

    int type    = get_short( qs ); qs += 2;
    int udpsize = get_short( qs ); qs += 2;
    int rcver   = get_short( qs ); qs += 2;
    int ez      = get_short( qs ); qs += 2;
    int rdlen   = get_short( qs ); qs += 2;

    if( type != TYPE_OPT ) return 0;
    if( rcver || ez )      return 0;
    if( qs + rdlen > qz )  return 0;

    ntd->edns.udpsize  = udpsize;
    ntd->respd.maxsize = BOUND(udpsize, 512, MAXUDPEXT);
    DEBUG("edns udp=%d", udpsize);

    while(rdlen){
        int optcode = get_short(qs); qs += 2;
        int optlen  = get_short(qs); qs += 2;
        rdlen -=4;
        if( optlen > rdlen ) break;

        DEBUG("edns opt %d", optcode);

        switch(optcode){
        case EDNS_OPT_NSID:
            ntd->edns.nsid = 1;
            break;
        case EDNS_OPT_CLIENTSUBNET:
            parse_client_subnet(ntd, qs, optlen);
            break;
        default:
            break;
        }

        qs    += optlen;
        rdlen -= optlen;
    }

    INCSTAT(ntd, n_edns);
    return 1;
}

static int
add_edns(NTD *ntd){

    int rdlen = 0;
    int alen  = 0;

    if( ntd->edns.addr_family ){
        alen = (ntd->edns.src_masklen + 7) / 8;
        rdlen += alen + 8;
    }
    if( ntd->edns.nsid ){
        rdlen += 2 + 4;
    }

    if( !ntd->space_avail(rdlen + 11) ) return 0;

    ntd->respb.put_byte(0);	// null name
    ntd->respb.put_rr( TYPE_OPT, MAXUDPEXT, 0, rdlen );

    if( ntd->edns.addr_family ){
        // client-subnet
        ntd->respb.put_short( EDNS_OPT_CLIENTSUBNET );
        ntd->respb.put_short( alen + 4 );
        ntd->respb.put_short( ntd->edns.addr_family );
        ntd->respb.put_byte(  ntd->edns.src_masklen );
        ntd->respb.put_byte(  ntd->edns.scope_masklen );
        ntd->respb.put_data(  (uchar*)ntd->edns.addr, alen );
    }

    if( ntd->edns.nsid ){
        // 5001
        ntd->respb.put_short( EDNS_OPT_NSID );
        ntd->respb.put_short( sizeof(short) );
        ntd->respb.put_short( mypid );
    }

    ntd->respd.arcount ++;

    return 1;
}

//################################################################
extern DNS_Stats net_stats;
static struct {
    const char *name;
    bool        auth;
    const char  fmt;
    const void *data;
} chaosmib[] = {
    { "version.bind.",    0, 0,    version                 },
    { "version.server.",  0, 0,    version                 },
    { "id.server.",       0, 0,    hostname                },
    { "hostname.server.", 0, 0,    hostname                },
    { "xyzzy.",	          0, 0,    "nothing happens"       },
    { "plugh.",           0, 0,    "Y2"                    },
    { "load.server.",     1, 'f',  &net_utiliz             },
    { "rps.server.",      1, 'f',  &net_req_per_sec        },
    { "status.server.",   1, 'D',  (void*)&current_runmode },
#include "stats_mib.h"
};

static int
add_chaos(NTD *ntd, int i){
    uchar *ans = ntd->respb.buf + sizeof(DNS_Hdr) + ntd->querd.qdlen;
    char buf[32];
    int (*func)(void);
    char *v;

    if( chaosmib[i].auth && ! config->check_acl(ntd->sa))
        return 0;

    switch(chaosmib[i].fmt){
    case 0:
        v = (char*) chaosmib[i].data;
        break;
    case 'f':
        snprintf(buf, sizeof(buf), "%.6f", * (float*)chaosmib[i].data);
        v = buf;
        break;
    case 'd':
        snprintf(buf, sizeof(buf), "%d", * (int*)chaosmib[i].data);
        v = buf;
        break;
    case 'q':
        snprintf(buf, sizeof(buf), "%lld", * (int64_t*)chaosmib[i].data);
        v = buf;
        break;
    case 'D':
        func = (int(*)(void))chaosmib[i].data;
        snprintf(buf, sizeof(buf), "%d", func() );
        v = buf;
        break;
    default:
        BUG("corrupt chaos mib");
        return 0;
    }

    int vlen = strlen(v);
    if( vlen > 255 ) return 0;				// too lazy to handle such silliness

    if( vlen + 13 + ntd->respb.datalen > ntd->respd.maxsize ){
        ntd->respd.flags |= FLAG_TC;
        return 1;
    }

    ntd->respd.ancount ++;
    ntd->respb.put_short( 0xC000 + sizeof(DNS_Hdr) );	// ptr to question
    ntd->respb.put_rr( TYPE_TXT, CLASS_CH, 300, vlen + 1 );
    ntd->respb.put_byte( vlen );			// character-string length 1035 3.3
    memcpy(ntd->respb.buf + ntd->respb.datalen, v, vlen );
    ntd->respb.datalen += vlen;

    return 1;
}

static int
reply_chaos(NTD *ntd){
    DNS_Hdr *resp = (DNS_Hdr*) ntd->respb.buf;
    DNS_Hdr *qury = (DNS_Hdr*) ntd->querb.buf;

    memset( ntd->respb.buf, 0, sizeof(DNS_Hdr) );
    ntd->copy_question();

    int type = ntd->querd.type;
    if( type == TYPE_ANY ) type = TYPE_TXT;

    ntd->respd.flags = FLAG_AA;

    int rcode = RCODE_NX;
    for(int i=0; i<ELEMENTSIN(chaosmib); i++){
        if( !strcmp(chaosmib[i].name, ntd->querd.name) ){
            if( type != TYPE_TXT ){
                rcode = 0;
                break;
            }
            if( add_chaos(ntd, i) ){
                rcode = 0;
            }else{
                rcode = RCODE_REFUSED;
            }
            break;
        }
    }


    ntd->respd.flags |= rcode << RCODE_SHIFT;
    ntd->fill_header();

    INCSTAT(ntd, n_chaos);
    maybe_log(ntd);

    return ntd->respb.datalen;
}

//################################################################

int
dns_process(NTD *ntd){
    DNS_Hdr *qury = (DNS_Hdr*) ntd->querb.buf;

    INCSTAT(ntd, n_requests);

    // check header
    if( ntd->querb.datalen < sizeof(DNS_Hdr) ) return error_drop(ntd);
    int fl  = ntohs( qury->flags );
    int op  = ( fl >> OPCODE_SHIFT ) & OPCODE_MASK;
    int rc  = ( fl >> RCODE_SHIFT  ) & RCODE_MASK;
    int qdc = ntohs(qury->qdcount);
    if( fl & FLAG_RESPONSE )   return error_drop(ntd);    // must drop - to avoid loop
    if( rc )                   return error_invalid(ntd);
    if( !zdb )		       return error_mybad(ntd);
    if( op == OPCODE_STATUS )  return status_reply(ntd);
    if( op != OPCODE_QUERY )   return error_notimp(ntd);
    if( qdc != 1 )             return error_invalid(ntd); // only answer 1 question

    // parse question
    if( !parse_question(ntd) ) return error_invalid(ntd);

    int cl = ntd->querd.klass;
    int ty = ntd->querd.type;

    if( cl == CLASS_CH )       return reply_chaos(ntd);
    if( cl != CLASS_IN )       return error_notimp(ntd);

    if( qury->arcount )        parse_edns(ntd);

    // find answer

    RRSet *rrs = zdb->find_rrset( ntd->querd.name );
    Zone  *z   = rrs ? rrs->zone : zdb->find_zone( ntd->querd.name );

    DEBUG("found rrs %x z %x (%s)", rrs, z, z? z->zonename.c_str() : "-");

    if( !z ) return error_refused(ntd);

    // build response
    ntd->respd.flags |= FLAG_AA;
    ntd->copy_question();

    // init compression table
    ntd->ztab.setqz(ntd->querd.name, ntd->querd.namelen, z->zonename.length());

    if( rrs ){
        // add answers
        rrs->add_answers(ntd, cl, ty);
        INCSTAT(ntd, n_rcode[0]);
    }else{
        // nope, can't help you. sorry.
        ntd->respd.flags |= RCODE_NX << RCODE_SHIFT;
        INCSTAT(ntd, n_rcode[RCODE_NX]);
    }

    if( ntd->respd.ancount || ntd->respd.nscount ){
        // if answers are truncated, don't add anything (even if they'd fit)
        if( ! (ntd->respd.flags & FLAG_TC) ){
            // add NS to auth
            if( !ntd->respd.has_ns_ans ) z->add_ns_auth(ntd);
            // add rrs additional
            rrs->add_additnl(ntd, cl, ty);
            // add NS-additional
            if( !ntd->respd.has_ns_ans ) z->add_ns_addl(ntd);
        }
    }else{
        // add soa to auth
        // 1034 4.3.4, 2181 7.1
        if( z ) z->add_soa_auth(ntd);
    }

    // add edns info
    if( !(ntd->respd.flags & FLAG_TC) && ntd->edns.udpsize ) add_edns(ntd);


    DEBUG("replying %d", ntd->respb.datalen);
    ntd->fill_header();

    // log some requests
    maybe_log(ntd);

    return ntd->respb.datalen;

}
