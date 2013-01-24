/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:28 (EST)
  Function: 
*/

#ifndef __acdns_network_h_
#define __acdns_network_h_

#include <string>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "dns.h"
#include "mmd.h"

using std::string;

class DNS_Stats {
public:
#include "stats_defs.h"

    DNS_Stats(){
        memset(this, 0, sizeof(DNS_Stats));
    }
};

class DNS_Buf {
public:
    uchar	*buf;
    int		bufsize;
    int		datalen;

    DNS_Buf(int len){
        buf = (uchar*)malloc(len);
        bufsize = len;
    }
    ~DNS_Buf(){ free(buf); bufsize = 0; }

    inline void put_byte(uchar val){
        buf[ datalen ++ ] = val;
    }

    inline void put_short(uint16_t val){
        buf[ datalen ++ ] = val >> 8;
        buf[ datalen ++ ] = val & 0xFF;
    }

    inline void put_long(uint32_t val){
        buf[ datalen ++ ] = (val >> 24) & 0xFF;
        buf[ datalen ++ ] = (val >> 16) & 0xFF;
        buf[ datalen ++ ] = (val >> 8)  & 0xFF;
        buf[ datalen ++ ] = (val     )  & 0xFF;
    }
    inline void put_data(uchar *src, int len){
        memcpy(buf + datalen, src, len);
        datalen += len;
    }
    inline void put_rr(int type, int klass, int ttl, int rdlen){
        put_short( type );
        put_short( klass );
        put_long(  ttl );
        put_short( rdlen );
    }

};

// name compression
class NTD_DNS_Z_E {
public:
    const char  	*name;
    int			pos;
};
class NTD_DNS_Z {
public:
    int			qpos;	// the question
    int			zpos;	// the zone
    int			nent;
    NTD_DNS_Z_E		ent[MAXZTAB];

    void setqz(const char *q, int ql, int zl){
        qpos = sizeof(DNS_Hdr);
        zpos = sizeof(DNS_Hdr) + ql - zl;
    }

    void add(const char *s, int p){
        if( nent >= MAXZTAB ) return;
        ent[nent].name = s;
        ent[nent].pos  = p;
        nent ++;
    }
};


class NTD_Question {
public:
    int			qdlen;
    uint32_t		klass;
    uint32_t		type;
    int			namelen;
    char		name[MAXNAME + 2];
};

class NTD_Response {
public:
    int			maxsize;
    int			flags;
    int			ancount;
    int			nscount;
    int			arcount;
    bool		has_ns_ans;	// don't do NS auth if we have NS answers
};

class EDNS {
public:
    int			udpsize;	// rfc 2671
    bool		nsid;		// rfc 5001

    // draft-vandergaast-edns-client-subnet
    int			addr_family;
#	define EDNS0_FAMILY_IPV4	1
#	define EDNS0_FAMILY_IPV6	2
    int			src_masklen;
    int			scope_masklen;
    uchar		addr[16];
};

class NTD {
public:
    int                 thno;
    int                 fd;
    DNS_Stats		*stats;
    EDNS		edns;
    DNS_Buf		querb;
    DNS_Buf		respb;
    NTD_Question	querd;
    NTD_Response	respd;
    NTD_DNS_Z		ztab;
    MMD			mmd;
    sockaddr		*sa;
    int			salen;

    NTD(int len) : querb(len), respb(len)  {
        thno = 0; fd = 0;
        memset(&stats, 0, sizeof(stats));
    }

    void reset(int max){
        querb.datalen = respb.datalen = 0;
        memset(&ztab,  0, sizeof(ztab));
        memset(&edns,  0, sizeof(edns));
        memset(&querd, 0, sizeof(querd));
        memset(&respd, 0, sizeof(respd));
        memset(respb.buf, 0, sizeof(DNS_Hdr));
        memset(&mmd,   0, sizeof(MMD));
        respd.maxsize = max;
        sa = 0; salen = 0;
    }

    inline bool space_avail(int l) const {
        return ( respb.datalen + l >= respd.maxsize ) ? 0 : 1;
    }
    void copy_question(void);
    void fill_header(void);
};

#define INCSTAT(n, s)	n->stats->s ++


extern char hostname[];
extern float net_utiliz;
extern float net_req_per_sec;
extern int64_t net_requests;

extern void network_init(void);
extern void network_manage(void);


#endif // __acdns_network_h_
