/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-06 11:46 (EST)
  Function: DNS RRs
*/

#define CURRENT_SUBSYSTEM	'D'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "lock.h"
#include "hrtime.h"
#include "network.h"
#include "dns.h"
#include "zdb.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


RR *
RR::make(string *lab, int kl, int ty, int tt, bool wild){
    RR *rr = 0;

    if( kl == CLASS_IN ){
        switch(ty){
        case TYPE_A:	    rr = new RR_A; 		break;
        case TYPE_AAAA:     rr = new RR_AAAA;		break;
        case TYPE_NS:	    rr = new RR_NS;		break;
        case TYPE_SOA: 	    rr = new RR_SOA;		break;
        case TYPE_CNAME:    rr = new RR_CNAME;		break;
        case TYPE_PTR: 	    rr = new RR_PTR;		break;
        case TYPE_MX: 	    rr = new RR_MX;		break;
        case TYPE_TXT:	    rr = new RR_TXT;		break;
        case TYPE_GLB_RR:   rr = new RR_GLB_RR;		break;
        case TYPE_GLB_GEO:  rr = new RR_GLB_Geo;	break;
        case TYPE_GLB_MM:   rr = new RR_GLB_MM;		break;
        case TYPE_GLB_Hash: rr = new RR_GLB_Hash;	break;
        default:
            BUG("cannot create RR type %d", ty);
            return 0;
        }
    }

    if( kl == CLASS_CH && ty == TYPE_TXT )
        rr = new RR_TXT;

    if( ! rr ) return 0;

    if( ty == TYPE_NS && ! lab->empty() ){
        // delegated subdomain
        rr->delegation = 1;
    }

    rr->type     = ty;
    rr->klass    = kl;
    rr->ttl      = tt;
    rr->wildcard = wild;
    rr->set_name( lab );

    return rr;
}

// dns label encoding
static int
cvt_name_to_wire(string *src, string *dst){

    dst->assign( " " + *src );
    int pos = 0;

    while( pos < dst->length()){
        int e = dst->find('.', pos+1);
        if( e == -1 ) e = dst->length();
        int ll = e - pos - 1;
        dst->at(pos) = ll;
        pos = e;
    }

    return 1;
}

int
RR::set_name(string *s){

    if( s->empty() ){
        name      = "@";
        name_wire = "";
        return 1;
    }

    name = *s;

    if( wildcard ){
        // wire format will most likely just be a pointer to the question
        // handle later
        name_wire = "";
        return 1;
    }

    cvt_name_to_wire(s, &name_wire);

    return 1;
}

void
RRCompString::set_name(string dest, string *zonename){

    // relative or abs?
    // in zone?

    if( dest[ dest.length() - 1 ] != '.' ){
        // relative name in zone
        same_zone = 1;
        name      = dest;
        fqdn      = dest + '.' + *zonename;
        cvt_name_to_wire(&dest, &name_wire);
        DEBUG("relative, same %s -> %s", name.c_str(), fqdn.c_str());
        return;
    }

    int zp = dest.find( *zonename );
    if( zp == dest.length() - zonename->length() ){
        // absolute name in zone
        same_zone = 1;
        fqdn      = dest;
        if( zp > 0 ){
            name      = dest.substr(0, zp-1);
            cvt_name_to_wire(&name, &name_wire);
        }else{
            // x CNAME zone.
            name      = "";
            name_wire = "";
        }
        DEBUG("absol, same %d, %s -> %s", zp, name.c_str(), fqdn.c_str());
        return;
    }

    // absolute out of zone
    same_zone = 0;
    fqdn      = dest;

    // pick a good split point
    int len = dest.length();
    int pos = len - 1;

    for(int i=len-7; i>0; i--){
        if( dest[i] == '.' ){
            pos = i;
            break;
        }
    }

    name      = dest.substr(0, pos);
    cvt_name_to_wire(&name, &name_wire);

    if( pos != len - 1 ){
        domain = dest.substr(pos+1);
        cvt_name_to_wire(&domain, &dom_wire);
        // NB: trailing dot turns into terminating 0
    }

    DEBUG("absol, offsite %s(%d) + %s(%d) -> %s",
          name.c_str(), name_wire.length(), domain.c_str(), dom_wire.length(), fqdn.c_str());

    return;
}



//################################################################

void
RR_Raw::config_raw(){
    DNS_RR_Hdr *hdr = (DNS_RR_Hdr*) rrdata.data();
    hdr->type  = htons( type );
    hdr->klass = htons( klass );
    hdr->ttl   = htonl( ttl );
}

int
RR_TXT::configure(InputF *f, Zone *z, string *rspec){

    const char *txt = rspec->c_str();
    int txtlen = rspec->length();

    // remove ""s
    if( *txt == '"' ){
        txt ++;
        txtlen -= 2;
    }

    // needed space
    int bks = txtlen / 255 + (txtlen % 255 ? 1 : 0);

    if( txtlen + bks > 0xFFFF ) return 1;	// won't fit

    rrdata.resize( DNS_RR_HDR_SIZE + txtlen + bks );
    config_raw();

    DNS_RR_Hdr *hdr = (DNS_RR_Hdr*) rrdata.data();
    hdr->rdlength   = htons( txtlen + bks );

    uchar *dst = (uchar*) hdr->rdata;
    while( txtlen ){
        int bl = txtlen > 255 ? 255 : txtlen;

        *dst++ = bl;
        memcpy(dst, txt, bl);
        dst += bl;
        txt += bl;
        txtlen -= bl;
    }

    return 0;
}

int
RR_A::configure(InputF *f, Zone *z, string *rspec){

    rrdata.resize( DNS_RR_HDR_SIZE + 4 );
    config_raw();

    DNS_RR_Hdr *hdr = (DNS_RR_Hdr*) rrdata.data();
    hdr->rdlength   = htons( 4 );

    int i = inet_pton(AF_INET, rspec->c_str(), hdr->rdata);
    if( i != 1 ){
        DEBUG("pton %s - %d", rspec->c_str(), i);
        return 1;
    }

    return 0;
}

int
RR_AAAA::configure(InputF *f, Zone *z, string *rspec){

    rrdata.resize( DNS_RR_HDR_SIZE + 16 );
    config_raw();

    DNS_RR_Hdr *hdr = (DNS_RR_Hdr*) rrdata.data();
    hdr->rdlength   = htons( 16 );

    int i = inet_pton(AF_INET6, rspec->c_str(), hdr->rdata);

    if( i != 1 ){
        DEBUG("pton %s - %d", rspec->c_str(), i);
        return 1;
    }

    return 0;
}

int
RR_Compress::configure(InputF *f, Zone *z, string *rspec){

    rrdata.set_name( *rspec, & z->zonename );
    return 0;
}

//################################################################

int
RRSet::add_answers(NTD *ntd, int qkl, int qty) const {

    for(int i=0; i<rr.size(); i++){
        RR *r = rr[i];

        if( r->klass == qkl && r->type == TYPE_NS && r->delegation ){
            // delegated subdomain
            DEBUG("found delegation %s %d", r->name.c_str(), r->type);
            r->put_rr(ntd, 0);
            ntd->respd.nscount ++;
            ntd->respd.has_ns_ans = 1;
            continue;
        }
        if( r->klass == qkl && r->can_satisfy(qty) ){
            if( r->type == TYPE_NS ) ntd->respd.has_ns_ans = 1;
            DEBUG("found answer %s %d", r->name.c_str(), r->type);
            if( ! r->add_answer(ntd, 1) ) return 1;

            if( r->type == TYPE_CNAME && qty != TYPE_CNAME && qty != TYPE_ANY ){
                // rfc 1034 3.6.2
                if( ! r->add_add_ans(ntd) ) return 1;
            }
        }
    }

    return 1;
}

int
RR::add_answer(NTD *ntd, bool isq) const{

    if( put_rr(ntd, isq) ){
        ntd->respd.ancount ++;
        return 1;
    }else{
        // rfc 2181 9
        ntd->respd.flags |= FLAG_TC;
        return 0;
    }
}

// add additional data as answers
int
RR::add_add_ans(NTD *ntd) const {

    for(int j=0; j<additional.size(); j++){
        RR *ra = additional[j];
        if( ! ra->add_answer(ntd, 0) ) return 1;
    }

    return 1;
}

int
RR::add_additnl(NTD *ntd) const {

    for(int j=0; j<additional.size(); j++){
        RR *ra = additional[j];
        if( ra->put_rr(ntd, 0) ) ntd->respd.arcount ++;
    }

    return 1;
}

int
RRSet::add_additnl(NTD *ntd, int qkl, int qty) const {

    for(int i=0; i<rr.size(); i++){
        RR *r = rr[i];
        // NB: cname additional is included in the answer, not the additional
        if( r->klass == qkl && (qty == TYPE_ANY || qty == r->type ||
                                // and include addrs for NS on a delegated subdomain
                                (r->type == TYPE_NS && r->delegation) ) ){
            r->add_additnl(ntd);
        }
    }

    return 1;
}

int
Zone::add_ns_auth(NTD *ntd) const {

    for(int i=0; i<ns.size(); i++){
        RR *r = ns[i];
        if( r->put_rr(ntd, 0) ) ntd->respd.nscount ++;
    }
}

int
Zone::add_ns_addl(NTD *ntd) const {

    for(int i=0; i<ns.size(); i++){
        RR *r = ns[i];
        for(int j=0; j<r->additional.size(); j++){
            RR *ra = r->additional[j];
            if( ra->put_rr(ntd, 0) ) ntd->respd.arcount ++;
        }
    }
}

int
Zone::add_soa_auth(NTD *ntd) const {

    if( ! soa ) return 0;
    if( soa->put_rr(ntd, 0) ) ntd->respd.nscount ++;
    return 1;
}

//################################################################
// NB: buffers are oversized, so we can write, then check
// (except for really big txt)

int
RR::put_rr(NTD *ntd, bool isq) const {

    int save = ntd->respb.datalen;

    if( put_name(ntd, isq) && _put_rr(ntd) ) return 1;

    // no room, rewind
    ntd->respb.datalen = save;
    return 0;

}

int
RR::put_name(NTD *ntd, bool isq) const {

    if( isq ){
        ntd->respb.put_short( 0xC000 + ntd->ztab.qpos );	// ptr to question
    }else{
        // NB: results are always in the question's zone
        // label + zone-ptr

        ntd->respb.put_data((uchar*) name_wire.c_str(), name_wire.length());
        ntd->respb.put_short( 0xC000 + ntd->ztab.zpos );
    }

    return ntd->space_avail(0);
}

//################################################################

int
RR_Raw::_put_rr(NTD *ntd) const {

    if( ! ntd->space_avail(rrdata.length()) ) return 0;
    ntd->respb.put_data((uchar*) rrdata.c_str(), rrdata.length());
    return ntd->space_avail(0);
}

int
RRCompString::wire_len(NTD *ntd) const {

    if( same_zone ){
        // name_wire + ptr
        return name_wire.length() + 2;
    }else{
        // RSN - compress
        // name_wire + dom_wire
        return name_wire.length() + dom_wire.length();
    }
}

int
RRCompString::put(NTD *ntd) const {

    ntd->respb.put_data((uchar*) name_wire.c_str(), name_wire.length());

    if( same_zone ){
        ntd->respb.put_short( 0xC000 + ntd->ztab.zpos );	// ptr to zone
    }else{
        ntd->respb.put_data((uchar*) dom_wire.c_str(), dom_wire.length());
    }
}

int
RR_Compress::_put_rr(NTD *ntd) const {

    int rdl = rrdata.wire_len(ntd);

    ntd->respb.put_rr(type, klass, ttl, rdl);
    rrdata.put(ntd);

    return ntd->space_avail(0);
}

int
RR_MX::_put_rr(NTD *ntd) const {

    int dl = dest.wire_len(ntd);
    ntd->respb.put_rr(type, klass, ttl, dl + 2);
    ntd->respb.put_short(pref);
    dest.put(ntd);

    return ntd->space_avail(0);
}

int
RR_SOA::_put_rr(NTD *ntd) const {

    int ml = mname.wire_len(ntd);
    int rl = rname.wire_len(ntd);

    ntd->respb.put_rr(type, klass, ttl, ml + rl + 20);
    mname.put(ntd);
    rname.put(ntd);
    ntd->respb.put_long( serial  );
    ntd->respb.put_long( refresh );
    ntd->respb.put_long( retry   );
    ntd->respb.put_long( expire  );
    ntd->respb.put_long( minimum );

    return ntd->space_avail(0);
}


//################################################################






