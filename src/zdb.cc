/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-07 11:29 (EST)
  Function: read zone file
 
  $Id$

*/
#define CURRENT_SUBSYSTEM	'Z'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "dns.h"
#include "zdb.h"
#include "version.h"

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

ZDB *zdb = 0;



void
zdb_init(void){

    if( !load_zdb() )
        exit(1);
}


//################################################################

RRSet::RRSet(Zone* z, string *l, bool wp){

    wildcard = wp;
    name = *l;
    zone = z;
    if( l->empty() )
        fqdn = zone->zonename;
    else
        fqdn = name + "." + zone->zonename;
}

// s: foo.example.com
// t:     example.com
static bool
match(const char *s, int sl, const char *t, int tl){

    int so = sl - tl;
    if( so < 0 ) return 0;
    if( memcmp(s + so, t, tl) ) return 0;
    if( !so ) return 1;		// exact match
    if( s[so - 1] == '.' ) return 1;
    return 0;
}

bool
RRSet::wildmatch(const char *s, int l) const {

    return match(s, l, fqdn.c_str(), fqdn.length());
}

bool
Zone::zonematch(const char *s, int l) const {

    return match(s, l, zonename.c_str(), zonename.length());

//    const char *p = strstr(s, zonename.c_str());
//    if( p && (p - s) + zonename.length() == l ) return 1;
//    return 0;
}

//################################################################

// add record to the zone
int
Zone::insert(ZDB *db, RR *rr, string *label){
    bool wildp = rr->wildcard;

    RRSet *rrs = find_rrset( label, wildp );
    if( ! rrs ){
        rrs = RRSet::make(this, label, wildp, rr->type);
        if( ! rrs ){
            BUG("create rrs failed! type %d", rr->type);
            return 0;
        }
        rrset.push_back(rrs);
        db->insert(rrs);
        DEBUG("new RRSet wild %d, name %s, zone %s; fqdn %s", wildp, label->c_str(), zonename.c_str(), rrs->fqdn.c_str());
    }

    // glb RR + RRSet must match
    if( ! rrs->is_compat(rr) )
        return 0;

    rrs->add_rr(rr);

    if( label->empty() ){
        if( rr->type == TYPE_NS ) ns.push_back(rr);
        if( rr->type == TYPE_SOA) soa = rr;
    }

    return 1;
}

// add a new rrset to the db
int
ZDB::insert(RRSet *rrs){

    if( rrs->wildcard )
        wildcard.push_back(rrs);
    else
        rrset[ rrs->fqdn.c_str() ] = rrs;

    return 1;
}

RRSet *
RRSet::make(Zone* z, string *l, bool wp, int type){

    if( (type & 0xFFFF) == type ){
        return new RRSet(z,l,wp);
    }

    switch(type){
    case TYPE_GLB_RR:
        return new RRSet_GLB_RR(z,l,wp);
    case TYPE_GLB_GEO:
        return new RRSet_GLB_Geo(z,l,wp);
    case TYPE_GLB_MM:
        return new RRSet_GLB_MM(z,l,wp);
    case TYPE_GLB_Hash:
        return new RRSet_GLB_Hash(z,l,wp);
    default:
        return 0;
    }

    return 0;
}

bool
RRSet::is_compat(RR *r) const {
    // std rrset - std rrs
    return (r->type & 0xFFFF == r->type) ? 0 : 1;
}

bool
RRSet_GLB_RR::is_compat(RR *r) const {
    return r->type == TYPE_GLB_RR;
}
bool
RRSet_GLB_Geo::is_compat(RR *r) const {
    return r->type == TYPE_GLB_GEO;
}
bool
RRSet_GLB_MM::is_compat(RR *r) const {
    return r->type == TYPE_GLB_MM;
}
bool
RRSet_GLB_Hash::is_compat(RR *r) const {
    return r->type == TYPE_GLB_MM;
}


void
RRSet::add_rr(RR *r){
    rr.push_back(r);
}

//################################################################

int
Zone::analyze(ZDB *db){

    for(int i=0; i<rrset.size(); i++){
        rrset[i]->analyze(this);
    }
    return 1;
}

int
RRSet::analyze(Zone *z){

    for(int i=0; i<rr.size(); i++){
        RR *r = rr[i];
        r->analyze(z);
    }

    return 1;
}

// find + attach A+AAAA to NS+CNAME
void
RR_Compress::analyze(Zone *z){

    if( type != TYPE_NS && type != TYPE_CNAME ) return;
    if( ! rrdata.same_zone ) return;

    RRSet *rrs = z->find_rrset( & rrdata.name, 0 );
    if( ! rrs ) return;

    for(int i=0; i< rrs->rr.size(); i++){
        RR *rr = rrs->rr[i];
        if( rr->klass != CLASS_IN ) continue;
        if( rr->type == TYPE_A || rr->type == TYPE_AAAA ){
            DEBUG("found addr for %s -> %s", name.c_str(), rrs->fqdn.c_str());
            additional.push_back(rr);
        }
    }
}

void
RR_MX::analyze(Zone *z){

    if( ! dest.same_zone ) return;

    RRSet *rrs = z->find_rrset( & dest.name, 0 );
    if( ! rrs ) return;

    for(int i=0; i< rrs->rr.size(); i++){
        RR *rr = rrs->rr[i];
        if( rr->klass != CLASS_IN ) continue;
        if( rr->type == TYPE_A || rr->type == TYPE_AAAA ){
            DEBUG("found addr for %s -> %s", name.c_str(), rrs->fqdn.c_str());
            additional.push_back(rr);
        }
    }
}


int
ZDB::analyze(){

    // RSN
    // sort wildcards ?

    return 1;
}

//################################################################

RRSet *
Zone::find_rrset(string *s, bool wp) const {

    // only used while loading zone, no need for speed

    for(int i=0; i<rrset.size(); i++){
        if( rrset[i]->wildcard == wp && rrset[i]->name == *s )
            return rrset[i];
    }
    return 0;
}

RRSet *
ZDB::find_rrset(const char *s) const {

    // rrset[ s ]
    MapRRSet::const_iterator it = rrset.find( s );
    if( it != rrset.end() ){
        return it->second;
    }

    // check wildcards
    int l = strlen(s);
    for(int i=0; i<wildcard.size(); i++){
        if( wildcard[i]->wildmatch(s, l) ) return wildcard[i];
    }

    return 0;
}

Zone *
ZDB::find_zone(const char *s) const {

    int l = strlen(s);
    for(int i=0; i<zone.size(); i++){
        if( zone[i]->zonematch(s, l) ) return zone[i];
    }
    return 0;
}

//################################################################

void
ZDB::add_monitored(RR *rr){
    monitored.push_back(rr);
}


//################################################################

RRSet::~RRSet(){

    for(int i=0; i<rr.size(); i++){
        RR *r = rr[i];
        delete r;
    }
}

Zone::~Zone(){

    for(int i=0; i<rrset.size(); i++){
        RRSet *r = rrset[i];
        delete r;
    }
}

ZDB::~ZDB(){

    for(int i=0; i<zone.size(); i++){
        Zone *z = zone[i];
        delete z;
    }
}
