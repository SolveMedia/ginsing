/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-11 17:01 (EST)
  Function: global traffic director / geo load balancing / gslb / ...
*/

#define CURRENT_SUBSYSTEM	'g'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "lock.h"
#include "hrtime.h"
#include "network.h"
#include "maint.h"
#include "dns.h"
#include "zdb.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <algorithm>


void
RRSet_GLB_MM::add_rr(RR *r){

    RRSet::add_rr(r);

    RR_GLB_MM *rm = (RR_GLB_MM*)r;
    dcrr[ rm->datacenter.c_str() ] = r;
}

// respond with all available matching RRs
static inline int
respond(NTD *ntd, const RRSet *rs, int qty){
    int ok = 0;

    for(int i=0; i<rs->rr.size(); i++){
        RR *rr = rs->rr[i];
        if( ! rr->can_satisfy(qty) )   continue;
        if( ! rr->probe_looks_good() ) continue;

        rr->add_answer(ntd, 1, CLASS_IN, qty);
        if( rr->type == TYPE_CNAME && qty != TYPE_CNAME && qty != TYPE_ANY )
            rr->add_add_ans(ntd, CLASS_IN, qty);
        ok = 1;
    }

    return ok;
}

bool
RR_GLB_MM::datacenter_looks_good(void) const{
    return ! maint_get( datacenter.c_str() );
}

int
RRSet_GLB_RR::add_answers(NTD *ntd, int qkl, int qty) const {
    float totwgt = 0;
    const RRSet *best = 0;

    if( qkl != CLASS_IN ) return 0;

    switch(qty){
    case TYPE_A:     case TYPE_AAAA:
    case TYPE_CNAME: case TYPE_ANY:
        break;
    default:
        return 0;
    }

    INCSTAT(ntd, n_glb);

    // randomly pick from available matching records

    for(int i=0; i<rr.size(); i++){
        RR_GLB_RR *r = (RR_GLB_RR*) rr[i];
        RRSet *rs = r->comp_rrset;
        if( ! rs || r->special ) continue;
        bool ok = 0;

        DEBUG("%s => %s w %f", name.c_str(), rs->name.c_str(), r->weight);
        for(int j=0; j<rs->rr.size(); j++){
            RR *rr = rs->rr[j];
            if( ! rr->can_satisfy(qty) )   continue;
            if( ! rr->probe_looks_good() ) continue;

            ok = 1;
            break;
        }

        if( ! ok ) continue;

        totwgt += r->weight;
        if( with_probability(r->weight / totwgt) ){
            best = rs;
        }
    }

    if( best ){
        return respond(ntd, best, qty);
    }

    INCSTAT(ntd, n_glb_failover_fail);
    return 0;
}

// find entry for specified datacenter
const RR_GLB_MM*
RRSet_GLB_MM::find(const char *dc) const {
    MapRR::const_iterator it = dcrr.find(dc);
    if( it == dcrr.end() ) return 0;		// QQQ - should this be logged?
    const RR_GLB_MM *r = (RR_GLB_MM*) it->second;
    return r;
}

void
RRSet_GLB_MM::weight_and_sort(NTD *ntd) const {
    MMElem *mme = ntd->mmd.mm;
    int nelem   = ntd->mmd.nelem;

    for(int i=0; i<nelem; i++){
        if( ! mme[i].datacenter ) continue;
        const RR_GLB_MM *r = find( mme[i].datacenter );
        if( !r ) continue;
        // higher weight = more preferred. => lower metric
        mme[i].metric = int( mme[i].metric / r->weight );
    }
    std::sort( mme, mme + nelem );
}

int
RRSet_GLB_MM::add_answers(NTD *ntd, int qkl, int qty) const {

    if( qkl != CLASS_IN ) return 0;

    switch(qty){
    case TYPE_A:     case TYPE_AAAA:
    case TYPE_CNAME: case TYPE_ANY:
        break;
    default:
        return 0;
    }

    INCSTAT(ntd, n_glb);

    // get metrics
    if( MMDB::locate(ntd) ){
        weight_and_sort(ntd);
    }else{
        INCSTAT(ntd, n_glb_nolocation);
        ntd->mmd.logflags |= GLBMM_F_NOLOC;
        // don't know where this user is
        // is there a configured "unknown" record?
        int res = a_a_failover_specify(":unknown", ntd, qty);
        if( res ) return res;
        // otherwise use the first available
        return add_answers_first_match(ntd, qty);
    }

    const RR_GLB_MM *best  = 0;
    MMElem *mme = ntd->mmd.mm;
    int nelem   = ntd->mmd.nelem;
    int navail  = nelem;
    bool typeok = 0;

    // try to find best match
    for(int i=0; i<nelem; i++){
        const char *dcn = mme[i].datacenter;
        if( !dcn ) continue;
        const RR_GLB_MM *r = find(dcn);
        const RRSet *rs = r ? r->comp_rrset : 0;
        if( ! rs ){
            mme[i].datacenter = 0;
            continue;
        }
        bool dcok = r->datacenter_looks_good();

        // track whether the datacenter is usable, in order to save time in failover
        bool match = 0;

        for(int j=0; j<rs->rr.size(); j++){
            const RR *rr = rs->rr[j];
            bool ok = dcok && rr->probe_looks_good();

            if( ! rr->can_satisfy(qty) ) continue;
            typeok = 1;

            if( !best && ok ){
                // best RR is up - use it. done
                DEBUG("best dc is %s, is up, using %s", dcn, rr->name.c_str());
                respond(ntd, rs, qty );
                return 1;
            }

            if( !best ) best = r;

            if( ok ){
                match = 1;
                break;
            }
        }

        if( !match ){
            // not usable, cross it off
            mme[i].datacenter = 0;
            navail --;
        }
    }

    // grumble. best is not available
    if( typeok ) INCSTAT(ntd, n_glb_failover);
    ntd->mmd.logflags |= GLBMM_F_FAIL;

    int res = 0;
    if( best && navail )
        res = add_answers_failover(best, ntd, qty);

    if( !res )
        res = a_a_failover_specify(":lastresort", ntd, qty);

    if( res ) return res;

    // nothing avail
    if( typeok ) INCSTAT(ntd, n_glb_failover_fail);
    ntd->mmd.logflags |= GLBMM_F_FAILFAIL;
    return 0;
}

// if we cannot figure out where the user is
// and there is no unknown configured
// they get sent to the first matching RR
int
RRSet_GLB_MM::add_answers_first_match(NTD *ntd, int qty) const {

    INCSTAT(ntd, n_glb_nolocation);

    bool typeok = 0;

    for(int i=0; i<rr.size(); i++){
        RR_GLB_MM *r = (RR_GLB_MM*) rr[i];
        RRSet *rs = r->comp_rrset;
        if( ! rs || r->special ) continue;

        for(int j=0; j<rs->rr.size(); j++){
            RR *rr = rs->rr[j];
            if( ! rr->can_satisfy(qty) )   continue;
            typeok = 1;
            if( ! rr->probe_looks_good() ) continue;

            DEBUG("cannot locate user, using %s", rr->name.c_str());
            respond(ntd, rs, qty );
            return 1;
        }
    }

    if( typeok ) INCSTAT(ntd, n_glb_failover_fail);
    ntd->mmd.logflags |= GLBMM_F_FAILFAIL;

    return 0;
}


int
RRSet_GLB_MM::add_answers_failover(const RR_GLB_MM *dbest, NTD *ntd, int qty) const {

    int res;

    if( dbest->failover_rrset )
        return respond(ntd, dbest->failover_rrset, qty);

    switch( dbest->failover_alg ){
    case GLB_FAILOVER_NEXTBEST:
        res = a_a_failover_nextbest(dbest, ntd, qty);
        break;
    case GLB_FAILOVER_RRALL:
        res = a_a_failover_rrall(dbest, ntd, qty);
        break;
    case GLB_FAILOVER_RRGOOD:
        res = a_a_failover_rrgood(dbest, ntd, qty);
        break;
    case GLB_FAILOVER_SPECIFY:
        res = a_a_failover_specify(dbest, ntd, qty);
        break;
    default:
        BUG("invalid glb:mm failover mode %d", dbest->failover_alg);
        res = 0;
    }

    return res;
}

// find next best available
int
RRSet_GLB_MM::a_a_failover_nextbest(const RR_GLB_MM *dbest, NTD *ntd, int qty) const {

    MMElem *mme = ntd->mmd.mm;
    int nelem   = ntd->mmd.nelem;

    for(int i=0; i<nelem; i++){
        const char *dcn = mme[i].datacenter;
        if( !dcn ) continue;
        const RR_GLB_MM *r = find(dcn);
        if( ! r ) continue;
        const RRSet *rs = r->comp_rrset;
        if( ! rs ) continue;

        // NB: list has already been pruned, this matches and is available
        DEBUG("failover nextbest dc is %s, using %s", dcn, rs->name.c_str());
        return respond(ntd, rs, qty);
    }

    return 0;
}

// round-robin all available
int
RRSet_GLB_MM::a_a_failover_rrall(const RR_GLB_MM * dbest, NTD *ntd, int qty) const {

    MMElem *mme = ntd->mmd.mm;
    int nelem   = ntd->mmd.nelem;
    const RRSet *best = 0;
    int nm = 0;

    for(int i=0; i<nelem; i++){
        const char *dcn = mme[i].datacenter;
        if( !dcn ) continue;
        const RR_GLB_MM *r = find(dcn);
        if( ! r )  continue;
        const RRSet *rs = r->comp_rrset;
        if( ! rs ) continue;

        nm ++;
        if( with_probability(1.0 / nm) ){
            best = rs;
        }
    }

    if( best ){
        DEBUG("failover rrall using %s", best->name.c_str());
        return respond(ntd, best, qty);
    }

    return 0;
}

// round-robin all available "nearby"
// "nearby" is determined by a simple heuristic
// based on typical datacenter distribution
// QQQ - should something be configurable?
int
RRSet_GLB_MM::a_a_failover_rrgood(const RR_GLB_MM *dbest, NTD *ntd, int qty) const {

    MMElem *mme = ntd->mmd.mm;
    int nelem   = ntd->mmd.nelem;
    const RRSet *best = 0;
    int nm = 0;

    if( nelem < 2 ) return 0;
    int thold = (nelem < 3) ? mme[nelem-1].metric :
        mme[0].metric + (mme[nelem-1].metric - mme[0].metric) * (nelem - 1) / (nelem - 2) / 2;

    for(int i=0; i<nelem; i++){
        const char *dcn = mme[i].datacenter;
        if( !dcn ) continue;

        // make sure we use at least 2
        if( nm > 2 && mme[i].metric > thold ) continue;

        const RR_GLB_MM *r = find(dcn);
        if( ! r )  continue;
        const RRSet *rs = r->comp_rrset;
        if( ! rs ) continue;

        nm ++;
        if( with_probability(1.0 / nm) ){
            best = rs;
        }
    }

    if( best ){
        DEBUG("failover rrgood using %s", best->name.c_str());
        return respond(ntd, best, qty);
    }

    return 0;
}

int
RRSet_GLB_MM::a_a_failover_specify(const RR_GLB_MM *dbest, NTD *ntd, int qty) const {

    // use configured datacenter
    const char *where  = dbest->failover_name.c_str();
    return a_a_failover_specify(where, ntd, qty);
}

int
RRSet_GLB_MM::a_a_failover_specify(const char *dst, NTD *ntd, int qty) const {

    // use specified dst
    const RR_GLB_MM *r = find( dst );

    if( ! r )  return 0;
    const RRSet *rs = r->comp_rrset;
    if( ! rs ) return 0;

    for(int j=0; j<rs->rr.size(); j++){
        const RR *rr = rs->rr[j];

        if( ! rr->probe_looks_good() ) continue;	// QQQ - or use anyway?
        if( ! rr->can_satisfy(qty) )   continue;

        DEBUG("failover to specified '%s', using %s", dst, rr->name.c_str());
        return respond(ntd, rs, qty);
    }

    return 0;
}

