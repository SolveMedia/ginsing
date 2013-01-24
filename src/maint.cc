/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-22 17:28 (EST)
  Function: track datacenter maintenance
*/

#define CURRENT_SUBSYSTEM	'g'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "lock.h"
#include "hrtime.h"
#include "maint.h"
#include "zdb.h"
#include "mmd.h"
#include "lock.h"

#include <stdlib.h>

static MMD   dcm;

static int
find(const char *dc){

    for(int i=0; i<dcm.nelem; i++){
        if( ! dcm.mm[i].datacenter ) continue;
        if( !strcmp(dc, dcm.mm[i].datacenter) ) return i;
    }

    return -1;
}

// datacenters are registered when mmdb is loaded
void
maint_register(const char *dc){

    int pos = find(dc);
    if( pos != -1 ) return;	// already got it

    if( dcm.nelem >= MAXMMELEM ){
        PROBLEM("too many datacenters. cannot add");
        return;
    }

    // insert
    dcm.mm[dcm.nelem].metric = 0;	// mark it as ok

    char *ndc = strdup(dc);
    ATOMIC_SETPTR(dcm.mm[dcm.nelem ++].datacenter, ndc);

}


bool
maint_get(const char *dc){

    int i = find(dc);
    if( i == -1 ){
        DEBUG("%s is ?", dc);
        return 0;
    }

    return dcm.mm[i].metric;
}

bool
maint_set(const char *dc, bool status){

    int i = find(dc);
    if( i == -1 ){
        DEBUG("invalid datacenter %s", dc);
        return 0;
    }

    dcm.mm[i].metric = status;

    if( status ){
        DEBUG("offline maint %s", dc);
    }else{
        DEBUG("online maint %s", dc);
    }

    return 1;
}

