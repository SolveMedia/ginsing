/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-16 14:18 (EST)
  Function: metrics mapping
*/

#define CURRENT_SUBSYSTEM	'm'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "mmd.h"
#include "network.h"
#include "thread.h"
#include "maint.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


static MMDB mmdb;


static void*
reload_data(void *){

    while(1){
        mmdb.maybe_load_ipv4();
        mmdb.maybe_load_ipv6();
        sleep(10);
    }
}

void
mmdb_init(void){

    if( !mmdb.load_ipv4() || !mmdb.load_ipv6() )
        exit(1);

    start_thread( reload_data, (void*)0 );
}

//################################################################

MMD::MMD(){ memset(this, 0, sizeof(MMD)); }


int
MMDB::maybe_load_ipv4(void){

    if( !ipv4 || ipv4->file_changed( config->datafile_ipv4.c_str() ) )
        load_ipv4();
}

int
MMDB::maybe_load_ipv6(void){

    if( !ipv6 || ipv6->file_changed( config->datafile_ipv6.c_str() ) )
        load_ipv6();
}

int
MMDB::load_ipv4(void){

    if( config->datafile_ipv4.empty() ) return 1;

    MMDB_File *tmp = new MMDB_File;

    if( ! tmp->load( config->datafile_ipv4.c_str() ) ){
        delete tmp;
        return 0;
    }

    MMDB_File *old = ipv4;
    ATOMIC_SETPTR( ipv4, tmp );

    if( old ){
        VERBOSE("reloaded ipv4 mm data");
        sleep(5);
        delete old;
    }

    return 1;
}

int
MMDB::load_ipv6(void){

    if( config->datafile_ipv6.empty() ) return 1;

    MMDB_File *tmp = new MMDB_File;

    if( ! tmp->load( config->datafile_ipv6.c_str() ) ){
        delete tmp;
        return 0;
    }

    MMDB_File *old = ipv6;
    ATOMIC_SETPTR( ipv6, tmp );

    if( old ){
        VERBOSE("reloaded ipv6 mm data");
        sleep(5);
        delete old;
    }

    return 1;

}

//################################################################

// for checking zone files
bool
MMDB::datacenter_valid(const char *dc){

    if( mmdb.ipv4 && mmdb.ipv4->datacenter_valid(dc) ) return 1;
    if( mmdb.ipv6 && mmdb.ipv6->datacenter_valid(dc) ) return 1;
    return 0;
}

bool
MMDB_File::datacenter_valid(const char *dcn) const{

    for(int i=0; i<hdr->n_datacenter; i++){
        if( !strcmp(dc[i], dcn) ) return 1;
    }
    return 0;
}

//################################################################

bool
MMDB_File::file_changed(const char *file) const {
    struct stat sb;

    if( !file || !*file ) return 0;

    int i = stat((char*)file, &sb);
    if( i == -1 ){
        VERBOSE("cannot stat file '%s': %s", file, strerror(errno));
        // yeah, something changed, but we can't load the file
        return 0;
    }

    if( sb.st_ino   != file_inum )  return 1;
    if( sb.st_mtime != file_mtime ) return 1;
    return 0;
}

int
MMDB_File::load(const char *file){
    int fd, err;
    size_t size, pgsz;
    void *mm;
    struct stat sb;

    fd = open(file, O_RDONLY);
    if( fd == -1 ){
        err = errno;
        VERBOSE("cannot open datafile '%s': %s", file, strerror(err));
        return 0;
    }

    fstat(fd, &sb);
    size = sb.st_size;
    pgsz = sysconf(_SC_PAGESIZE);
    DEBUG("datafile: %s size %d, page %d", file, size, pgsz);
    size = (size + pgsz - 1) & ~(pgsz - 1);

    mm = mmap(0, size, PROT_READ, MAP_SHARED
#ifdef MAP_FILE
              | MAP_FILE
#endif
              , fd, 0);

    err = errno;
    close(fd);

    if( mm == MAP_FAILED ){
        PROBLEM("mmap datafile failed %s", strerror(err));
        return 0;
    }

    file_mtime = sb.st_mtime;
    file_inum  = sb.st_ino;
    map_start  = mm;
    map_size   = size;
    hdr        = (MMDFile_Hdr*)map_start;

    if( hdr->magic != MMDDATAMAGIC || hdr->version != MMDDATAVERSION ){
        PROBLEM("corrupt datafile (magic %X)", hdr->magic);
        return 0;
    }

    // RSN - more validation


    rec        = (MMDFile_Rec*)( (char*)map_start + hdr->recs_start );
    addr_size  = hdr->ipver == 6 ? 8 : 4;
    rec_size   = hdr->rec_size;

    // init datacenter list
    const char *dcs = (char*)map_start + hdr->datacenter_start;
    for(int i=0; i<hdr->n_datacenter; i++){
        dc[i] = dcs;
        maint_register( dcs );
        DEBUG("datacenter %d => %s", i, dcs);
        while( *dcs ++ ){}
    }

#if 0
    for(int i=0; i<hdr->n_recs; i++){
        const MMDFile_Rec *r = get_rec(i);
        DEBUG("rec %d  %02x.%02x.%02x.%02x", i, r->addr[0], r->addr[1], r->addr[2], r->addr[3]);
    }
#endif

    return 1;
}

MMDB_File::~MMDB_File(){

    int i = munmap((char*)map_start, map_size);
    if( i == -1 ){
        PROBLEM("error unmapping datafile: %s", strerror(errno));
    }
}

//################################################################

// wherefore art thou, romeo?
int
MMDB::locate(NTD *ntd) {
    sockaddr_in *si;
    sockaddr_in6 *ss;

    // do we have edns clinet-subnet info?
    switch( ntd->edns.addr_family ){
    case EDNS0_FAMILY_IPV4:
        return mmdb.ipv4 ? mmdb.ipv4->locate(ntd, ntd->edns.addr) : 0;

    case EDNS0_FAMILY_IPV6:
        return mmdb.ipv6 ? mmdb.ipv6->locate(ntd, ntd->edns.addr) : 0;
    }

    // otherwise use src addr
    switch( ntd->sa->sa_family ){
    case AF_INET:
        si = (sockaddr_in*)ntd->sa;
        return mmdb.ipv4 ? mmdb.ipv4->locate(ntd, (uchar*)& si->sin_addr) : 0;

    case AF_INET6:
        ss = (sockaddr_in6*)ntd->sa;
        return mmdb.ipv4 ? mmdb.ipv4->locate(ntd, (uchar*)& ss->sin6_addr) : 0;
    }

    return 0;
}

int
MMDB_File::locate(NTD *ntd, const uchar *addr) const {

    DEBUG("look for %02x%02x%02x%02x.%02x%02x%02x%02x",
          addr[0], addr[1], addr[2], addr[3],
          addr[4], addr[5], addr[6], addr[7]);

    const MMDFile_Rec *fb = best_rec(addr);
    if( !fb ) return 0;

    DEBUG("found %02x%02x%02x%02x.%02x%02x%02x%02x /%d f=%d",
          fb->addr[0], fb->addr[1], fb->addr[2], fb->addr[3],
          fb->addr[4], fb->addr[5], fb->addr[6], fb->addr[7],
          fb->masklen, fb->flags);

    if( fb->flags & MMDFREC_FLAG_UNKNOWN ) return 0;

    // copy data
    for(int i=0; i<hdr->n_datacenter; i++){
        ntd->mmd.mm[i].datacenter = dc[i];
        ntd->mmd.mm[i].metric     = fb->metric[i];
        DEBUG("  %s => %d", dc[i], fb->metric[i]);
    }

    ntd->mmd.nelem = hdr->n_datacenter;
    ntd->edns.scope_masklen = fb->masklen;

    return 1;
}

const MMDFile_Rec *
MMDB_File::best_rec(const uchar *addr) const {

    // binary search
    int f=0, l=hdr->n_recs-1;
    DEBUG("bsearch %d - %d recs, as %d, rs %d", f, l, addr_size, hdr->rec_size);

    while(f <= l){
        int m = (f+l)/2;
        const MMDFile_Rec *r = get_rec(m);
        int s = memcmp(addr, r->addr, addr_size);

        if( s > 0 )      f = m + 1;     // move right
        else if( s < 0 ) l = m - 1;     // move left
        else return r;		        // found exact
    }

    // close match?
    if( l >= 0 && l < hdr->n_recs ){
        const MMDFile_Rec *r = get_rec(l);	// block on the left
        int masklen = r->masklen;

        // does the found block contain the target?
        // only a loose check, better to have a bad answer than none at all
        if( r->addr[0] != addr[0] ) return 0;
        if( masklen >= 16 && r->addr[1] != addr[1] ) return 0;
        if( addr_size > 4 ){
            // ipv6:
            if( masklen >= 24 && r->addr[2] != addr[2] ) return 0;
            if( masklen >= 32 && r->addr[3] != addr[3] ) return 0;
        }
        return r;
    }

    return 0;   // not found
}
