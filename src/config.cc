/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:14 (EST)
  Function: info from config file
*/

#define CURRENT_SUBSYSTEM	'c'

#include "defs.h"
#include "diag.h"
#include "config.h"
#include "misc.h"
#include "zdb.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

Config *config = 0;

#define SET_STR_VAL(p)	\
static int set_##p (Config *cf, string *v){	\
    if(v){					\
	cf->p.assign( *v );			\
    }						\
    return 0;					\
}

#define ADD_STR_VAL(p)	\
static int add_##p (Config *cf, string *v){	\
    if(v){					\
	cf->p.push_back( *v );			\
    }						\
    return 0;					\
}

#define SET_INT_VAL(p)	\
static int set_##p (Config *cf, string *v){		\
    if( v ){						\
        cf->p = atoi( v->c_str() );			\
    }else{						\
	cf->p = 0;					\
    }							\
    return 0;						\
}
#define SET_FLOAT_VAL(p)	\
static int set_##p (Config *cf, string *v){		\
    if( v ){						\
        cf->p = atof( v->c_str() );			\
    }else{						\
	cf->p = 0;					\
    }							\
    return 0;						\
}


static int set_port(Config *, string *);
static int set_console(Config *, string *);
static int set_dbglvl(Config *, string *);
static int set_debug(Config *, string *);
static int set_trace(Config *, string *);
static int add_acl(Config *, string *);
static int add_zone(Config *, string *);

SET_INT_VAL(udp_threads);
SET_INT_VAL(tcp_threads);
SET_INT_VAL(port_dns);
SET_INT_VAL(port_console);
SET_INT_VAL(debuglevel);
SET_FLOAT_VAL(logpercent);

SET_STR_VAL(environment);
SET_STR_VAL(mon_path);
SET_STR_VAL(datafile_ipv4);
SET_STR_VAL(datafile_ipv6);
SET_STR_VAL(error_mailto);
SET_STR_VAL(error_mailfrom);
SET_STR_VAL(logfile);

static struct {
    const char *word;
    int (*fnc)(Config *, string *);
} confmap[] = {
    { "udp_threads",	set_udp_threads    },
    { "tcp_threads",	set_tcp_threads    },
    { "port",           set_port_dns     },
    { "logfile",	set_logfile        },
    { "logpercent",	set_logpercent     },
    { "console",        set_port_console   },
    { "environment",    set_environment    },
    { "monpath",        set_mon_path       },
    { "ipv4data",	set_datafile_ipv4  },
    { "ipv6data",	set_datafile_ipv6  },
    { "debug",          set_debug          },
    { "trace",          set_trace          },
    { "debuglevel",     set_debuglevel     },
    { "error_mailto",   set_error_mailto   },
    { "error_mailfrom", set_error_mailfrom },
    { "allow",		add_acl     	   },
    { "zone",           add_zone           },

    // ...
};

static struct {
    const char *name;
    int  value;
} debugname[] = {
    { "config",    'c' },
    { "network",   'N' },
    { "console",   'C' },
    { "thread",    'T' },
    { "daemon",    'd' },
    { "dns",       'D' },
    { "glb",       'g' },
    { "mmdb",	   'm' },
    { "zdb",       'Z' },
    { "zonefile",  'z' },
    { "mon",       'M' },
    { "logfile",   'L' },
    // ...
};


static void
store_value(Config *cf, string *k, string *v){
    int i, l;

    DEBUG("store value %s => %s", k->c_str(), v?v->c_str():"");

    // search table
    l = sizeof(confmap) / sizeof(confmap[0]);
    for(i=0; i<l; i++){
	if( !k->compare( confmap[i].word ) ){
	    confmap[i].fnc(cf, v);
	    return;
	}
    }

    if( config ){
        PROBLEM("invalid entry in config file '%s'", k->c_str());
    }else{
        FATAL("invalid entry in config file '%s'", k->c_str());
    }
}


static int
read_token(FILE *f, string *k, int spacep){
    int c;

    k->clear();

    while(1){
	c = fgetc(f);
	if(c == EOF) return -1;
	if(c == '#'){
	    // eat til eol
	    while(1){
		c = fgetc(f);
		if(c == EOF)  return -1;
		if(c == '\n') break;
	    }
	    if( k->length() ) return 0;
	    continue;
	}
	if(c == '\n'){
	    if( k->length() ) return 0;
	    continue;
	}
	if( !spacep && isspace(c) ){
	    if( k->length() ) return 1;
	    continue;
	}
	// skip leading space
	if( spacep && isspace(c) && ! k->length() ) continue;


	k->append(1,c);
    }
}

int
read_config(const char *filename){
    FILE *f;
    Config *cf;
    int i;
    string k, v;
    int rt = 0;

    f = fopen(filename, "r");
    if(!f){
        if( config ){
            PROBLEM("cannot open file '%s': %s", filename, strerror(errno));
        }else{
            FATAL("cannot open file '%s': %s", filename, strerror(errno));
        }
    }

    cf = new Config;

    while(1){
	i = read_token(f, &k, 0);
	if(i == -1) break;	// eof
	if(i == 0){
	    store_value(cf, &k, 0);
	    continue;
	}
	i = read_token(f, &v, 1);
	store_value(cf, &k, &v);
	if(i == -1) break;	// eof
    }

    fclose(f);
    Config *old = config;
    ATOMIC_SETPTR( config, cf );

    if( old ){
        sleep(2);
        delete old;
    }

    return 0;
}

//################################################################

static int
debug_name_to_val(const string *name){

    int l = ELEMENTSIN(debugname);
    for(int i=0; i<l; i++){
	if( !name->compare( debugname[i].name ) ){
	    return debugname[i].value;
	}
    }

    PROBLEM("invalid debug flag '%s'", name->c_str());
    return 0;
}

static int
set_debug(Config *cf, string *v){

    if(!v) return 0;

    int c = debug_name_to_val( v );
    if( c ){
	cf->debugflags[ c/8 ] |= 1 << (c&7);
        debug_enabled = 1;
    }
    return 0;
}

static int
set_trace(Config *cf, string *v){

    if(!v) return 0;

    int c = debug_name_to_val( v );
    if( c )
	cf->traceflags[ c/8 ] |= 1 << (c&7);

    return 0;
}

// addr
// addr/mask
static int
add_acl(Config *cf, string *v){
    char addr[32];
    int mlen = 32;
    int p = 0;

    // parse addr
    while( p < v->length() ){
	int c = v->at(p);
	if( c == '/' || isspace(c) ) break;
	addr[p] = c;
	addr[++p] = 0;
    }

    // parse masklen
    p ++;	// skip /
    if( p < v->length() ){
	mlen = atoi( v->c_str() + p );
    }

    // add to list
    struct ACL *acl = new struct ACL;
    struct in_addr a;

    inet_aton(addr, &a);
    acl->mask = ntohl(0xFFFFFFFF << (32 - mlen));
    acl->ipv4 = a.s_addr & acl->mask;
    cf->acls.push_back( acl );

    DEBUG("acl %s mask %d => %x + %x", addr, mlen, acl->ipv4, acl->mask);

    return 0;
}

static int
add_zone(Config *cf, string *v){

    int fstart = v->rfind(' ');
    int ftabs  = v->rfind('\t');
    if( ftabs > fstart && ftabs != -1 ) fstart = ftabs;
    int zend   = v->find(' ');
    int ztabs  = v->find('\t');

    if( ztabs < zend && ztabs != -1 || zend == -1 ) zend = ztabs;

    if( fstart == -1 || zend == -1 ){
        if( config ){
            PROBLEM("invalid zone config: %s", v->c_str());
        }else{
            FATAL("invalid zone config: %s", v->c_str());
        }
        return 0;
    }

    ZoneConf *zc = new ZoneConf;
    zc->file.assign( v->substr(fstart+1) );
    zc->zone.assign( v->substr(0, zend) );

    DEBUG(" zone [%s] file [%s]", zc->zone.c_str(), zc->file.c_str());

    cf->zones.push_back( zc );

    return 0;
}

//################################################################

static int
int_from_file(const char *file){
    FILE *f;
    int r;

    f = fopen(file, "r");
    if(!f){
        return 0;
    }

    fscanf(f, "%d", &r);
    fclose(f);

    return r;
}

//################################################################

Config::Config(){

    udp_threads  = 4;
    tcp_threads  = 4;
    port_dns     = 53;
    port_console = 5301;
    debuglevel   = 0;
    logpercent   = 0;
    environment.assign("unknown");

    memset(debugflags, 0, sizeof(debugflags));
    memset(traceflags, 0, sizeof(traceflags));

}

Config::~Config(){

    for(ACL_List::iterator it=acls.begin(); it != acls.end(); it++){
        ACL *a = *it;
        delete a;
    }
    for(Zone_List::iterator it=zones.begin(); it != zones.end(); it++){
        ZoneConf *z = *it;
        delete z;
    }
}

//################################################################

int
Config::check_acl(const sockaddr* sa) {
    sockaddr_in *in = (sockaddr_in*)sa;

    DEBUG("check acl %x", in->sin_addr.s_addr);

    if( in->sin_addr.s_addr == htonl(0x7f000001) )   return 1;	// always permit localhost

    ACL_List::iterator final = acls.end(), it;

    for(it=acls.begin(); it != final; it++){
	ACL *a = *it;

	DEBUG("check %08x == %08x + %08x == %08x",
	      a->ipv4, in->sin_addr.s_addr, a->mask, (in->sin_addr.s_addr & a->mask));

	if( a->ipv4 == (in->sin_addr.s_addr & a->mask) ) return 1;
    }

    return 0;
}

