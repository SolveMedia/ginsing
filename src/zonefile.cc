/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-07 11:29 (EST)
  Function: read zone file
*/

#define CURRENT_SUBSYSTEM	'z'

#include "defs.h"
#include "misc.h"
#include "diag.h"
#include "config.h"
#include "dns.h"
#include "zdb.h"
#include "mmd.h"
#include "mon.h"
#include "version.h"

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

//################################################################

class InputF {
public:
    FILE 	*f;
    string 	*name;
    int 	line;

    InputF(string *n, FILE *fp){ name = n; f = fp; line = 0; }
    int inline nextc(){
        int c = getc(f);
        if( c == '\n' ) line ++;
        return c;
    }
    void problem(const char *msg) const {
        PROBLEM("ERROR file %s line %d: %s", name->c_str(), line, msg);
    }
};

// ################################################################

int
load_zdb(){
    ZDB *z;

    z = new ZDB;

    // load zones
    Zone_List::iterator final = config->zones.end(), it;

    for(it=config->zones.begin(); it != final; it++){
	ZoneConf *zc = *it;
        int ok = z->load(& zc->zone, & zc->file);

        if( !ok ){
            PROBLEM("error loading zone %s from %s - aborting load", zc->zone.c_str(), zc->file.c_str());
            delete z;
            return 0;
        }

        VERBOSE("loaded zone %s", zc->zone.c_str());
    }

    if( ! z->analyze() ){
        PROBLEM("error loading zones");
        delete z;
        return 0;
    }

    // replace old db
    ZDB *old = zdb;
    ATOMIC_SETPTR( zdb, z );

    mon_restart();

    if( old ){
        sleep(2);
        delete old;
    }

    return 1;
}


int
ZDB::load(string *zonename, string *file){

    DEBUG("loading zone %s from %s", zonename->c_str(), file->c_str());

    // open file
    FILE *f = fopen(file->c_str(), "r");
    if( !f ){
        PROBLEM("cannot open zone file %s", file->c_str());
        return 0;
    }

    InputF ff(file, f);
    Zone *z = new Zone(zonename, file);
    int ok = z->load(this, &ff);

    fclose(f);

    if( !ok ){
        delete z;
        return 0;
    }

    zone.push_back(z);

    return 1;
}


// 1 = ok, 0 = eof, -1 = uhoh
static int
get_line(InputF *f, string *line){
    int parens   = 0;
    int allspace = 1;
    int prev     = 0;

    line->clear();

    while(1){
        int c = f->nextc();
    redo:
        if( c == -1 ){
            if( !line->empty() ){
                f->problem("unexpected eof");
                return -1;
            }
            return 0;
        }
        if( c == ';' ){
            // eat to end of line
            while( c != '\n' && c != -1 ) c = f->nextc();
            goto redo;
        }
        if( c == '"' ){
            // XXX - handle \"
            // until "
            do {
                line->push_back(c);
                c = f->nextc();
            } while( c != '"' && c != -1 );
            // fall through
        }

        if( c == '(' ){
            parens ++;
            continue;
        }
        if( c == ')' ){
            if( !parens ){
                f->problem("unexpected )");
                return -1;
            }
            parens --;
            continue;
        }
        if( c == '{' ){
            parens ++;
            // fall through
        }
        if( c == '}' ){
            if( parens != 1 ){
                f->problem("unexpected }");
                return -1;
            }
            parens --;
            // fall through
        }
        if( c == '\n' ){
            if( parens ) continue;
            if( line->empty() ) continue;
            if( allspace ){
                line->clear();
                continue;
            }
            return 1;
        }

        // collapse multiple spaces
        if( prev && isspace(c) && isspace(prev) ) continue;
        if( isspace(c) ) c = ' '; // convert to spaces
        else allspace = 0;

        line->push_back(c);
        prev = c;
    }
}

static int
parse_time(InputF *f, string *line, int len, int *i){
    int val = 0;

    for( ; *i<len; (*i)++){
        int c = line->at(*i);
        if( isdigit(c) ){
            val *= 10;
            val += c - '0';
            continue;
        }
        if( isspace(c) ) return val;

        switch(c){
        case 'G': case 'g':	val *= 1024;	// fall thru
        case 'M': case 'm':	val *= 1024;	// fall thru
        case 'K': case 'k':	val *= 1024;
            break;
        case 'W': case 'w':	val *= 7;	// fall thru
        case 'D': case 'd':	val *= 24;	// fall thru
        case 'H': case 'h':	val *= 3600;
            break;
        default:
            f->problem("invalid number");
            break;
        }
    }

    return val;
}

static int
parse_class(InputF *f, string *line, int len, int *i, int *klass){

    if( *i >= len ) return 1;

    if( ! line->compare(*i, 2, "IN") ){
        *i += 3;
        *klass = CLASS_IN;
    }

    if( ! line->compare(*i, 2, "CH") ){
        f->problem("class CH is not supported. so sorry.");
        return 0;
    }

    if( ! line->compare(*i, 2, "HS") ){
        f->problem("class HS is not supported. so sorry.");
        return 0;
    }

    return 1;
}

static const struct {
    const char *name;
    int len;
    int value;
} type_name[] = {
    { "A",	  1, TYPE_A },
    { "AAAA",	  4, TYPE_AAAA },
    { "SOA",	  3, TYPE_SOA },
    { "NS",	  2, TYPE_NS },
    { "CNAME",	  5, TYPE_CNAME },
    { "MX",  	  2, TYPE_MX },
    { "PTR",  	  3, TYPE_PTR },
    { "TXT",	  3, TYPE_TXT },
    { "ALIAS",    5, TYPE_ALIAS },
    { "GLB:RR",	  6, TYPE_GLB_RR },
//    { "GLB:GEO",  7, TYPE_GLB_GEO },
    { "GLB:MM",   6, TYPE_GLB_MM },
};

static int
parse_type(InputF *f, string *line, int len, int *i, int *type){

    if( *i >= len ) return 1;
    const char *tok = line->c_str() + *i;

    for(int t=0; t<ELEMENTSIN(type_name); t++){
        if( !strncmp(tok, type_name[t].name, type_name[t].len) ){
            if( *i + 1 < len && isspace(tok[type_name[t].len])){
                *i += type_name[t].len + 1;
                *type = type_name[t].value;
                return 1;
            }
        }
    }

    f->problem("unsupported record type");
    return 0;
}

static int
parse_word(InputF *f, string *src, int *pos, string *dst){

    int ew = src->find(' ', *pos);
    if( ew == -1 ){
        dst->assign( src->substr(*pos) );
        *pos = src->length();
    }else{
        dst->assign( src->substr(*pos, ew-*pos) );
        *pos = ew + 1;
    }

    return dst->length();
}

static int
parse_rest(InputF *f, string *line, int len, int *i, string *rdata, string *extra){

    if( *i >= len ) return 0;

    if( line->at(len-1) == '}' ){
        int p = line->rfind('{');
        if( p == -1 ){
            f->problem("unbalanced }");
            return 0;
        }
        rdata->assign( line->substr(*i,p-*i-1) );	// and remove the space
        extra->assign( line->substr(p) );
    }else{
        if( isspace(line->at(len-1)) )
            rdata->assign( line->substr(*i, len-*i-1) );
        else
            rdata->assign( line->substr(*i) );
        extra->clear();
    }

    return 1;
}

// LABEL TTL CLASS TYPE DATA
// values (other than data) default to previous line's values
static int
parse_line(InputF *f, string *line, /* out: */ string *label, int *ttl, int *klass, int *type, string *rdata, string *extra){

    int i=0;
    int len = line->length();

    // label
    if( !isspace(line->at(i)) ){
        label->clear();
        for( ; i<len; i++){
            if( isspace(line->at(i)) ) break;
            label->push_back( tolower(line->at(i)) );
        }

        if( label->at( label->length() - 1 ) == '.' ){
            f->problem("absolute label not supported");
            return 0;
        }
    }
    i++;
    if( i >= len ) return 0;

    // ttl
    if( isdigit(line->at(i)) ){
        *ttl = parse_time(f, line, len, &i);
        i++;
    }

    if( ! parse_class(f, line, len, &i, klass) ) return 0;
    if( ! parse_type( f, line, len, &i, type)  ) return 0;
    if( ! parse_rest( f, line, len, &i, rdata, extra)  ) return 0;

    return 1;
}

static int
parse_probe(ZDB *db, RR *rr, InputF *f, string *rdata, string *extra){
    string freqs;
    string prog;
    string args;
    int freq = 0;

    // remove "{ " + " }"
    if( extra->length() > 1 && extra->at(0) == '{' )   extra->erase(0,1);
    if( extra->length() > 1 && isspace(extra->at(0)) ) extra->erase(0,1);
    if( extra->length() > 1 && extra->at(extra->length() - 1) == '}' )   extra->erase(extra->length() - 1);
    if( extra->length() > 1 && isspace(extra->at(extra->length() - 1)) ) extra->erase(extra->length() - 1);

    int pos = 0;
    int len = extra->length();

    DEBUG("probe [%s] len %d", extra->c_str(), len);

    if( pos < len && isdigit(extra->at(pos)) ){
        if( parse_word(f, extra, &pos, &freqs) ){
            freq = atoi( freqs.c_str() );
        }
    }
    if( ! freq ){
        f->problem("invalid probe spec: expected freq");
        return 0;
    }

    if( pos >= len || ! parse_word(f, extra, &pos, &prog) ){
        f->problem("invalid probe spec: expected type");
        return 1;
    }

    // remove trailing " }"
    DEBUG("pos %d, len %d", pos, len);
    if( pos < len )
        args = extra->substr(pos, len - pos);

    DEBUG("probe %d %s, %s.", freq, prog.c_str(), args.c_str());

    rr->add_probe( new Monitor(freq, rdata, &prog, &args) );
    db->add_monitored( rr );
}

int
Zone::load(ZDB *db, InputF *f){
    string line;
    string label;
    string rdata;
    string extra;
    int ttl=-1, klass = CLASS_IN, type=-1;


    while( 1 ){
        // go line-by-line
        int glst = get_line(f, &line);
        if( !glst ) break;
        if( glst == -1 ) return 0;

        // DEBUG(">> %s", line.c_str());

        // parse line
        int plst = parse_line(f, &line, &label, &ttl, &klass, &type, &rdata, &extra);
        if( !plst ){
            f->problem("cannot parse line");
            return 0;
        }
        if( ttl == -1 ){
            f->problem("TTL not specified");
            return 0;
        }

        bool wildp = 0;

        if( label == "@" ) label = "";

        if( label[0] == '*' ){
            // convert wildcard
            wildp = 1;
            int dot = label.find('.');
            if( dot == -1 ) label = "";
            else{
                label.erase(0, dot+1);
            }
        }

        DEBUG("label: %s, ttl: %d, class: %d, type: %d, wild: %d", label.c_str(), ttl, klass, type, wildp);
        DEBUG("rdata: %s; extra: %s", rdata.c_str(), extra.c_str());

        // create rr
        RR *rr = RR::make(&label, klass, type, ttl, wildp);
        if( !rr ){
            f->problem("cannot create rr");
            return 0;
        }
        if( rr->configure(f, this, &rdata) ){
            f->problem("cannot parse rdata");
            delete rr;
            return 0;
        }

        if( extra.length() ){
            if( ! parse_probe(db, rr, f, &rdata, &extra ) )
                return 0;
        }

        if( !insert(db, rr, &label) ){
            f->problem("unable to insert RR, not compitble with RRSet");
            return 0;
        }
    }

    if( ! soa ){
        f->problem("SOA missing");
        return 0;
    }
    if( ns.empty() ){
        f->problem("no NS records");
        return 0;
    }

    // RSN - more sanity checks


    if( !analyze(db) ){
        f->problem("zone failed to properly load");
        return 0;
    }


    return 1;
}


// ################################################################

// mname rname serial refresh retry expire min
int
RR_SOA::configure(InputF *f, Zone *z, string *rspec){

    int emn = rspec->find(' ');
    if( emn == -1 ){ f->problem("invalid SOA mname"); return 1; }
    mname.set_name( rspec->substr(0, emn), &z->zonename );

    int ern = rspec->find(' ', emn+1);
    if( ern == -1 ){ f->problem("invalid SOA rname"); return 1; }
    rname.set_name( rspec->substr(emn+1, ern-emn-1), &z->zonename );

    int len = rspec->length();
    int pos = ern + 1;

    if( !isdigit(rspec->at(pos)) ){ f->problem("invalid SOA serial"); return 1; }
    serial = parse_time(f, rspec, len, &pos);
    pos ++;

    if( !isdigit(rspec->at(pos)) ){ f->problem("invalid SOA refresh"); return 1; }
    refresh = parse_time(f, rspec, len, &pos);
    pos ++;

    if( !isdigit(rspec->at(pos)) ){ f->problem("invalid SOA retry"); return 1; }
    retry = parse_time(f, rspec, len, &pos);
    pos ++;

    if( !isdigit(rspec->at(pos)) ){ f->problem("invalid SOA expire"); return 1; }
    expire = parse_time(f, rspec, len, &pos);
    pos ++;

    if( !isdigit(rspec->at(pos)) ){ f->problem("invalid SOA min"); return 1; }
    minimum = parse_time(f, rspec, len, &pos);

    return 0;
}


int
RR_MX::configure(InputF *f, Zone *z, string *rspec){

    if( !isdigit(rspec->at(0)) ){ f->problem("invalid MX pref"); return 1; }
    pref = atoi( rspec->c_str() );

    int ep = rspec->find(' ');
    if( ep == -1 ){ f->problem("invalid MX"); return 1; }

    dest.set_name( rspec->substr(ep+1), &z->zonename );

    return 0;
}

int
RR_GLB::configure(InputF *f, Zone *z, string *rspec){
    BUG("RR_GLB");
    return 1;
}

int
RR_GLB_RR::configure(InputF *f, Zone *z, string *rspec){
    string comp_name;
    string wtspec;
    int pos = 0;

    // GLB:RR  rrsetname  weight

    if( ! parse_word(f, rspec, &pos, &comp_name) ){
        f->problem("invalid GLB:RR spec. expected target name");
        return 1;
    }

    RRSet *rrs = z->find_rrset(&comp_name, 0);
    if( !rrs ){
        PROBLEM("ERROR file %s line %d: '%s' is not a known RRSet", f->name->c_str(), f->line, comp_name.c_str());
        return 1;
    }

    comp_rrset = rrs;

    if( parse_word(f, rspec, &pos, &wtspec) ){
        weight = atof( wtspec.c_str() );
    }else{
        weight = 1.0;
    }

    DEBUG("%s %x wgt %f", name.c_str(), this, weight);

    return 0;
}

int
RR_GLB_Geo::configure(InputF *f, Zone *z, string *rspec){

    return 1;
}

int
RR_GLB_Hash::configure(InputF *f, Zone *z, string *rspec){
    string comp_name;
    string wtspec;
    int pos = 0;

    // GLB:Hash  rrsetname

    if( ! parse_word(f, rspec, &pos, &comp_name) ){
        f->problem("invalid GLB:Hash spec. expected target name");
        return 1;
    }

    RRSet *rrs = z->find_rrset(&comp_name, 0);
    if( !rrs ){
        PROBLEM("ERROR file %s line %d: '%s' is not a known RRSet", f->name->c_str(), f->line, comp_name.c_str());
        return 1;
    }

    comp_rrset = rrs;

    return 0;
}

static bool
is_valid_datacenter(string *dc){

    if( ! dc->compare(":unknown") )
        return 1;
    if( ! dc->compare(":lastresort") )
        return 1;
    if( MMDB::datacenter_valid(dc->c_str()) )
        return 1;

    return 0;
}

int
RR_GLB_MM::configure(InputF *f, Zone *z, string *rspec){
    string comp_name;
    string wtspec;
    int pos = 0;

    // GLB:MM  rrsetname  datacenter  [weight]  [failover]
    // failover :: fail:nextbext, fail:rrall, fail:rrgood, datacenter, rrname

    if( ! parse_word(f, rspec, &pos, &comp_name) ){
        f->problem("invalid GLB:MM spec. expected target name");
        return 1;
    }

    RRSet *rrs = z->find_rrset(&comp_name, 0);
    if( !rrs ){
        PROBLEM("ERROR file %s line %d: '%s' is not a known RRSet", f->name->c_str(), f->line, comp_name.c_str());
        return 1;
    }

    comp_rrset = rrs;

    if( ! parse_word(f, rspec, &pos, &datacenter) ){
        f->problem("invalid GLB:MM spec. expected datacenter");
    }

    if( ! datacenter.compare(":unknown") ){
        special = 1;
    }else if( ! datacenter.compare(":lastresort") ){
        special = 1;
    }else if( ! MMDB::datacenter_valid(datacenter.c_str()) ){
        PROBLEM("ERROR file %s line %d: invalid datacenter'%s'", f->name->c_str(), f->line, datacenter.c_str());
        return 1;
    }

    if( pos < rspec->length() && isdigit(rspec->at(pos)) ){
        if( parse_word(f, rspec, &pos, &wtspec) ){
            weight = atof( wtspec.c_str() );
        }
    }else{
        weight = 1;
    }

    if( parse_word(f, rspec, &pos, &failover_name) ){
        if(! failover_name.compare(":nextbest") )
            failover_alg = GLB_FAILOVER_NEXTBEST;
        else if( ! failover_name.compare(":rrall") )
            failover_alg = GLB_FAILOVER_RRALL;
        else if( ! failover_name.compare(":rrgood") )
            failover_alg = GLB_FAILOVER_RRGOOD;
        else{
            failover_alg = GLB_FAILOVER_SPECIFY;

            RRSet *frs = z->find_rrset(&failover_name, 0);
            if( frs ){
                failover_rrset = frs;
            }else if( ! is_valid_datacenter(&failover_name) ){
                PROBLEM("ERROR file %s line %d: invalid failover '%s'",
                        f->name->c_str(), f->line, failover_name.c_str());
                return 1;
            }
        }

    }else{
        failover_name = ":nextbest";
        failover_alg  = GLB_FAILOVER_NEXTBEST;
    }

    DEBUG("glb-mm %s => %s; on fail: %s", datacenter.c_str(), comp_name.c_str(), failover_name.c_str());
    return 0;
}
