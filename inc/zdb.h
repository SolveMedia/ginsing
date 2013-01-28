/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 12:03 (EST)
  Function: dns zone database
*/

#ifndef __acdns_zdb_h_
#define __acdns_zdb_h_

#include <string.h>
#include <string>
#include <vector>
#include <map>

#include "dns.h"
#include "mon.h"

using std::string;
using std::vector;
using std::map;

class NTD;
class RR;
class RRSet;
class Zone;
class ZDB;
class InputF;


// for map<char*>
struct CStrComp {
    bool operator() (const char* lhs, const char* rhs) const {
        return strcmp(lhs, rhs) < 0;
    }
};

typedef map<const char *, RR*, CStrComp>     MapRR;
typedef map<const char *, RRSet*, CStrComp>  MapRRSet;


class RR {
public:
    string	name;		// for debugging
    string	name_wire;	// name in wire format, without domain
    bool	wildcard;
    bool	delegation;
    int		klass;
    int		type;
    int		ttl;
    vector<RR*> additional;

    Monitor	*probe;
    bool	probe_ok;

    static RR *make(string *, int, int, int, bool);
    int set_name(string *);
    void add_probe(Monitor *p){ probe = p; }
    virtual int configure(InputF *, Zone *, string *) = 0;
    virtual void analyze(Zone *) {}			// when done loading the zone
    virtual void wire_up(ZDB*, Zone*, RRSet*) {}	// when done loading all the zones

    virtual int add_answer(NTD*, bool, int, int) const;
    int add_additnl(NTD*)              const;
    int add_add_ans(NTD*, int, int)    const;
    int put_name(NTD*, bool)           const;
    int put_rr(NTD*, bool)             const;
    virtual int _put_rr(NTD*)          const = 0;
    bool probe_looks_good()            const { return probe_ok; }
    inline bool can_satisfy(int t)     const {
        return t==type || t==TYPE_ANY || type==TYPE_CNAME || type==TYPE_ALIAS;
    }

    virtual ~RR() {
        if( probe ) delete probe;
    };

protected:
    RR(){
        wildcard   = 0;
        delegation = 0;
        klass      = 0;
        type       = 0;
        ttl        = 0;
        probe_ok   = 1;
        probe      = 0;
    }
};

//################################################################

// insert the data as-is, no compression
class RR_Raw : public RR {
protected:
    string		rrdata;		// includes DNS_RR_Hdr

    ~RR_Raw() {}
    void config_raw();

    int _put_rr(NTD* ntd) const;
};

//################################################################

class RR_A    : public RR_Raw {
public:
    int configure(InputF *, Zone *, string *);
};
class RR_AAAA : public RR_Raw {
public:
    int configure(InputF *, Zone *, string *);
};
class RR_TXT  : public RR_Raw {
public:
    int configure(InputF *, Zone *, string *);
};



//################################################################

class RRCompString {
public:
    bool	same_zone;
    string	fqdn;
    string	name;
    string	domain;
    string	name_wire;
    string	dom_wire;

    void set_name(string s, string *);
    int wire_len(NTD*) const;
    int put(NTD*)      const;
};

class RR_Compress : public RR {
protected:
    RRCompString	rrdata;
    void		analyze(Zone*);
protected:
    ~RR_Compress() {}
    int _put_rr(NTD* ntd) const;

public:
    int configure(InputF *, Zone *, string *);
};

class RR_PTR   : public RR_Compress { };
class RR_CNAME : public RR_Compress { };
class RR_NS    : public RR_Compress { };

//################################################################

class RR_MX    : public RR {
    int			pref;
    RRCompString	dest;

protected:
    ~RR_MX() {};
    int _put_rr(NTD* ntd) const;
    void analyze(Zone*);
public:
    int configure(InputF *, Zone *, string *);
};
class RR_SOA   : public RR {

    RRCompString	mname;
    RRCompString	rname;
    uint32_t		serial;
    uint32_t		refresh;
    uint32_t		retry;
    uint32_t		expire;
    uint32_t		minimum;

protected:
    ~RR_SOA() {}
    int _put_rr(NTD* ntd) const;
public:
    int configure(InputF *, Zone *, string *);
};

class RR_Alias : public RR {
    string		target;
    RRSet		*targ_rrs;
protected:
    ~RR_Alias() {};
    int add_answer(NTD*, bool, int, int) const;
    void wire_up(ZDB*, Zone*, RRSet *);
    int _put_rr(NTD*) const {}
public:
    RR_Alias(){ targ_rrs = 0; }
    int configure(InputF *, Zone *, string *);
};

//################################################################

class RR_GLB : public RR {
protected:
    RRSet		*comp_rrset;
    float		weight;
    bool		special;

    RR_GLB(){ comp_rrset = 0; weight = 1.0; special = 0; }
    ~RR_GLB() {}
protected:
    int _put_rr(NTD*) const {}
public:
    int configure(InputF *, Zone *, string *);
};

class RR_GLB_RR   : public RR_GLB {
    friend class RRSet_GLB_RR;

protected:
    ~RR_GLB_RR() {}
public:
    int configure(InputF *, Zone *, string *);
};

class RR_GLB_Hash   : public RR_GLB {
    friend class RRSet_GLB_Hash;

protected:
    ~RR_GLB_Hash() {}
public:
    int configure(InputF *, Zone *, string *);
};

#  define GLB_FAILOVER_SPECIFY	0
#  define GLB_FAILOVER_RRALL	1
#  define GLB_FAILOVER_RRGOOD	2
#  define GLB_FAILOVER_NEXTBEST	3


class RR_GLB_Geo  : public RR_GLB {
    friend class RRSet_GLB_Geo;

    float		geo_lat;
    float		geo_lon;
    string		failover_name;
    int			failover_alg;
    RRSet		*failover_rrset;

protected:
    ~RR_GLB_Geo() {}
public:
    int configure(InputF *, Zone *, string *);
};

class RR_GLB_MM  : public RR_GLB {
    friend class RRSet_GLB_MM;

    string		datacenter;
    string		failover_name;
    int			failover_alg;
    RRSet		*failover_rrset;

protected:
    ~RR_GLB_MM() {  }
public:
    RR_GLB_MM()  { failover_rrset = 0; }
    int configure(InputF *, Zone *, string *);
    bool datacenter_looks_good() const;

};



//################################################################

class RRSet {
public:
    vector<RR*>			rr;
    bool			wildcard;
    bool			delegation;
    string			name;		// for searching
    string			fqdn;		// for searching
    Zone *			zone;

    virtual ~RRSet();
    virtual void add_rr(RR *);
    virtual int analyze(Zone*);
    void wire_up(ZDB*, Zone *);
    bool wildmatch(const char *, int)       const;
    virtual int add_answers(NTD*, int, int) const;
    virtual int add_additnl(NTD*, int, int) const;
    virtual bool is_compat(RR*)             const;

    static RRSet *make(Zone* z, string *l, bool wp, int ty);

protected:
    RRSet(Zone* z, string *l, bool wp);
};

//################################################################

class RRSet_GLB : public RRSet {
protected:

public:
    RRSet_GLB(Zone* z, string *l, bool wp) : RRSet(z,l,wp) {}
    int add_additnl(NTD*, int, int) const {}
};

class RRSet_GLB_RR : public RRSet_GLB {
protected:

public:
    RRSet_GLB_RR(Zone* z, string *l, bool wp) : RRSet_GLB(z,l,wp) {}
    bool is_compat(RR*)             const;
    int add_answers(NTD*, int, int) const;
};

class RRSet_GLB_Hash : public RRSet_GLB {
protected:

public:
    RRSet_GLB_Hash(Zone* z, string *l, bool wp) : RRSet_GLB(z,l,wp) {}
    bool is_compat(RR*)             const;
};

class RRSet_GLB_Geo : public RRSet_GLB {
protected:

public:
    RRSet_GLB_Geo(Zone* z, string *l, bool wp) : RRSet_GLB(z,l,wp) {}
    bool is_compat(RR*)       	    const;
};

class RRSet_GLB_MM : public RRSet_GLB {
protected:
    MapRR		dcrr;

    const RR_GLB_MM *find(const char *)                        const;
    void weight_and_sort(NTD *)                                const;
    int add_answers_first_match(NTD *, int)                    const;
    int add_answers_failover(const RR_GLB_MM *, NTD *, int)    const;
    int a_a_failover_nextbest(const RR_GLB_MM *, NTD *, int)   const;
    int a_a_failover_rrall(const RR_GLB_MM *, NTD *, int)      const;
    int a_a_failover_rrgood(const RR_GLB_MM *, NTD *, int)     const;
    int a_a_failover_specify(const RR_GLB_MM *, NTD *, int)    const;
    int a_a_failover_specify(const char *, NTD *, int)         const;
public:
    void add_rr(RR *);
    RRSet_GLB_MM(Zone* z, string *l, bool wp) : RRSet_GLB(z,l,wp) {}
    bool is_compat(RR*)                                        const;
    int add_answers(NTD*, int, int)                            const;

};

//################################################################

class Zone {
    friend class ZDB;
    friend class RRSet;
public:
    string			zonename;	// fqdn with training .
    string			zonefile;
private:
    vector<RRSet*>		rrset;

    // quick access to often needed zone data
    vector<RR*>			ns;		// NS records
    RR*				soa;		// SOA

    Zone(string *z, string *f){ soa = 0; zonename = *z + "."; zonefile = *f; }
    ~Zone();
    int load(ZDB*, InputF*);
    int insert(ZDB *, RR*, string *);
    int analyze(ZDB*);
    bool zonematch(const char *, int)      const;
    void wire_up(ZDB*);

public:
    RRSet *find_rrset(string *, bool wild) const;
    int add_ns_auth(NTD*)                  const;
    int add_ns_addl(NTD*)                  const;
    int add_soa_auth(NTD *)                const;
};

//################################################################

class ZDB {
    vector<Zone*>		zone;
    vector<RRSet*>		wildcard;
    MapRRSet			rrset;
public:
    vector<RR*>			monitored;

public:
    ~ZDB();
    int load(string*, string *);
    RRSet *find_rrset(const char *)       const;
    Zone  *find_zone(const char *)        const;
    int insert(RRSet *);
    int analyze();
    void add_monitored(RR*);
};

extern ZDB *zdb;
extern int load_zdb(void);



#endif // __acdns_zdb_h_
