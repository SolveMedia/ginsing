/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:11 (EST)
  Function: info from config file
*/

#ifndef __acdns_config_h_
#define __acdns_config_h_

#include <stdint.h>

#include <list>
#include <string>
using std::list;
using std::string;


struct sockaddr;

struct ACL {
    uint32_t	ipv4;
    uint32_t	mask;
};

struct ZoneConf {
    string	zone;
    string	file;
};


typedef list<struct ACL*> ACL_List;
typedef list<struct ZoneConf *>  Zone_List;

class Config {
public:
    int 	udp_threads;
    int 	tcp_threads;
    int 	port_console;
    int 	port_dns;
    int 	debuglevel;
    float	logpercent;
    char 	debugflags[256/8];
    char 	traceflags[256/8];

    string	datafile_ipv4;
    string	datafile_ipv6;
    string 	environment;
    ACL_List	acls;
    Zone_List	zones;
    string	error_mailto;
    string	error_mailfrom;
    string	mon_path;
    string	logfile;

    int check_acl(const sockaddr *);
    bool debug_is_set(int s) const { return debugflags[ s / 8 ] & (1<<(s&7)); }
    bool trace_is_set(int s) const { return traceflags[ s / 8 ] & (1<<(s&7)); }
protected:
    Config();
    ~Config();

    friend int read_config(const char*);
};

extern Config *config;

extern int read_config(const char *);

#endif // __acdns_config_h_

