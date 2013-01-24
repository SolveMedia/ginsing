/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-21 12:37 (EST)
  Function: service monitoring
*/

#ifndef __acdns_mon_h_
#define __acdns_mon_h_

#include "hrtime.h"
#include <string>
#include <vector>

using std::string;
using std::vector;

class Monitor {
protected:
    int            freq;
    int            fail_count;
    int            pid;
    bool           status;
    time_t         t_last;
    time_t         t_next;
    time_t         t_started;
    string         prog;
    string         address;
    int		   kills;
    vector<string> argv;
public:
    int            uid;

protected:
    void set_status(bool, int);
    void start(time_t);

public:
    Monitor(int f, string *ad, string *p, string *a);
    bool is_running() const { return pid; }
    bool too_long(time_t)   const;
    void maybe_start(time_t);
    void wait(int, time_t);
    void abort(void);
};

extern void mon_restart(void);


#endif // __acdns_mon_h_
