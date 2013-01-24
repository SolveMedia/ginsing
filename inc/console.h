/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-10 16:07 (EST)
  Function: 
*/

#ifndef __acdns_console_h_
#define __acdns_console_h_

#include "lock.h"

#include <string>
#include <vector>
using std::string;
using std::vector;

extern void console_init(void);

typedef vector<string> cmd_args;

class Console {
private:
    Mutex	_mutex;
    int		_loglevel;
    bool    	_onlogq;
    int       	_fd;

public:
    string      prompt;
    int         y2_b;

    Console(int);
    ~Console();

    void        set_loglevel(int l);
    void        output(const string *s);
    void	output(const char *);
    static void broadcast(int, const char *, int);


private:
    DISALLOW_COPY(Console);
};




#endif // __acdns_console_h_
