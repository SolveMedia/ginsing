/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 21:09 (EST)
  Function: 
*/

#ifndef __acdns_runmode_h_
#define __acdns_runmode_h_

#include "hrtime.h"


#define RUN_MODE_RUN		0
#define RUN_MODE_WINDDOWN	1
#define RUN_MODE_EXITING	2
#define RUN_MODE_ERRORED	3
#define RUN_LOLA_RUN		RUN_MODE_RUN

#define WINDDOWN_TIME      	60

#define EXIT_NORMAL_EXIT	0
#define EXIT_NORMAL_RESTART	1
#define EXIT_ERROR_RESTART	2

class RunMode {

    int    _run_mode;
    time_t _winddown_until;
    int    _final_exit_value;


public:
    RunMode(){
        _run_mode         = RUN_LOLA_RUN;
        _winddown_until   = 0;
        _final_exit_value = EXIT_NORMAL_EXIT;
    }

    void shutdown(int restart=0) {
        _final_exit_value = restart;
	_run_mode         = RUN_MODE_EXITING;
    }
    void winddown(int restart=0) {
        _final_exit_value = restart;
        _winddown_until   = lr_now() + WINDDOWN_TIME;
	_run_mode         = RUN_MODE_WINDDOWN;
    }

    void errored() {
	_run_mode         = RUN_MODE_ERRORED;
    }

    void cancel() { _run_mode = RUN_MODE_RUN; }

    void shutdown_and_restart() { shutdown(EXIT_NORMAL_RESTART); }
    void winddown_and_restart() { winddown(EXIT_NORMAL_RESTART); }

    void wounddown() { _run_mode = RUN_MODE_EXITING; }

    volatile int mode() { return _run_mode; }
    volatile int final_exit_value() { return _final_exit_value; }
    volatile int winddown_until() { return _winddown_until; }
};

extern RunMode runmode;

inline int
current_runmode(void){
    return runmode.mode();
}

#endif // __acdns_runmode_h_
