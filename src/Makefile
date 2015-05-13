# Copyright (c) 2013
# Author: Jeff Weisberg <jaw @ solvemedia.com>
# Created: 2013-Jan-04 10:29 (EST)


OBJS =  lock.o diag.o config.o daemon.o thread.o network.o dns.o version.o rr.o \
	zdb.o zonefile.o console.o conscmd.o glb.o mmd.o mon_t.o mon_b.o maint.o \
	log.o main.o

CC=gcc
CCC=g++
LOCALDIR=/usr/local/m64
FLAGS=-march=opteron -mtune=opteron -m64
MYNAME=ginsing

CFLAGS = -g $(FLAGS) -O3 -ffast-math -pthreads -I`pwd`/../inc -I$(LOCALDIR)/include -DMYNAME=\"$(MYNAME)\"
CCFLAGS=$(CFLAGS)
CXXFLAGS=$(CFLAGS)


# solaris:
LDFLAGS = -L$(LOCALDIR)/lib -lpthread -lrt -lsocket -lnsl -lmtmalloc

# netbsd + linux:
# LDFLAGS = -L$(LOCALDIR)/lib -lpthread


all: $(MYNAME)d

$(MYNAME)d: $(OBJS)
	$(CCC) -o $(MYNAME)d $(CFLAGS) $(OBJS) $(LDFLAGS)

install:
	-mv ../../../bin/$(MYNAME)d ../../../bin/$(MYNAME)d-
	cp $(MYNAME)d ../../../bin/

clean:
	rm -f $(OBJS) $(MYNAME)d ../inc/stats_defs.h ../inc/stats_mib.h


../inc/stats_defs.h: ../tools/mk-stats
	perl ../tools/mk-stats ../inc/stats_defs.h ../inc/stats_mib.h ../inc/stats_cmd.h

depend:
	makedepend -Y -I../inc *.cc


# DO NOT DELETE

config.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/misc.h
config.o: ../inc/zdb.h ../inc/dns.h ../inc/mon.h ../inc/hrtime.h
conscmd.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/hrtime.h
conscmd.o: ../inc/thread.h ../inc/config.h ../inc/console.h ../inc/lock.h
conscmd.o: ../inc/network.h ../inc/dns.h ../inc/mmd.h ../inc/stats_defs.h
conscmd.o: ../inc/runmode.h ../inc/maint.h ../inc/zdb.h ../inc/mon.h
conscmd.o: ../inc/stats_cmd.h
console.o: ../inc/defs.h ../inc/diag.h ../inc/thread.h ../inc/config.h
console.o: ../inc/console.h ../inc/lock.h ../inc/network.h ../inc/dns.h
console.o: ../inc/mmd.h ../inc/stats_defs.h ../inc/runmode.h ../inc/hrtime.h
daemon.o: ../inc/defs.h ../inc/diag.h ../inc/hrtime.h ../inc/runmode.h
diag.o: ../inc/defs.h ../inc/diag.h ../inc/misc.h ../inc/config.h
diag.o: ../inc/hrtime.h ../inc/thread.h ../inc/runmode.h ../inc/console.h
diag.o: ../inc/lock.h
dns.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h
dns.o: ../inc/lock.h ../inc/hrtime.h ../inc/network.h ../inc/dns.h
dns.o: ../inc/mmd.h ../inc/stats_defs.h ../inc/runmode.h ../inc/zdb.h
dns.o: ../inc/mon.h ../inc/version.h ../inc/stats_mib.h
glb.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h
glb.o: ../inc/lock.h ../inc/hrtime.h ../inc/network.h ../inc/dns.h
glb.o: ../inc/mmd.h ../inc/stats_defs.h ../inc/maint.h ../inc/zdb.h
glb.o: ../inc/mon.h
lock.o: ../inc/defs.h ../inc/thread.h ../inc/lock.h
log.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h
log.o: ../inc/lock.h ../inc/hrtime.h ../inc/network.h ../inc/dns.h
log.o: ../inc/mmd.h ../inc/stats_defs.h ../inc/runmode.h ../inc/zdb.h
log.o: ../inc/mon.h ../inc/version.h
main.o: ../inc/defs.h ../inc/diag.h ../inc/daemon.h ../inc/config.h
main.o: ../inc/hrtime.h ../inc/thread.h ../inc/runmode.h ../inc/zdb.h
main.o: ../inc/dns.h ../inc/mon.h
maint.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h
maint.o: ../inc/lock.h ../inc/hrtime.h ../inc/maint.h ../inc/zdb.h
maint.o: ../inc/dns.h ../inc/mon.h ../inc/mmd.h
mmd.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h ../inc/mmd.h
mmd.o: ../inc/network.h ../inc/dns.h ../inc/stats_defs.h ../inc/thread.h
mmd.o: ../inc/maint.h
mon_b.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h
mon_b.o: ../inc/lock.h ../inc/hrtime.h ../inc/daemon.h ../inc/runmode.h
mon_b.o: ../inc/thread.h ../inc/zdb.h ../inc/dns.h ../inc/mon.h
mon_t.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h
mon_t.o: ../inc/lock.h ../inc/hrtime.h ../inc/runmode.h ../inc/thread.h
mon_t.o: ../inc/mon.h
network.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/thread.h
network.o: ../inc/config.h ../inc/lock.h ../inc/hrtime.h ../inc/network.h
network.o: ../inc/dns.h ../inc/mmd.h ../inc/stats_defs.h ../inc/runmode.h
rr.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h ../inc/lock.h
rr.o: ../inc/hrtime.h ../inc/network.h ../inc/dns.h ../inc/mmd.h
rr.o: ../inc/stats_defs.h ../inc/zdb.h ../inc/mon.h
thread.o: ../inc/defs.h ../inc/diag.h ../inc/config.h ../inc/thread.h
zdb.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h ../inc/dns.h
zdb.o: ../inc/zdb.h ../inc/mon.h ../inc/hrtime.h ../inc/version.h
zonefile.o: ../inc/defs.h ../inc/misc.h ../inc/diag.h ../inc/config.h
zonefile.o: ../inc/dns.h ../inc/zdb.h ../inc/mon.h ../inc/hrtime.h
zonefile.o: ../inc/mmd.h ../inc/version.h
