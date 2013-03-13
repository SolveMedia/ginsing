/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-14 15:54 (EST)
  Function: mapping metrics data
*/

#ifndef __acdns_mmd_h_
#define __acdns_mmd_h_

#define MAXMMELEM	64

#define MMDDATAMAGIC    0x41436d46
#define MMDDATAVERSION	1

class NTD;
typedef unsigned char uchar;

// on disk:
// datafile : header (+ space) + datacenters (+ space) + data
class MMDFile_Hdr {
public:
    uint32_t		magic;
    uint32_t		version;

    int32_t		ipver;
    int32_t		rec_size;

    int64_t		datacenter_start;
    int64_t		n_datacenter;

    int64_t		recs_start;
    int64_t		n_recs;

};

class MMDFile_Rec {
public:
    uchar		addr[8];	// ipv4/32 0-padded or ipv6/64
    int16_t		masklen;
    uint16_t		flags;
    int32_t		metric[0];	// ...

#  define MMDFREC_FLAG_UNKNOWN	1	// location unknown

};

//################################################################

// in mem:
class MMDB_File {

    void		*map_start;
    int64_t       	map_size;
    int64_t       	file_size;
    int			addr_size;
    int			rec_size;
    time_t		file_mtime;
    int64_t		file_inum;

    MMDFile_Hdr		*hdr;
    MMDFile_Rec		*rec;

    const char		*dc[MAXMMELEM];

    const MMDFile_Rec* best_rec(const uchar*) const;
    inline const MMDFile_Rec* get_rec(int n) const {
        return (MMDFile_Rec*) ((char*)rec + n * rec_size);
    }

public:
    MMDB_File() {
        map_start = 0; map_size = 0; file_size = 0; hdr = 0; rec = 0;
        for(int i=0; i<MAXMMELEM; i++) dc[i] = 0;
    }
    ~MMDB_File();
    int  load(const char *);
    bool file_changed(const char *)     const;
    int  locate(NTD *, const uchar *)   const;
    bool datacenter_valid(const char *) const;
};


class MMDB {
    MMDB_File		*ipv4;
    MMDB_File		*ipv6;

public:
    MMDB(){ ipv4 = 0; ipv6 = 0; }

    int load_ipv4(void);
    int load_ipv6(void);
    int maybe_load_ipv4(void);
    int maybe_load_ipv6(void);
    static int locate(NTD *);
    static bool datacenter_valid(const char *);
};

//################################################################

// in NTD:
class MMElem {
public:
    const char		*datacenter;
    int			metric;

    bool operator<(const MMElem& b) const { return metric < b.metric; }
};

class MMD {
public:
    uint32_t		logflags;
#	define GLBMM_F_NOLOC	1
#	define GLBMM_F_FAIL	2
#	define GLBMM_F_FAILFAIL	4

    int 		nelem;
    MMElem		mm[MAXMMELEM];

    MMD();
};



#endif // __acdns_mmd_h_

