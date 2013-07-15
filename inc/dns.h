/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-03 13:49 (EST)
  Function: dns protocol
*/

#ifndef __acdns_dns_h_
#define __acdns_dns_h_


#define MAXNAME		255	// rfc 1035 2.3.4
#define MAXLABEL	63	// rfc 1035 2.3.4
#define MAXUDP		512	// rfc 1035 2.3.4
#define MAXUDPEXT	4224	// edns 2671, no required value. this is ~3 packets.
#define MAXTCP		65535	// rfc 1035 (max 16bit)
#define MAXZTAB		8

// extra space, so we can defer checks
#define TCPBUFSIZ	(MAXTCP + 512)
#define UDPBUFSIZ	(MAXUDPEXT + 512)

// rfc 1035 4.1.1
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


#define TYPE_A		1	// rfc 1035 3.2.2
#define TYPE_NS		2	// rfc 1035 3.2.2
#define TYPE_CNAME	5	// rfc 1035 3.2.2
#define TYPE_SOA	6	// rfc 1035 3.2.2
#define TYPE_PTR	12	// rfc 1035 3.2.2
#define TYPE_MX		15	// rfc 1035 3.2.2
#define TYPE_TXT	16	// rfc 1035 3.2.2
#define TYPE_AAAA	28	// rfc 1886 2.1
#define TYPE_OPT	41	// rfc 2671 7 (edns0)
#define TYPE_ANY	255	// rfc 1035 3.2.3

#define TYPE_ALIAS	0x10001
#define TYPE_GLB_RR	0x20001
#define TYPE_GLB_GEO	0x20002
#define TYPE_GLB_MM	0x20003
#define TYPE_GLB_Hash	0x20004

#define TYPE_COMPAT_MASK	0x1FFFF


#define CLASS_IN	1	// rfc 1035 3.2.4
#define CLASS_CH	3	// rfc 1035 3.2.4
#define CLASS_ANY	255	// rfc 1035 3.2.5


#define FLAG_QUERY	0	// rfc 1035 4.1.1
#define FLAG_RESPONSE	0x8000	// rfc 1035 4.1.1

#define OPCODE_QUERY	0	// rfc 1035 4.1.1
#define OPCODE_STATUS	2	// rfc 1035 4.1.1
#define OPCODE_SHIFT    11
#define OPCODE_MASK     0xf

#define FLAG_AA		0x400	// rfc 1035 4.1.1
#define FLAG_TC		0x200	// rfc 1035 4.1.1
#define FLAG_RD		0x100	// rfc 1035 4.1.1
#define FLAG_RA		0x80	// rfc 1035 4.1.1

#define RCODE_OK	0	// rfc 1035 4.1.1
#define RCODE_FORMAT	1	// rfc 1035 4.1.1
#define RCODE_IFAIL	2	// rfc 1035 4.1.1
#define RCODE_NX	3	// rfc 1035 4.1.1
#define RCODE_NOTIMP	4	// rfc 1035 4.1.1
#define RCODE_REFUSED	5	// rfc 1035 4.1.1
#define RCODE_SHIFT	0
#define RCODE_MASK      0xf

#define EDNS_OPT_CLIENTSUBNET		8	// official number. http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
#define EDNS_OPT_CLIENTSUBNET_EXP	0x50FA	// experimental.    draft-vandergaast-edns-client-subnet
#define EDNS_OPT_NSID			3	// rfc 5001

class DNS_Hdr {		// rfc 1035 4.1.1
public:
    uint16_t	id;
    uint16_t	flags;
    uint16_t	qdcount;
    uint16_t	ancount;
    uint16_t	nscount;
    uint16_t	arcount;
};

// 1035 3.2
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


struct DNS_RR_Hdr {
    uint16_t		type;
    uint16_t		klass;
    uint32_t		ttl;
    uint16_t		rdlength;
    char		rdata[0];
};
// compiler wants to pad this, don't use sizeof
#define DNS_RR_HDR_SIZE	10


struct DNS_OPT_RR_Hdr {
    uint16_t		type;
    uint16_t		udpsize;
    uint8_t		ercode;
    uint8_t		version;
    uint16_t		z;
    uint16_t		rdlength;
    char		rdata[0];
};



class NTD;
extern int dns_process(NTD *);

#endif // __acdns_dns_h_
