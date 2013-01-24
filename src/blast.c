/*
  Copyright (c) 2013
  Author: Jeff Weisberg <jaw @ solvemedia.com>
  Created: 2013-Jan-21 10:27 (EST)
  Function: generate test queries
*/


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


unsigned char packet[] =
    "\x12\x34\x00\x00"	/* id, flags */
    "\x00\x01\x00\x00\x00\x00\x00\x00" /* qn, an, nn, rn */
    "\x03" "www\x07" "example\x03" "com\x00" /* www.example.com */
    "\x00\x01\x00\x01" /* IN A */
    ;

void
fatal(const char *msg){

    fprintf(stderr, "%s\n", msg);
    exit(-1);
}

void
blast(const char *addr){
    struct sockaddr_in sa;

    if( ! inet_aton(addr, & sa.sin_addr) )
        fatal("invalid dst addr");

    sa.sin_family = AF_INET;
    sa.sin_port   = htons(53);

    int udp = socket(PF_INET, SOCK_DGRAM, 17);
    if( udp == -1 ){
        fatal("cannot create socket");
    }

    while(1){

        int i = sendto(udp, packet, sizeof(packet) - 1, 0, (void*)&sa, sizeof(sa));
        if( i == -1 ){
            fprintf(stderr, "send failed: %s", strerror(errno));
            sleep(1);
        }
    }
}

int
main(int argc, char**argv){
    const char *addr = "127.0.0.1";

    if( argc > 1 )
        addr = argv[1];

    blast(addr);

}

