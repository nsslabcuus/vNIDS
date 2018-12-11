/*************************************************************************
> File Name: listener.c
> Author:   Hongda Li  
> Created Time: Mon 13 Jul 2015 02:59:35 PM MDT

    Compile :   gcc listen.c -lpcap [-o output]
    
*************************************************************************/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <time.h>
struct timespec ts={0,0}, td={0,0};

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{

    static int flag = 0;
    long long ds = 0;
    long long dus = 0;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(stdout, "%lld.%lld\n", (long long)ts.tv_sec,(long long)ts.tv_nsec);
    fflush(stdout);
    
#if 0
    if ( 0 == flag ) {
        clock_gettime(CLOCK_REALTIME, &ts);
        flag = 1;
    } else {
        clock_gettime(CLOCK_REALTIME, &td);
        flag = 0;
        ds = (td.tv_sec - ts.tv_sec) * 100000000;
        dus = td.tv_nsec / 10  - ts.tv_nsec / 10;
        fprintf(stdout, "%lld\n",ds+dus);
        fflush(stdout);
    }
#endif
}

int main(int argc,char **argv)
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    /* At least two arguments. User should indicates the interface. */
    if( argc < 2 ) { 
        fprintf(stdout,"Usage: %s numpackets\n",argv[0]);
        return 1;
    }

    /* User should tell the name of the device */
    dev = argv[1];
    printf("Listening on device : %s \n", dev); 
    /* open device for reading */
    /* dev      :   listen on 'dev' 
     * BUFSIZ   :   maximun number of bytes to be captrued by pcap.     
     * 0        :   not in promisc mode, only listening on packets to this host. 
     * -1       :   no-zero means waitting a time before time out (in millionseconds). 
     * errbuf   :   error message if error occurs. 
     ***/
    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    if ( descr == NULL ) { 
        printf("pcap_open_live(): %s\n",errbuf); 
        exit(1); 
    }

    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)*/
    /* descr        :   device to listen to. 
     * -1           :   -1 means listen forever untill error occurs.
     * my_callback  :   function that will be called when packet is received.
     * NULL         :   point to user data, passing to my_callback function. 
     * */
    pcap_loop(descr, -1, my_callback, NULL);
    
    /* Exit successfully. */
    return 0;
}




