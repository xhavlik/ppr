// standard C libs
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdint.h>

// standard C++ libs
#include <string>
#include <vector>
#include <iostream>

// Networking libs
// https://www.devdungeon.com/content/using-libpcap-c
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// constant declarations
#define F_TYPE_REGULAR 8
#define TCP_PROTO 6
#define HTTP_PORT 80
#define ETH_LEN 14
#define PKT_SIZE 2048
#define INIT_DEVICES 20

// structure containing device information - mac address and user agent strings
typedef struct {
    uint8_t mac_addr[6];
    std::string user_agent;
} t_device;

// function declarations
int is_pcap(std::string filename);
bool mac_check(uint8_t *dev, uint8_t *pkt_mac);
t_device find_dev(std::vector<t_device> &devices, t_device dev);

/*
    === MAIN PROGRAM ===
*/

using namespace std;
int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct dirent *de;
    pcap_t *handle;
    const u_int8_t *pkt;
    struct pcap_pkthdr packet_header;
    u_int16_t pkt_cnt = 0;
    t_device dev;
    

    // open current dir by default or directory passed by absolute path
    DIR *dr = opendir("."); 

    if (dr == NULL) { 
        fprintf(stderr, "Could not open directory" ); 
        return -1;
    } 
  
    // iterate over all files in a directory and analyze pcap files
    while ((de = readdir(dr)) != NULL)  {
        if (de->d_type == F_TYPE_REGULAR && is_pcap((string)de->d_name)) {
            handle = pcap_open_offline(de->d_name, errbuf);
            printf("Analyzing %s ...\n", de->d_name);
            pkt_cnt = 0;
            vector<t_device> devs;

            while ((pkt = pcap_next(handle, &packet_header)) != NULL) {

                pkt_cnt++;
                
                // Data link layer
                struct ether_header *eth_h;
                eth_h = (struct ether_header *) pkt;
                uint8_t eth_type = ntohs(eth_h->ether_type);

                if (eth_type != IPPROTO_IP) // not an ip packet, skip
                    continue;

                // Network layer
                struct ip *ip_h;
                ip_h = (struct ip *) (pkt+ETH_LEN);
                uint8_t ip_len = ip_h->ip_hl * 4; // byte count

                if (ip_h->ip_p != TCP_PROTO) // not a tcp packet, skip
                    continue;

                // Transport layer
                struct tcphdr *tcp_h;
                tcp_h = (struct tcphdr *) (pkt+ip_len+ETH_LEN);
                uint16_t tcp_len = tcp_h->th_off * 4;
                int tcp_port = ntohs(tcp_h->th_dport);

                if (tcp_port == HTTP_PORT) {
                    int headers_total = tcp_len+ip_len+ETH_LEN;
                    int packet_len = ntohs(ip_h->ip_len)+ETH_LEN;

                    if (packet_len > headers_total) { // detect payload
                        uint16_t p_iter = headers_total;
                        uint8_t bool_ua = 0; // user agent detection
                        string user_agent;
                        uint8_t ua_iter = 0;    

                        while (p_iter < packet_len) {
                            
                            // User agent hexa
                            if ((p_iter+3 < packet_len) && (pkt[p_iter]==0x55 && pkt[p_iter+1]==0x73 && pkt[p_iter+2]==0x65 && pkt[p_iter+3]==0x72)) {
                                p_iter += 12; // skip "User-Agent: " string
                                bool_ua = 1;                                
                            }


                            if (bool_ua) {
                                if (pkt[p_iter]==0x0d && pkt[p_iter+1]==0x0a) {
                                    p_iter += 2; // skip /r/n which indicates end of record
                                    bool_ua = 0;                     
                                }
                                else {
                                    user_agent += pkt[p_iter];
                                }
                            }

                            p_iter++;
                        }

                        if (!user_agent.empty()) {
                            memcpy(dev.mac_addr, eth_h->ether_shost, 6);
                            dev.user_agent = user_agent; 

                            find_dev(devs, dev);
                        }
                    }
                }
            }
        cout << "  Number of devices: " << devs.size() << endl;
        }
    }  

    // Cleanup
    closedir(dr);

    return 0;
}

int is_pcap(string filename) {
    string file_ext = filename.substr(filename.length()-4);
    string pcap_ext = "pcap";

    if (file_ext.compare(pcap_ext) == 0)
        return 1; // as true

    return 0;
}

bool mac_check(uint8_t *dev, uint8_t *pkt_mac) {
    for (int i=0; i < 6; i++) {
        if (dev[i] != pkt_mac[i]){
            return false;
        }
    }
    return true;
}

// either return an existing device or creates a new one
t_device find_dev(vector<t_device> &devices, t_device dev) {
    for (auto& it : devices) {
        if (mac_check(dev.mac_addr, it.mac_addr)) {
            return it;
        }
    }
    cout << "  Adding new device: " << endl;
    printf("\tmac address: %02x %02x %02x %02x %02x %02x\n", dev.mac_addr[0], dev.mac_addr[1], dev.mac_addr[2],
                                                            dev.mac_addr[3], dev.mac_addr[4], dev.mac_addr[5]);
    cout << "\tUser-agent: " << dev.user_agent << endl;
    // didn't find the one, let's add it to devices
    devices.push_back(dev);
    return dev;
}