#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <net/if.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3

struct dhcp_packet {
    u_int8_t op;
    u_int8_t htype;
    u_int8_t hlen;
    u_int8_t hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    in_addr ciaddr;
    in_addr yiaddr;
    in_addr siaddr;
    in_addr giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
};

int create_socket(const std::string& if_name) {

    sockaddr_in addr{
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_CLIENT_PORT),
        .sin_addr = htonl(INADDR_ANY),
    };

    //DHCP operates over UDP
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to create socket descriptor\n");
        exit(-1);
    }

    constexpr int flag = 1;

    // so we can make a socket if the address and port is in use
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        perror("Failed to set reuse address socket option\n");
        exit(-1);
    }

    // set the option for DHCP broadcast
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &flag, sizeof flag) < 0) {
        perror("Failed to set broadcast socket option\n");
        exit(-1);
    }

    //Bind the socket to the interface
    ifreq interface{};
    strncpy(interface.ifr_ifrn.ifrn_name, if_name.c_str(), if_name.length() + 1);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0) {
        perror("Failed to bind socket to interface\n");
        exit(-1);
    }

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind socket to address\n");
        exit(-1);
    }

    return sock;
}

// Binary representation of a mac is 6 bytes
uint8_t r_mac[6];
void gen_rand_mac()
{
    *(uint32_t*)r_mac = random();
    *(uint16_t*)(r_mac + 4) = random();
}

u_int32_t dhcp_discover(int sock) {
    dhcp_packet discover{};
    memset(&discover, 0, sizeof(discover));

    discover.op = 1;
    discover.htype = 1;
    discover.hlen = 6;
    discover.hops = 0;

    u_int32_t transactionID = random();
    discover.xid = htonl(transactionID);
    discover.secs = 0x00;

    //broadcast flag
    discover.flags = htons(1<<15);

    //copy mac
    memcpy(discover.chaddr, r_mac, 6);

    // Magic cookie values
    discover.options[0]= 0x63;
    discover.options[1]= 0x82;
    discover.options[2]= 0x53;
    discover.options[3]= 0x63;

    // message type DHCPDISCOVER
    discover.options[4] = 0x35;
    discover.options[5] = 0x1;
    discover.options[6] = DHCPDISCOVER;

    // options end
    discover.options[7] = 0xFF;

    sockaddr_in broadcast_address{
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr = htonl(INADDR_BROADCAST),
    };

    sendto(sock, &discover, sizeof(discover), 0, (sockaddr*)&broadcast_address, sizeof(broadcast_address));

    return transactionID;
}


void dhcp_request(int sock, u_int32_t transactionID, in_addr server_ip, in_addr request_ip ) {
    dhcp_packet request{};

    memset(&request, 0, sizeof(request));

    // BOOTREQUEST
    request.op = 1;

    //defaults
    request.htype = 1;
    request.hlen = 6;
    request.hops = 0;

    request.xid = htonl(transactionID);
    ntohl(request.xid);

    request.secs = 0x00;
    //broadcast flag
    request.flags = htons(1<<15);
    request.ciaddr = request_ip;

    //mac
    memcpy(request.chaddr, r_mac, 6);

    // Magic cookie values
    request.options[0]= 0x63;
    request.options[1]= 0x82;
    request.options[2]= 0x53;
    request.options[3]= 0x63;

    // message type DHCPREQUEST
    request.options[4] = 0x35;
    request.options[5] = 0x1;
    request.options[6] = DHCPREQUEST;

    // set address option
    request.options[7] = 50;
    request.options[8] = 4;
    memcpy(&request.options[9], &request_ip, sizeof(request_ip));

    request.options[13] = 54;
    request.options[14] = 4;
    memcpy(&request.options[15], &server_ip, sizeof(server_ip));
    request.options[19] = 0xFF;

    sockaddr_in broadcast_address{
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr = htonl(INADDR_BROADCAST),
    };

    sendto(sock, &request, sizeof(request), 0, (sockaddr*)&broadcast_address, sizeof(broadcast_address));
}

#define OFFER_TIMEOUT 2
void get_offers(int sock, u_int32_t transactionID) {
    dhcp_packet offer{};


    time_t start_time;
    time_t current_time;

    time(&start_time);
    current_time = start_time;

    while (current_time - start_time < OFFER_TIMEOUT) {

        time(&current_time);

        memset(&offer, 0, sizeof(offer));

        fd_set readfds;
        timeval timeout{
            .tv_sec = 1,
            .tv_usec = 0
        };

        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        select(sock + 1, &readfds, nullptr, nullptr, &timeout);

        if (!FD_ISSET(sock, &readfds)) {
            continue;
        }

        sockaddr_in source{};
        socklen_t addrlen = sizeof(source);

        memset(&source, 0, sizeof(source));
        if(recvfrom(sock, &offer, sizeof(offer), 0, (sockaddr*)&source, &addrlen) < 0)
        {
            continue;
        }

        //match the transactionID
        if (ntohl(offer.xid) != transactionID) continue;

        std::cout << "Got ip address " << inet_ntoa(offer.yiaddr) << std::endl;

        dhcp_request(sock, transactionID, source.sin_addr, offer.yiaddr);
        break;
    }

}


int main(const int argc, char *argv[]) {

    std::string iterface = argv[1];
    int sockfd = create_socket(iterface);

    while (true)
    {
        gen_rand_mac();
        uint32_t transactionID = dhcp_discover(sockfd);
        get_offers(sockfd, transactionID);
    }

    close(sockfd);
    return 0;
}