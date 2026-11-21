#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int valid;
    char protocol[8];
    char mac[18];
    char ip[INET_ADDRSTRLEN];
    char hostname[64];
} NetObsEvent;

static void format_mac(const uint8_t *mac, char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int parse_arp_frame(const uint8_t *buf, size_t len, NetObsEvent *ev) {
    /* Ethernet (14 bytes) + ARP Ethernet/IPv4 (28 bytes) */
    if (len < 42) {
        return 0;
    }
    uint16_t ethertype = (uint16_t)((buf[12] << 8) | buf[13]);
    if (ethertype != 0x0806) {
        return 0;
    }
    const uint8_t *arp = buf + 14;
    uint16_t htype = (uint16_t)((arp[0] << 8) | arp[1]);
    uint16_t ptype = (uint16_t)((arp[2] << 8) | arp[3]);
    if (htype != 1 || ptype != 0x0800 || arp[4] != 6 || arp[5] != 4) {
        return 0;
    }
    ev->valid = 1;
    snprintf(ev->protocol, sizeof(ev->protocol), "ARP");
    format_mac(arp + 8, ev->mac);
    struct in_addr addr;
    memcpy(&addr.s_addr, arp + 14, 4);
    inet_ntop(AF_INET, &addr, ev->ip, sizeof(ev->ip));
    ev->hostname[0] = '\0';
    return 1;
}

static int parse_dhcp_frame(const uint8_t *buf, size_t len, NetObsEvent *ev) {
    if (len < 14 + 20 + 8 + 240) {
        return 0;
    }
    uint16_t ethertype = (uint16_t)((buf[12] << 8) | buf[13]);
    if (ethertype != 0x0800) {
        return 0;
    }
    const uint8_t *ip = buf + 14;
    if ((ip[0] >> 4) != 4) {
        return 0;
    }
    uint8_t ihl = (uint8_t)((ip[0] & 0x0F) * 4);
    if (ihl < 20 || ip[9] != 17 || len < (size_t)(14 + ihl + 8 + 240)) {
        return 0;
    }
    const uint8_t *udp = ip + ihl;
    uint16_t sport = (uint16_t)((udp[0] << 8) | udp[1]);
    uint16_t dport = (uint16_t)((udp[2] << 8) | udp[3]);
    uint16_t udp_len = (uint16_t)((udp[4] << 8) | udp[5]);
    if (!((sport == 67 && dport == 68) || (sport == 68 && dport == 67))) {
        return 0;
    }
    size_t udp_offset = (size_t)(udp - buf);
    if (udp_len < 8 + 240 || udp_offset + udp_len > len) {
        return 0;
    }
    const uint8_t *bootp = udp + 8;
    size_t bootp_len = (size_t)(udp_len - 8);
    /* Magic cookie DHCP: 99.130.83.99 */
    if (bootp[236] != 99 || bootp[237] != 130 || bootp[238] != 83 || bootp[239] != 99) {
        return 0;
    }

    ev->valid = 1;
    snprintf(ev->protocol, sizeof(ev->protocol), "DHCP");
    format_mac(bootp + 28, ev->mac);

    struct in_addr yiaddr;
    memcpy(&yiaddr.s_addr, bootp + 16, 4);
    if (yiaddr.s_addr == 0) {
        memcpy(&yiaddr.s_addr, bootp + 12, 4);
    }
    inet_ntop(AF_INET, &yiaddr, ev->ip, sizeof(ev->ip));
    ev->hostname[0] = '\0';

    /* Opções DHCP a partir do offset 240 */
    size_t pos = 240;
    while (pos < bootp_len) {
        uint8_t opt = bootp[pos++];
        if (opt == 0) {
            continue;
        }
        if (opt == 255 || pos >= bootp_len) {
            break;
        }
        uint8_t olen = bootp[pos++];
        if (pos + olen > bootp_len) {
            break;
        }
        if (opt == 12 && olen > 0) {
            size_t copy_len = olen < sizeof(ev->hostname) - 1 ? olen : sizeof(ev->hostname) - 1;
            for (size_t i = 0; i < copy_len; i++) {
                uint8_t ch = bootp[pos + i];
                ev->hostname[i] = (ch >= 32 && ch <= 126 && ch != '"' && ch != '\\') ? (char)ch : '_';
            }
            ev->hostname[copy_len] = '\0';
        }
        pos += olen;
    }
    return 1;
}

static void print_event_json(const NetObsEvent *ev) {
    printf("{\"protocol\":\"%s\",\"mac\":\"%s\",\"ip\":\"%s\",\"hostname\":\"%s\"}\n",
           ev->protocol, ev->mac, ev->ip, ev->hostname);
}

static int run_self_test(void) {
    uint8_t arp_pkt[42];
    memset(arp_pkt, 0, sizeof(arp_pkt));
    arp_pkt[12] = 0x08;
    arp_pkt[13] = 0x06;
    arp_pkt[15] = 1; /* htype Ethernet */
    arp_pkt[16] = 0x08;
    arp_pkt[17] = 0x00; /* IPv4 */
    arp_pkt[18] = 6;
    arp_pkt[19] = 4;
    arp_pkt[21] = 1; /* request */
    uint8_t src_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    memcpy(arp_pkt + 22, src_mac, 6);
    arp_pkt[28] = 192;
    arp_pkt[29] = 168;
    arp_pkt[30] = 3;
    arp_pkt[31] = 77;

    NetObsEvent ev;
    memset(&ev, 0, sizeof(ev));
    if (!parse_arp_frame(arp_pkt, sizeof(arp_pkt), &ev)) {
        fprintf(stderr, "FAIL: parse_arp_frame\n");
        return 1;
    }
    if (strcmp(ev.mac, "aa:bb:cc:dd:ee:01") != 0 || strcmp(ev.ip, "192.168.3.77") != 0) {
        fprintf(stderr, "FAIL: ARP mismatch mac=%s ip=%s\n", ev.mac, ev.ip);
        return 1;
    }

    uint8_t dhcp_pkt[300];
    memset(dhcp_pkt, 0, sizeof(dhcp_pkt));
    dhcp_pkt[12] = 0x08;
    dhcp_pkt[13] = 0x00;
    dhcp_pkt[14] = 0x45;
    dhcp_pkt[23] = 17; /* UDP */
    /* sport=68 dport=67 em 14+20=34 */
    dhcp_pkt[34] = 0;
    dhcp_pkt[35] = 68;
    dhcp_pkt[36] = 0;
    dhcp_pkt[37] = 67;
    /* UDP length = 8 + 258 = 266 bytes */
    dhcp_pkt[38] = (uint8_t)(266 >> 8);
    dhcp_pkt[39] = (uint8_t)(266 & 0xFF);
    /* BOOTP começa em 42; yiaddr em 42+16=58; chaddr em 42+28=70 */
    dhcp_pkt[58] = 192;
    dhcp_pkt[59] = 168;
    dhcp_pkt[60] = 3;
    dhcp_pkt[61] = 88;
    uint8_t dmac[6] = {0x10, 0x22, 0x33, 0x44, 0x55, 0x66};
    memcpy(dhcp_pkt + 70, dmac, 6);
    dhcp_pkt[42 + 236] = 99;
    dhcp_pkt[42 + 237] = 130;
    dhcp_pkt[42 + 238] = 83;
    dhcp_pkt[42 + 239] = 99;
    /* Opção 12 Hostname = "impressora" */
    dhcp_pkt[42 + 240] = 12;
    dhcp_pkt[42 + 241] = 10;
    memcpy(dhcp_pkt + 42 + 242, "impressora", 10);
    dhcp_pkt[42 + 252] = 255;

    memset(&ev, 0, sizeof(ev));
    if (!parse_dhcp_frame(dhcp_pkt, sizeof(dhcp_pkt), &ev)) {
        fprintf(stderr, "FAIL: parse_dhcp_frame\n");
        return 1;
    }
    if (strcmp(ev.mac, "10:22:33:44:55:66") != 0 ||
        strcmp(ev.ip, "192.168.3.88") != 0 ||
        strcmp(ev.hostname, "impressora") != 0) {
        fprintf(stderr, "FAIL: DHCP mismatch mac=%s ip=%s host=%s\n", ev.mac, ev.ip, ev.hostname);
        return 1;
    }

    printf("mintsec-netmon self-test OK (ARP + DHCP)\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        return run_self_test();
    }
    const char *ifname = NULL;
    int max_packets = 100;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            ifname = argv[++i];
        } else if (strcmp(argv[i], "--max-packets") == 0 && i + 1 < argc) {
            long val = strtol(argv[++i], NULL, 10);
            if (val < 1) val = 1;
            if (val > 100000) val = 100000;
            max_packets = (int)val;
        }
    }
    if (!ifname || strlen(ifname) == 0 || strlen(ifname) >= IFNAMSIZ) {
        fprintf(stderr, "Uso: %s --iface <interface> [--max-packets N] | --self-test\n", argv[0]);
        return 2;
    }

    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return 1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(fd);
        return 1;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        close(fd);
        return 1;
    }

    uint8_t buf[2048];
    int count = 0;
    while (count < max_packets) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        NetObsEvent ev;
        memset(&ev, 0, sizeof(ev));
        if (parse_arp_frame(buf, (size_t)n, &ev) || parse_dhcp_frame(buf, (size_t)n, &ev)) {
            print_event_json(&ev);
            fflush(stdout);
            count++;
        }
    }
    close(fd);
    return 0;
}
