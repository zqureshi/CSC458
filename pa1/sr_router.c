/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <glib.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/* Macros to convert byte order */
#define HOST_SHORT(PTR) (PTR = ntohs(PTR))
#define HOST_LONG(PTR)  (PTR = ntohl(PTR))

#define NET_SHORT(PTR)  (PTR = htons(PTR))
#define NET_LONG(PTR)   (PTR = htonl(PTR))

/* Offset of IPv4 Checksum */
#define IPv4_CHECKSUM_OFFSET 10
#define IPv4_CHECKSUM_LENGTH 2
#define IPv4_WORD_SIZE 4

#define ICMP_CHECKSUM_OFFSET 2
#define ICMP_CHECKSUM_LENGTH 2

/* Forward declarations */
void sr_handleproto_ARP(struct sr_instance *, struct sr_if *,
        struct sr_ethernet_hdr *, struct sr_arphdr *);
void sr_handleproto_IP(struct sr_instance *, struct sr_if *,
        struct sr_ethernet_hdr *, struct ip *);
void populate_ethernet_header(uint8_t *, uint8_t *, uint8_t *, uint16_t);
uint16_t header_checksum(uint8_t *, uint16_t, uint16_t, uint16_t);
uint16_t IP_header_checksum(struct ip *);
uint16_t ICMP_header_checksum(struct ip *, struct icmp_hdr *);

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* Ethernet Interface */
    struct sr_if *eth_if = (struct sr_if *) sr_get_interface(sr, interface);

    if(eth_if) {
        printf("Interface: %s \n", eth_if->name);
    } else {
        printf("!!! Invalid Interface: %s \n", interface);
    }

    /* Ethernet Header */
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *) packet;

    switch(ntohs(eth_hdr->ether_type)) {
        case ETHERTYPE_ARP:
            printf("Protocol: ARP. \n");

            /* Cast to ARP header by indexing into packet */
            struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

            sr_handleproto_ARP(sr, eth_if, eth_hdr, arp_hdr);
            break;

        case ETHERTYPE_IP:
            printf("Protocol: IP. \n");

            /* Cast to IP Header by indexing into packet */
            struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

            sr_handleproto_IP(sr, eth_if, eth_hdr, ip_hdr);
            break;
        default:
            printf("!!! Unrecognized Protocol Type: %d \n", eth_hdr->ether_type);
    }
}/* end sr_handlpacket */

/*
 * Handle ARP protocol packets
 */
void sr_handleproto_ARP(struct sr_instance *sr, /* Native byte order */
        struct sr_if *eth_if, /* Network byte order */
        struct sr_ethernet_hdr *eth_hdr, /* Network byte order */
        struct sr_arphdr *arp_hdr /* Network byte order */)
{
    assert(sr);
    assert(eth_if);
    assert(eth_hdr);
    assert(arp_hdr);

    /* Only handle ARP packets for Ethernet */
    switch(ntohs(arp_hdr->ar_hrd)) {
        case ARPHDR_ETHER:
            break;

        default:
            printf("Only handle ARP Packets for Ethernet. \n");
            return;
    }

    switch(ntohs(arp_hdr->ar_op)) {
        case ARP_REQUEST: /* Handle ARP Request */

            /* If Request is for Router's IP then send a reply */
            if(eth_if->ip == arp_hdr->ar_tip) {
                unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
                uint8_t *buf = malloc(len);

                /* Populate reply Ethernet header */
                populate_ethernet_header(buf, eth_if->addr, eth_hdr->ether_shost, ETHERTYPE_ARP);

                /*
                 * Populate ARP reply, copy over source arp header since most
                 * of the fields are going to be the same
                 */
                struct sr_arphdr *rep_arp_hdr = (struct sr_arphdr *) (buf + sizeof(struct sr_ethernet_hdr));
                memcpy(rep_arp_hdr, arp_hdr, sizeof(struct sr_arphdr));

                /* Mark packet as reply*/
                rep_arp_hdr->ar_op = htons(ARP_REPLY);
                /* Sender in Request is Target in reply */
                memcpy(rep_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(arp_hdr->ar_sha));
                rep_arp_hdr->ar_tip = arp_hdr->ar_sip;
                /* Sender in reply is our own address */
                memcpy(rep_arp_hdr->ar_sha, eth_if->addr, sizeof(eth_if->addr));
                rep_arp_hdr->ar_sip = eth_if->ip;

                /* Send packet and free buffer */
                int result = sr_send_packet(sr, buf, len, eth_if->name);
                free(buf);
                if(result == 0) {
                    printf("*** -> Sent Packet of length: %d \n", len);
                }
            }

            break;

        case ARP_REPLY: /* Handle ARP Reply */
            break;

        default:
            printf("Only handle ARP Request and Reply. \n");
    }
}

/* Handle IP Packets */
void sr_handleproto_IP(struct sr_instance *sr, /* Native byte order */
        struct sr_if *eth_if, /* Network byte order */
        struct sr_ethernet_hdr *eth_hdr, /* Network byte order */
        struct ip *ip_hdr /* Network byte order */)
{
    assert(sr);
    assert(eth_if);
    assert(eth_hdr);
    assert(ip_hdr);

    /* Check IP Protocol Version */
    switch(ip_hdr->ip_v) {
        case IPv4:
            break;

        default:
            printf("Only handle IP Version 4. \n");
            return;
    }

    /* Validate Checksum */
    if(ntohs(ip_hdr->ip_sum) != IP_header_checksum(ip_hdr)) {
        printf("!!! Invalid checksum. \n");
        return;
    }

    /* Handle packet if Router is destination */
    if(ip_hdr->ip_dst.s_addr == eth_if->ip) {
        switch(ip_hdr->ip_p) {
            case IPPROTO_ICMP:
                printf("IP Protocol: ICMP \n");

                struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(((uint8_t *)ip_hdr) + ip_hdr->ip_hl * IPv4_WORD_SIZE);

                /* Validate Checksum */
                if(ntohs(ntohs(icmp_hdr->ic_sum) != ICMP_header_checksum(ip_hdr, icmp_hdr))) {
                    printf("!!! Invalid checksum. \n");
                    return;
                }

                switch(icmp_hdr->ic_type) {
                    case ICMP_ECHO_REQUEST:
                        printf("ICMP Message Type: Echo Request \n");
                        break;

                    default:
                        printf("Unhandled ICMP Message Type. \n");
                }
                break;

            default:
                printf("Only handle ICMP if Router is Destination. \n");
        }

        return;
    }

    /* Else, forward packet after lookup in Routing Table */
}

/*
 * Populate allocated buffer *buf to be sent to destination eth_dhost
 * from eth_shost with protocol type ether_type
 */
void populate_ethernet_header(uint8_t *buf, uint8_t *eth_shost, uint8_t *eth_dhost, uint16_t ether_type) {
    struct sr_ethernet_hdr *rep_eth_hdr = (struct sr_ethernet_hdr *) buf;
    memcpy(rep_eth_hdr->ether_shost, eth_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(rep_eth_hdr->ether_dhost, eth_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    rep_eth_hdr->ether_type = htons(ether_type);
}
uint16_t IP_header_checksum(struct ip *ip_hdr) {
    return header_checksum((uint8_t *)ip_hdr, ip_hdr->ip_hl * IPv4_WORD_SIZE, IPv4_CHECKSUM_OFFSET, IPv4_CHECKSUM_LENGTH);
}

uint16_t ICMP_header_checksum(struct ip *ip_hdr, struct icmp_hdr *icmp_hdr) {
    uint16_t icmp_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * IPv4_WORD_SIZE;
    return header_checksum((uint8_t *)icmp_hdr, icmp_len, ICMP_CHECKSUM_OFFSET, ICMP_CHECKSUM_LENGTH);
}

uint16_t header_checksum(uint8_t *buf, uint16_t len, uint16_t cksum_offset, uint16_t cksum_length)
{
    uint32_t sum = 0;
    uint8_t *header = malloc(sizeof(uint8_t) * len);

    /* Copy over buffer */
    memcpy(header, buf, len);

    /* Set header checksum to zero */
    memset(header + cksum_offset, 0x0, cksum_length);

    /* Calculate 16 bit sum */
    for(int i=0; i < len; i+=2) {
        sum += (uint32_t)(header[i] << 8 | header[i+1]);
    }

    /* Fold 32 bit number to 16 bit */
    while(sum >> 16)
        sum = (sum >> 16) + (sum & 0xffff);

    /* One's Complement */
    sum = ~sum;

    /* Free up allocated buffer */
    free(header);

    return sum;
}
