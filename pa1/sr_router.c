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
#include <glib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_dumper.h"

/* Macros to convert byte order */
#define HOST_SHORT(PTR) (PTR = ntohs(PTR))
#define HOST_LONG(PTR)  (PTR = ntohl(PTR))

#define NET_SHORT(PTR)  (PTR = htons(PTR))
#define NET_LONG(PTR)   (PTR = htonl(PTR))

/* Offset of IPv4 Checksum */
#define IPv4_CHECKSUM_OFFSET 10
#define IPv4_CHECKSUM_LENGTH 2
#define IPv4_WORD_SIZE 4
#define IPv4_ADDR_LEN 4
#define IPV4_TTL 64

#define ICMP_CHECKSUM_OFFSET 2
#define ICMP_CHECKSUM_LENGTH 2

#define ETHER_ADDR_BROADCAST "\xff\xff\xff\xff\xff\xff"

#define ARP_CACHE_TIMEOUT 15 * G_USEC_PER_SEC /* 15 Seconds */
#define IP_QUEUE_TIMEOUT   5 * G_USEC_PER_SEC /*  5 Seconds */

#define MAX_POOL_THREADS 10

#define SEND_PACKET(sr, buf, len, interface) \
    if(sr_send_packet((sr), (buf), (len), (interface)) == 0) { \
        printf("*** -> Sent Packet of length: %d \n", (len)); \
    } \

/* Forward declarations */
void sr_handlepacket_thread(gpointer data, gpointer user_data);
void sr_handleproto_ARP(struct sr_instance *sr, /* Native byte order */
        struct sr_if *eth_if, /* Network byte order */
        struct sr_ethernet_hdr *eth_hdr, /* Network byte order */
        struct sr_arphdr *arp_hdr /* Network byte order */);
void sr_handleproto_IP(struct sr_instance *sr, /* Native byte order */
        struct sr_if *eth_if, /* Network byte order */
        struct sr_ethernet_hdr *eth_hdr, /* Network byte order */
        struct ip *ip_hdr /* Network byte order */);

void populate_ethernet_header(uint8_t *buf, uint8_t *eth_shost, uint8_t *eth_dhost, uint16_t ether_type);
void populate_ip_header(uint8_t *buf, uint16_t data_len, uint8_t proto, struct in_addr src, struct in_addr dst);
void populate_arp_header(uint8_t *buf, uint16_t hrd, uint16_t op, uint8_t *sha, uint32_t sip, uint8_t *dha, uint32_t dip);
void populate_icmp_error(uint8_t *buf, struct ip *ip_hdr, uint8_t type, uint8_t code);

uint16_t header_checksum(uint8_t *buf, uint16_t len, uint16_t cksum_offset, uint16_t cksum_length);
uint16_t IP_header_checksum(struct ip *ip_hdr);
uint16_t ICMP_header_checksum(struct icmp_hdr *icmp_hdr, uint16_t icmp_len);

/* ARP Cache */
GMutex *arp_cache_lock;
GHashTable *arp_cache;

struct arp_entry
{
    uint32_t ip;  /* Host IP Address */
    uint8_t  ha[ETHER_ADDR_LEN];  /* Host Hardware Address */
    gint64 time;  /* Time when cache entry was last refreshed */
};

/* Threadpool */
GThreadPool *sr_thread_pool;

struct sr_handlepacket_input
{
    struct sr_instance *sr;
    uint8_t *packet;
    unsigned int len;
    char *interface;
};

/* IP Queue waiting for ARP Replies */
GMutex *ip_queue_lock;
GHashTable *ip_queue;

struct ip_queue_entry
{
    uint32_t ip;       /* IP for ARP Request */
    GMutex lock;       /* Lock to signal/wait on condition */
    GCond wait_reply;  /* Wait until reply received or timeout */
};

/* ARP Cache Helpers */

/*
 * Return TRUE if entry found and copy over to out, else FALSE.
 */
int arp_lookup_entry(uint32_t ip, struct arp_entry *out, int refresh)
{
    g_mutex_lock(arp_cache_lock);
    struct arp_entry *entry = g_hash_table_lookup(arp_cache, &ip);
    int found = FALSE;

    if(entry) {
        printf("ARP Cache: Hit \n");
        if((g_get_monotonic_time() - entry->time) > ARP_CACHE_TIMEOUT) {
            printf("ARP Cache: Expired Entry \n");
            g_hash_table_remove(arp_cache, &ip);
        } else {
            if(refresh == TRUE) {
                printf("ARP Cache: Renew Entry \n");
                entry->time = g_get_monotonic_time();
            }
            memcpy(out, entry, sizeof(struct arp_entry));
            found = TRUE;
        }
    }
    g_mutex_unlock(arp_cache_lock);

    return found;
};

/*
 * Insert ARP Cache entry with given IP and Hardware Address and current time.
 */
void arp_insert_entry(uint32_t ip, uint8_t *ha)
{
    g_mutex_lock(arp_cache_lock);

    /* Create entry */
    struct arp_entry *entry = malloc(sizeof(struct arp_entry));
    memcpy(entry->ha, ha, ETHER_ADDR_LEN);
    entry->ip = ip;
    entry->time = g_get_monotonic_time();

    /* Insert it into cache*/
    g_hash_table_insert(arp_cache, &(entry->ip), entry);

    g_mutex_unlock(arp_cache_lock);
}

/* NOT to be directly called, only invoked on removal inside arp_lookup_entry / arp_insert_entry */
void arp_free_entry(gpointer value)
{
    free((struct arp_entry *)value);
}

/* IP Queue Helpers */

/*
 * Return the GCond variable for an IP or create a new one if not present.
 */
struct ip_queue_entry *ip_queue_lookup(uint32_t ip)
{
    g_mutex_lock(ip_queue_lock);
    struct ip_queue_entry *entry = (struct ip_queue_entry *)g_hash_table_lookup(ip_queue, &ip);

    if(!entry) {
        /* If entry not present, create and insert new one */
        entry = malloc(sizeof(struct ip_queue_entry));
        entry->ip = ip;
        g_mutex_init(&(entry->lock));
        g_cond_init(&(entry->wait_reply));

        g_hash_table_insert(ip_queue, &(entry->ip), entry);
    }

    g_mutex_unlock(ip_queue_lock);
    return entry;
}

/*
 * Signal all threads that were waiting for an ARP Reply from IP.
 */
void ip_queue_broadcast(uint32_t ip)
{
    g_mutex_lock(ip_queue_lock);
    struct ip_queue_entry *entry = (struct ip_queue_entry *)g_hash_table_lookup(ip_queue, &ip);

    /* Gain lock to signal GCond */
    g_mutex_lock(&(entry->lock));
    g_cond_broadcast(&(entry->wait_reply));

    /* Release GCond lock */
    g_mutex_unlock(&(entry->lock));

    g_mutex_unlock(ip_queue_lock);
}

/*
 * Print queue entries.
 * Note: NOT to be called directly, use ip_print_queue
 */
void ip_queue_print_entry(gpointer key, gpointer value, gpointer user_data)
{
    struct ip_queue_entry *entry = (struct ip_queue_entry *)value;
    struct in_addr ip = { entry->ip };

    printf("Entry: IP = %s \n", inet_ntoa(ip));
}

/*
 * Print all queue entry
 */
void ip_queue_print()
{
    g_mutex_lock(ip_queue_lock);
    printf("IP Queue: \n");
    g_hash_table_foreach(ip_queue, ip_queue_print_entry, NULL);
    g_mutex_unlock(ip_queue_lock);
}

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

    /* Initialize ARP Cache */
    arp_cache_lock = g_new(GMutex, 1);
    g_mutex_init(arp_cache_lock);
    arp_cache = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, arp_free_entry);

    /* Initialize IP Queue */
    ip_queue_lock = g_new(GMutex, 1);
    g_mutex_init(ip_queue_lock);
    ip_queue = g_hash_table_new(g_int_hash, g_int_equal);

    /* Initialize ThreadPool */
    sr_thread_pool = g_thread_pool_new(sr_handlepacket_thread, NULL, MAX_POOL_THREADS, TRUE, FALSE);
} /* -- sr_init -- */

void sr_destruct(struct sr_instance* sr)
{
    /* Free ARP Cache */
    g_hash_table_destroy(arp_cache);
    g_mutex_free(arp_cache_lock);

    /* Free IP Queue */
    g_hash_table_destroy(ip_queue);
    g_mutex_free(ip_queue_lock);

    /* Free Thread Pool */
    g_thread_pool_free(sr_thread_pool, TRUE, FALSE);
}

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

    printf("\n*** -> Received packet of length %d \n", len);

    /* Copy over input parameters for thread */
    struct sr_handlepacket_input *input = malloc(sizeof(struct sr_handlepacket_input));

    input->sr = sr;
    input->len = len;
    input->packet = malloc(sizeof(uint8_t) * len);
    memcpy(input->packet, packet, len);
    input->interface = malloc(strlen(interface)+1);
    strcpy(input->interface, interface);

    if(!g_thread_pool_push(sr_thread_pool, (gpointer)input, NULL)) {
        printf("!!! Error pushing packet to thread pool for processing. \n");
    };
}/* end sr_handlpacket */

void sr_handlepacket_thread(gpointer data, gpointer user_data)
{
    struct sr_handlepacket_input *input = (struct sr_handlepacket_input *)data;
    struct sr_instance* sr = input->sr;
    uint8_t * packet = input->packet;
    char* interface = input->interface;

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

    /* Free up all input */
    free(input->interface);
    free(input->packet);
    free(input);
}

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
        {
            printf("ARP Operation: Request \n");

            /* If Request is for Router's IP then send a reply */
            struct sr_if *t_eth_if = sr_get_interface_for_ip(sr, arp_hdr->ar_tip);
            if(t_eth_if != 0) {
                unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
                uint8_t *buf = malloc(len);

                /* Populate ARP Reply */
                populate_arp_header(buf + sizeof(struct sr_ethernet_hdr),
                        ARPHDR_ETHER,
                        ARP_REPLY,
                        t_eth_if->addr,
                        t_eth_if->ip,
                        arp_hdr->ar_sha,
                        arp_hdr->ar_sip);

                /* Populate reply Ethernet header */
                populate_ethernet_header(buf, t_eth_if->addr, eth_hdr->ether_shost, ETHERTYPE_ARP);

                /* Send packet and free buffer */
                SEND_PACKET(sr, buf, len, t_eth_if->name);
                free(buf);
            }

            /*
             * If ARP Target IP wasn't one of the router's IP's,
             * then just drop packet.
             */

            break;
        }

        case ARP_REPLY: /* Handle ARP Reply */
            printf("ARP Operation: Reply \n");

            /* Insert into ARP Cache and signal waiting threads */
            arp_insert_entry(arp_hdr->ar_sip, arp_hdr->ar_sha);
            ip_queue_broadcast(arp_hdr->ar_sip);
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

    /* Validate IP Checksum */
    if(ntohs(ip_hdr->ip_sum) != IP_header_checksum(ip_hdr)) {
        printf("!!! Invalid checksum. \n");
        return;
    }

    /* Handle packet if Router is destination */
    if(sr_get_interface_for_ip(sr, ip_hdr->ip_dst.s_addr) != 0) {
        switch(ip_hdr->ip_p) {
            case IPPROTO_ICMP:
            {
                printf("IP Protocol: ICMP \n");

                struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(((uint8_t *)ip_hdr) + ip_hdr->ip_hl * IPv4_WORD_SIZE);
                uint16_t icmp_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * IPv4_WORD_SIZE;

                /* Validate ICMP Checksum */
                if(ntohs(icmp_hdr->ic_sum) != ICMP_header_checksum(icmp_hdr, icmp_len)) {
                    printf("!!! Invalid checksum. \n");
                    return;
                }

                switch(icmp_hdr->ic_type) {
                    case ICMP_ECHO_REQUEST:
                        printf("ICMP Message Type: Echo Request \n");

                        int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + icmp_len;
                        uint8_t *buf = (uint8_t *)malloc(len);

                        /* Populate ICMP Header */
                        struct icmp_hdr *rep_icmp_hdr =
                                (struct icmp_hdr *)(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

                        /* Copy existing packet since most of the info is the same */
                        memcpy(rep_icmp_hdr, icmp_hdr, icmp_len);

                        /* Update Type */
                        rep_icmp_hdr->ic_type = ICMP_ECHO_REPLY;

                        /* Calculate ICMP Checksum */
                        rep_icmp_hdr->ic_sum = htons(ICMP_header_checksum(icmp_hdr, icmp_len));

                        /* Populate IP Header */
                        populate_ip_header(
                                buf + sizeof(struct sr_ethernet_hdr),
                                icmp_len,
                                IPPROTO_ICMP,
                                ip_hdr->ip_dst,
                                ip_hdr->ip_src);

                        /* Populate Ethernet Header */
                        populate_ethernet_header(buf, eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHERTYPE_IP);

                        /* Send packet and free buffer */
                        SEND_PACKET(sr, buf, len, eth_if->name);
                        free(buf);

                        return;

                    default:
                        printf("Unhandled ICMP Message Type. \n");
                }

                return;
            }

            case IPPROTO_TCP:
            case IPPROTO_UDP:
            {
                printf("IP Protocol: TCP/UDP. \n");
                printf("Sending 'ICMP: Port Unreachable' to Source. \n");

                int ip_len = (ip_hdr->ip_hl * IPv4_WORD_SIZE)
                        + min(8, ip_hdr->ip_len - ip_hdr->ip_hl * IPv4_WORD_SIZE);
                int icmp_len = sizeof(struct icmp_hdr)
                        + sizeof(struct icmp_echo_hdr)
                        + ip_len;
                int len = sizeof(struct sr_ethernet_hdr)
                        + sizeof(struct ip) + icmp_len;

                uint8_t *buf = malloc(len);

                /* Populate ICMP Error Message */
                populate_icmp_error(buf, ip_hdr, ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE);

                /* Populate IP Header */
                populate_ip_header(buf + sizeof(struct sr_ethernet_hdr),
                        icmp_len,
                        IPPROTO_ICMP,
                        ip_hdr->ip_dst,
                        ip_hdr->ip_src);

                /* Populate Ethernet Header */
                populate_ethernet_header(buf, eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHERTYPE_IP);

                /* Send packet and free buffer */
                SEND_PACKET(sr, buf, len, eth_if->name);
                free(buf);

                return;
            }

            default:
                printf("!!! Unhandled IP Protocol. \n");
        }

        return;
    }

    /* Else, forward packet after lookup in Routing Table */
    struct sr_rt *next_hop = sr_get_next_hop(sr, eth_if, ip_hdr->ip_dst);

    /* If next_hop is NULL, we didn't find a routing entry, drop packet */
    if(next_hop == NULL) {
        printf("!!! No Routing Entry, Dropping Packet. \n");
        return;
    }

    /* Fetch the interface to send packet from */
    struct sr_if *out_port = sr_get_interface(sr, next_hop->interface);

    struct arp_entry arp_entry;
    if(!arp_lookup_entry(next_hop->gw.s_addr, &arp_entry, FALSE)) {
        /* Queue packet and send ARP Request */
        printf("No ARP Entry for Gateway, queuing packet. \n");

        /* Send ARP Request for Gateway */
        int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
        uint8_t *buf = malloc(len);

        /* Populate ARP Header */
        populate_arp_header(buf + sizeof(struct sr_ethernet_hdr),
                ARPHDR_ETHER,
                ARP_REQUEST,
                out_port->addr,
                out_port->ip,
                (uint8_t *)ETHER_ADDR_BROADCAST,
                next_hop->gw.s_addr);

        /* Populate Ethernet Header */
        populate_ethernet_header(buf, out_port->addr, (uint8_t *)ETHER_ADDR_BROADCAST, ETHERTYPE_ARP);

        /* Send packet and free buffer */
        SEND_PACKET(sr, buf, len, out_port->name);
        free(buf);
    }

    /* Wait for ARP Reply or Timeout */
    struct ip_queue_entry *ip_entry = ip_queue_lookup(next_hop->gw.s_addr);
    gint64 end_time = g_get_monotonic_time() + IP_QUEUE_TIMEOUT;

    g_mutex_lock(&(ip_entry->lock));
    while(!arp_lookup_entry(next_hop->gw.s_addr, &arp_entry, TRUE)) {
        if(!g_cond_wait_until(&(ip_entry->wait_reply), &(ip_entry->lock), end_time)) {
            printf("!!! Packet timed out waiting for ARP Reply from %s, dropping. \n", inet_ntoa(next_hop->gw));

            goto sr_handleproto_IP_end;
        }
    }

    /* If here, means we've received an ARP Reply */
    printf("Received ARP Reply from Gateway %s, forwarding packet. \n", inet_ntoa(next_hop->gw));

    /* Decrement TTL and forward packet */
    if(ip_hdr->ip_ttl <= 1) {
        /* TTL: 0 or 1, drop packet and send ICMP*/
        printf("TTL: %d, sending ICMP Time Exceeded. \n", ip_hdr->ip_ttl);

        int ip_len = (ip_hdr->ip_hl * IPv4_WORD_SIZE)
                + min(8, ip_hdr->ip_len - ip_hdr->ip_hl * IPv4_WORD_SIZE);
        int icmp_len = sizeof(struct icmp_hdr)
                + sizeof(struct icmp_echo_hdr)
                + ip_len;
        int len = sizeof(struct sr_ethernet_hdr)
                + sizeof(struct ip) + icmp_len;

        uint8_t *buf = malloc(len);

        /* Populate ICMP Error Message */
        populate_icmp_error(buf, ip_hdr, ICMP_TIME_EXCEEDED, ICMP_CODE_TTL_ZERO);

        /* Populate IP Header */
        populate_ip_header(buf + sizeof(struct sr_ethernet_hdr),
                icmp_len,
                IPPROTO_ICMP,
                ip_hdr->ip_dst,
                ip_hdr->ip_src);

        /* Populate Ethernet Header */
        populate_ethernet_header(buf, eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHERTYPE_IP);

        /* Send packet and free buffer */
        SEND_PACKET(sr, buf, len, eth_if->name);
        free(buf);

    } else {
        /* Otherwise Decrement TTL, calculate new checksum and forward */

        int len = sizeof(struct sr_ethernet_hdr) + ntohs(ip_hdr->ip_len);
        uint8_t *buf = malloc(len);

        /* Copy IP Header + Data and decrement TTL*/
        struct ip *rep_ip_hdr = (struct ip*)(buf + sizeof(struct sr_ethernet_hdr));
        memcpy(rep_ip_hdr, ip_hdr, ntohs(ip_hdr->ip_len));
        rep_ip_hdr->ip_ttl--;
        rep_ip_hdr->ip_sum = htons(IP_header_checksum(rep_ip_hdr));

        /* Populate Ethernet Header */
        populate_ethernet_header(buf, out_port->addr, arp_entry.ha, ETHERTYPE_IP);

        SEND_PACKET(sr, buf, len, out_port->name);
        free(buf);
    }

    sr_handleproto_IP_end:
    g_mutex_unlock(&(ip_entry->lock));
}

/*
 * Populate allocated buffer *buf to be sent to destination eth_dhost
 * from eth_shost with protocol type ether_type
 */
void populate_ethernet_header(uint8_t *buf, uint8_t *eth_shost, uint8_t *eth_dhost, uint16_t ether_type)
{
    struct sr_ethernet_hdr *rep_eth_hdr = (struct sr_ethernet_hdr *) buf;
    memcpy(rep_eth_hdr->ether_shost, eth_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(rep_eth_hdr->ether_dhost, eth_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    rep_eth_hdr->ether_type = htons(ether_type);
}

/*
 * Populate allocated buf with fresh ARP Header.
 *
 * buf:  Buffer with enough space for header
 * hrd:  Hardware Type
 * op:  ARP Operation Code
 * sha:  Source Hardware Address
 * sip:  Source IP Address
 * dha:  Destination Hardware Address
 * dip: Destination IP Address
 */
void populate_arp_header(uint8_t *buf, uint16_t hrd, uint16_t op, uint8_t *sha, uint32_t sip, uint8_t *dha, uint32_t dip)
{
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)buf;

    arp_hdr->ar_hrd = htons(hrd);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = IPv4_ADDR_LEN;
    arp_hdr->ar_op = htons(op);
    memcpy(arp_hdr->ar_sha, sha, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = sip;
    memcpy(arp_hdr->ar_tha, dha, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = dip;
}

/*
 * Populate allocated buf with a fresh IP Header. You should call this method
 * once the data has been put in the buffer so that the generated checksum is
 * valid.
 *
 * buf:  Buffer with enough space for header
 * data_len:  Length of data (excluding IP header which will be added automatically) (Host Order)
 * proto:  IP Protocol
 * src:  Source Address (Network Order)
 * dst:  Destination Address (Network Order)
 */
void populate_ip_header(uint8_t *buf, uint16_t data_len, uint8_t proto, struct in_addr src, struct in_addr dst)
{
    struct ip *ip_hdr = (struct ip *)buf;

    ip_hdr->ip_v = IPv4;
    ip_hdr->ip_hl = sizeof(struct ip)/IPv4_WORD_SIZE;
    ip_hdr->ip_len = htons(sizeof(struct ip) + data_len);
    ip_hdr->ip_id = 0x0000;
    ip_hdr->ip_off = 0x0000;
    ip_hdr->ip_ttl = IPV4_TTL;
    ip_hdr->ip_p = proto;
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dst;

    /* Calculate Checksum */
    ip_hdr->ip_sum = htons(IP_header_checksum(ip_hdr));
}

void populate_icmp_error(uint8_t *buf, struct ip *ip_hdr, uint8_t type, uint8_t code)
{
    int ip_len = (ip_hdr->ip_hl * IPv4_WORD_SIZE)
                        + min(8, ip_hdr->ip_len - ip_hdr->ip_hl * IPv4_WORD_SIZE);
    int icmp_len = sizeof(struct icmp_hdr)
            + sizeof(struct icmp_echo_hdr)
            + ip_len;

    /* Populate ICMP Header and Data*/
    struct icmp_hdr *rep_icmp_hdr =
            (struct icmp_hdr *)(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

    /* Copy old IP Header + 8 Data bytes into ICMP Data section */
    memcpy(((uint8_t *)rep_icmp_hdr)
            + sizeof(struct icmp_hdr) + sizeof(struct icmp_echo_hdr),
            (uint8_t *)ip_hdr,
            ip_len);

    /* Set ICMP Header Type and Checksum */
    rep_icmp_hdr->ic_type = type;
    rep_icmp_hdr->ic_code = code;
    rep_icmp_hdr->ic_sum = htons(ICMP_header_checksum(rep_icmp_hdr, icmp_len));
}

uint16_t IP_header_checksum(struct ip *ip_hdr)
{
    return header_checksum((uint8_t *)ip_hdr, ip_hdr->ip_hl * IPv4_WORD_SIZE, IPv4_CHECKSUM_OFFSET, IPv4_CHECKSUM_LENGTH);
}

uint16_t ICMP_header_checksum(struct icmp_hdr *icmp_hdr, uint16_t icmp_len)
{
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
