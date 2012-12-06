/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include "mysock_impl.h"

#define HANDSHAKE_COND(c) \
if(!(c)) { \
    errno = ECONNREFUSED; \
    ctx->done = true; \
    goto unblock_app; \
}

#define PROTOCOL_COND(cond, lbl) \
if(!(cond)) { \
    goto lbl; \
}

#define RCV_COND(cond) PROTOCOL_COND((cond), handle_close_request)

enum
{
    CSTATE_WAIT_SYN,
    CSTATE_WAIT_ACK,
    CSTATE_WAIT_SYNACK,
    CSTATE_ESTABLISHED,
    CSTATE_CLOSED
};    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* Send Sequence Variables */
    tcp_seq snd_una;    /* Send Unacknowledged */
    tcp_seq snd_nxt;    /* Send Next */
    tcp_seq snd_wnd;    /* Segment Window */

    /* Receive Sequence Variables */
    tcp_seq rcv_nxt;    /* Receive Next */
    tcp_seq rcv_wnd;    /* Receive Window */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* Initialize Sender Variables */
    ctx->snd_una = ctx->initial_sequence_num;
    ctx->snd_nxt = ctx->snd_una;
    ctx->snd_wnd = STCP_WINDOW_SIZE;

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    if(is_active) { /* Client */
        /*
         * Send SYN packet
         */
        STCPHeader *header_syn = (STCPHeader *) calloc(1, sizeof(STCPHeader));

        header_syn->th_seq = htonl((ctx->snd_nxt)++);
        header_syn->th_off = STCP_HDR_LEN;
        header_syn->th_flags = TH_SYN;
        header_syn->th_win = htons(ctx->snd_wnd);

        ssize_t success = stcp_network_send(sd, header_syn, sizeof(STCPHeader), NULL);
        free(header_syn);

        /* If send failed, abort */
        HANDSHAKE_COND(success != -1);

        /*
         * Wait for SYNACK
         */
        ctx->connection_state = CSTATE_WAIT_SYNACK;

        uint8_t *packet_synack = (uint8_t *) calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t packet_len = stcp_network_recv(sd, packet_synack, sizeof(STCPHeader) + STCP_MSS);

        HANDSHAKE_COND((unsigned) packet_len >= sizeof(STCPHeader));

        STCPHeader *header_synack = (STCPHeader *) packet_synack;

        /* If Packet is not SYNACK, retry handshake */
        HANDSHAKE_COND(header_synack->th_flags & (TH_SYN | TH_ACK));

        /* Check Acknowledgement Number */
        HANDSHAKE_COND(ctx->snd_una < ntohl(header_synack->th_ack));
        HANDSHAKE_COND(ntohl(header_synack->th_ack) <= ctx->snd_nxt);
        ctx->snd_una = ntohl(header_synack->th_ack) - 1;

        /* Record Sequence Number and Window Size */
        ctx->rcv_nxt = ntohl(header_synack->th_seq);
        ctx->rcv_wnd = MIN(ntohs(header_synack->th_win), STCP_WINDOW_SIZE);

        free(packet_synack);

        /*
         * Send ACK
         */
        STCPHeader *header_ack = (STCPHeader *) calloc(1, sizeof(STCPHeader));

        header_ack->th_seq = htonl(ctx->snd_nxt);
        header_ack->th_ack = htonl(++(ctx->rcv_nxt));
        header_ack->th_off = STCP_HDR_LEN;
        header_ack->th_flags = TH_ACK;
        header_ack->th_win = htons(STCP_WINDOW_SIZE);

        success = stcp_network_send(sd, header_ack, sizeof(STCPHeader), NULL);
        free(header_ack);

        /* If send failed, retry handshake */
        HANDSHAKE_COND(success != -1);

    } else { /* Server */

        /*
         *  Wait For SYN
         */
        ctx->connection_state = CSTATE_WAIT_SYN;

        uint8_t *packet_syn = (uint8_t *) calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t packet_syn_len = stcp_network_recv(sd, packet_syn, sizeof(STCPHeader) + STCP_MSS);

        HANDSHAKE_COND((unsigned) packet_syn_len >= sizeof(STCPHeader));

        STCPHeader *header_syn = (STCPHeader *) packet_syn;

        /* If Packet is not SYN, retry handshake */
        HANDSHAKE_COND(header_syn->th_flags & TH_SYN);

        /* Record Sequence Number and Window Size */
        ctx->rcv_nxt = ntohl(header_syn->th_seq);
        ctx->rcv_wnd = MIN(ntohs(header_syn->th_win), STCP_WINDOW_SIZE);

        free(packet_syn);

        /*
         * Send SYNACK
         */
        STCPHeader *header_synack = (STCPHeader *) calloc(1, sizeof(STCPHeader));

        header_synack->th_seq = htonl((ctx->snd_nxt)++);
        header_synack->th_ack = htonl(++(ctx->rcv_nxt));
        header_synack->th_off = STCP_HDR_LEN;
        header_synack->th_flags = TH_SYN | TH_ACK;
        header_synack->th_win = htonl(STCP_WINDOW_SIZE);

        ssize_t success = stcp_network_send(sd, header_synack, sizeof(STCPHeader), NULL);
        free(header_synack);

        /* If send failed, retry handshake */
        HANDSHAKE_COND(success != -1);

        /*
         * Wait for ACK
         */
        ctx->connection_state = CSTATE_WAIT_ACK;

        uint8_t *packet_ack = (uint8_t *) calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t packet_ack_len = stcp_network_recv(sd, packet_ack, sizeof(STCPHeader) + STCP_MSS);

        HANDSHAKE_COND((unsigned) packet_ack_len >= sizeof(STCPHeader));

        STCPHeader *header_ack = (STCPHeader *) packet_ack;

        /* Check Sequence Number */
        HANDSHAKE_COND(ctx->rcv_nxt == ntohl(header_ack->th_seq));

        /* If Packet is not ACK, retry handshake */
        HANDSHAKE_COND(header_ack->th_flags & TH_ACK);

        /* Check Acknowledgement Number */
        HANDSHAKE_COND(ctx->snd_una < ntohl(header_ack->th_ack));
        HANDSHAKE_COND(ntohl(header_ack->th_ack) <= ctx->snd_nxt);
        ctx->snd_una = ntohl(header_ack->th_ack) - 1;

        free(packet_ack);
    }

    ctx->connection_state = CSTATE_ESTABLISHED;

unblock_app:
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 255;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA) {
            /* the application has requested that data be sent */
            uint8_t *buffer = (uint8_t *) calloc(1, sizeof(uint8_t) * STCP_MSS);
            int buffer_len = stcp_app_recv(sd, buffer, STCP_MSS);

            /* Create Packet with Header + Payload */
            int packet_len = sizeof(STCPHeader) +  buffer_len;
            uint8_t *packet = (uint8_t *) calloc(1, packet_len);

            /* Populate Header */
            STCPHeader *header = (STCPHeader *) packet;
            header->th_seq = htonl(ctx->snd_nxt);
            header->th_ack = htonl(ctx->rcv_nxt);
            header->th_off = STCP_HDR_LEN;
            header->th_flags = TH_ACK;
            header->th_win = htons(ctx->snd_wnd);

            /* Update Sending Variables */
            ctx->snd_nxt += buffer_len;

            /* Copy over payload */
            memcpy(packet + TCP_DATA_START(packet), buffer, buffer_len);

            /* Send Packet */
            stcp_network_send(sd, packet, packet_len, NULL);

            /* Free up buffers */
            free(packet);
            free(buffer);
        }

        if (event & NETWORK_DATA) {
            /* Network has received data, send it up to app */
            uint8_t *packet = (uint8_t *) calloc(1, sizeof(STCPHeader) + sizeof(uint8_t) * STCP_MSS);
            ssize_t packet_len = stcp_network_recv(sd, packet, sizeof(STCPHeader) + sizeof(uint8_t) * STCP_MSS);
            STCPHeader *header = (STCPHeader *) packet;

            /* Validate Sequence Number */
            RCV_COND(ctx->rcv_nxt == ntohl(header->th_seq));
            ctx->rcv_nxt += packet_len - TCP_DATA_START(packet);

            /* Validate Acknowledgement if any */
            if(header->th_flags & TH_ACK) {
                RCV_COND(ctx->snd_una < ntohl(header->th_ack));
                RCV_COND(ntohl(header->th_ack) <= ctx->snd_nxt);
                ctx->snd_una = ntohl(header->th_ack) - 1;
            }

            /* Pass Data to App */
            stcp_app_send(sd, packet + TCP_DATA_START(packet), packet_len - TCP_DATA_START(packet));

            /* Free up buffers */
            free(packet);
        }

        handle_close_request:
        if (event & APP_CLOSE_REQUESTED) {
            /* App has requested connection to be closed, terminate connection */

        }

        if (event & TIMEOUT) {
            /* Timeout Occurred, handle it */

        }

        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



