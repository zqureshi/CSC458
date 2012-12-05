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

#define CONNECTION_ERROR \
    errno = ECONNREFUSED; \
    goto unblock_app

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
    tcp_seq receive_sequence_num;

    uint16_t window_size;
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

        header_syn->th_seq = htonl(ctx->initial_sequence_num);
        header_syn->th_off = STCP_HDR_LEN;
        header_syn->th_flags = TH_SYN;
        header_syn->th_win = htons(STCP_WINDOW_SIZE);

        ssize_t success = stcp_network_send(sd, header_syn, sizeof(STCPHeader), NULL);
        free(header_syn);

        /* If send failed, retry handshake */
        if(success == -1) {
            CONNECTION_ERROR;
        }

        /*
         * Wait for SYNACK
         */
        ctx->connection_state = CSTATE_WAIT_SYNACK;

        uint8_t *packet_synack = (uint8_t *) calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t packet_len = stcp_network_recv(sd, packet_synack, sizeof(STCPHeader) + STCP_MSS);

        if((unsigned) packet_len < sizeof(STCPHeader)) {
            CONNECTION_ERROR;
        }

        STCPHeader *header_synack = (STCPHeader *) packet_synack;

        /* If Packet is not SYNACK, retry handshake */
        if(!(header_synack->th_flags & (TH_SYN | TH_ACK))) {
            CONNECTION_ERROR;
        }

        /* Check Acknowledgement Number */
        if(htonl(header_synack->th_ack) != ctx->initial_sequence_num + 1) {
            CONNECTION_ERROR;
        }

        /* Record Sequence Number and Window Size */
        ctx->receive_sequence_num = ntohl(header_synack->th_seq);
        ctx->window_size = MIN(ntohs(header_synack->th_win), STCP_WINDOW_SIZE);

        free(packet_synack);

        /*
         * Send ACK
         */
        STCPHeader *header_ack = (STCPHeader *) calloc(1, sizeof(STCPHeader));

        header_ack->th_seq = htonl(++(ctx->initial_sequence_num));
        header_ack->th_ack = htonl(++(ctx->receive_sequence_num));
        header_ack->th_off = STCP_HDR_LEN;
        header_ack->th_flags = TH_ACK;
        header_ack->th_win = htons(STCP_WINDOW_SIZE);

        success = stcp_network_send(sd, header_ack, sizeof(STCPHeader), NULL);
        free(header_ack);

        /* If send failed, retry handshake */
        if(success == -1) {
            CONNECTION_ERROR;
        }

    } else { /* Server */

        /*
         *  Wait For SYN
         */
        ctx->connection_state = CSTATE_WAIT_SYN;

        uint8_t *packet_syn = (uint8_t *) calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t packet_syn_len = stcp_network_recv(sd, packet_syn, sizeof(STCPHeader) + STCP_MSS);

        if((unsigned) packet_syn_len < sizeof(STCPHeader)) {
            CONNECTION_ERROR;
        }

        STCPHeader *header_syn = (STCPHeader *) packet_syn;

        /* If Packet is not SYN, retry handshake */
        if(!(header_syn->th_flags & TH_SYN)) {
            CONNECTION_ERROR;
        }

        /* Record Sequence Number and Window Size */
        ctx->receive_sequence_num = ntohl(header_syn->th_seq);
        ctx->window_size = MIN(ntohs(header_syn->th_win), STCP_WINDOW_SIZE);

        free(packet_syn);

        /*
         * Send SYNACK
         */
        STCPHeader *header_synack = (STCPHeader *) calloc(1, sizeof(STCPHeader));

        header_synack->th_seq = htonl(ctx->initial_sequence_num);
        header_synack->th_ack = htonl(++(ctx->receive_sequence_num));
        header_synack->th_off = STCP_HDR_LEN;
        header_synack->th_flags = TH_SYN | TH_ACK;
        header_synack->th_win = htonl(STCP_WINDOW_SIZE);

        ssize_t success = stcp_network_send(sd, header_synack, sizeof(STCPHeader), NULL);
        free(header_synack);

        /* If send failed, retry handshake */
        if(success == -1) {
            CONNECTION_ERROR;
        }

        /*
         * Wait for ACK
         */
        ctx->connection_state = CSTATE_WAIT_ACK;

        uint8_t *packet_ack = (uint8_t *) calloc(1, sizeof(STCPHeader) + STCP_MSS);
        ssize_t packet_ack_len = stcp_network_recv(sd, packet_ack, sizeof(STCPHeader) + STCP_MSS);

        if((unsigned) packet_ack_len < sizeof(STCPHeader)) {
            CONNECTION_ERROR;
        }

        STCPHeader *header_ack = (STCPHeader *) packet_ack;

        /* If Packet is not SYNACK, retry handshake */
        if(!(header_ack->th_flags & TH_ACK)) {
            CONNECTION_ERROR;
        }

        /* Check Acknowledgement Number */
        if(htonl(header_ack->th_ack) != ctx->initial_sequence_num + 1) {
            CONNECTION_ERROR;
        }

        /* Record Sequence Number and Window Size */
        ctx->receive_sequence_num = ntohl(header_ack->th_seq);
        ctx->window_size = MIN(ntohs(header_ack->th_win), STCP_WINDOW_SIZE);

        free(packet_ack);
    }

unblock_app:
    ctx->connection_state = CSTATE_ESTABLISHED;
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
        event = stcp_wait_for_event(sd, 0, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
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



