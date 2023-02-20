#pragma once
#include <osmocom/core/endian.h>

struct e1oip_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t version:4,
		flags:4;
	uint8_t msg_type;		/* enum e1oip_msgtype */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t flags:4, version:4;
	uint8_t msg_type;
#endif
} __attribute__ ((packed));

#define E1OIP_VERSION	1

enum e1oip_msgtype {
	E1OIP_MSGT_ECHO_REQ	= 0,	/* struct e1oip_echo */
	E1OIP_MSGT_ECHO_RESP	= 1,	/* struct e1oip_echo */
	E1OIP_MSGT_TDM_DATA	= 2,	/* struct e1oip_tdm_hdr + payload */
	E1OIP_MSGT_SERVICE_REQ	= 3,	/* struct e1oip_service_req */
	E1OIP_MSGT_SERVICE_ACK	= 4,	/* struct e1oip_service_ack */
	E1OIP_MSGT_SERVICE_REJ	= 5,	/* struct e1oip_service_rej */
	E1OIP_MSGT_REDIR_CMD	= 6,	/* struct e1oip_redir_cmd */
	E1OIP_MSGT_AUTH_REQ	= 7,	/* struct e1oip_auth_req */
	E1OIP_MSGT_AUTH_RESP	= 8,	/* struct e1oip_auth_resp */
	E1OIP_MSGT_ERROR_IND	= 9,	/* struct e1oip_error_ind */
};

enum e1oip_service {
	E1OIP_SERVICE_NONE	= 0,
	E1OIP_SERVICE_E1_FRAMED	= 1,	/* single (framed) E1 trunk */
};

/* ECHO REQ + ECHO RESP */
struct e1oip_echo {
	/* sequence number to distinguish subsequent requests and
	 * responses */
	uint16_t seq_nr;
	/* data chosen by sender of ECHO_REQ, echoed back in ECHO_RESP */
	uint8_t data[0];
} __attribute__ ((packed));


/* follows e1oip_hdr for E1OIP_MSGT_TDM_DATA */
struct e1oip_tdm_hdr {
	/* reduced frame number, increments with every E1 frame (8000
	 * Hz). 16bit provides > 8s of wrap-around time, which is more
	 * than sufficient for detecting re-ordered framses over any
	 * meaningful interval */
	uint16_t frame_nr;
	/* bit-mask of timeslots with data contained in 'data' below*/
	uint32_t ts_mask;
	/* timeslot data: array of bytes per frame; each frame having
	 * one octet for the active timeslots indicated in 'ts_mask',
	 * in ascending order.  If ts_mask == 0, then we have a single
	 * octet in 'data' specifying the number of frames expressed in
	 * this packet. */
	uint8_t data[0];
} __attribute__ ((packed));

/* client says "hello" to server + requests a service */
struct e1oip_service_req {
	uint32_t requested_service;
	char subscriber_id[32];
	char software_id[32];
	char software_version[16];
	uint32_t capability_flags;
} __attribute__ ((packed));

/* server instructs client to use other server IP/port */
struct e1oip_redir_cmd {
	char server_ip[40];	/* IPv4 or IPv6 */
	uint16_t server_port;	/* UDP port number */
} __attribute__ ((packed));

/* server requests client to authenticate */
struct e1oip_auth_req {
	uint8_t rand_len;
	uint8_t rand[16];
	uint8_t autn_len;
	uint8_t autn[16];
} __attribute__ ((packed));

/* client responds to auth request.
 * - res_len == 0 && auts_len == 0 -> failure
 * - res_len != 0 && auts_len == 0 -> success
 * - res_len == 0 && auts_len != 0 -> re-sync */
struct e1oip_auth_resp {
	uint8_t res_len;	/* RES in success case */
	uint8_t res[16];
	uint8_t auts_len;	/* AUTS in resync case */
	uint8_t auts[16];
} __attribute__ ((packed));

/* server acknowledges a client "hello" + service granted */
struct e1oip_service_ack {
	uint32_t assigned_service;
	char server_id[32];
	char software_id[32];
	char software_version[16];
	uint32_t capability_flags;	/* server supported capabilities */
} __attribute__ ((packed));

/* server acknowledges a client "hello" + service rejected */
struct e1oip_service_rej {
	uint32_t rejected_service;
	char reject_message[64];
} __attribute__ ((packed));

/* either side informs the other of an erroneous condition */
struct e1oip_error_ind {
	uint32_t cause;
	char error_message[64];
	uint8_t original_message[0];
} __attribute__ ((packed));


struct e1oip_msg {
	struct e1oip_hdr hdr;
	union {
		struct e1oip_echo echo;
		struct e1oip_tdm_hdr tdm_hdr;
		struct e1oip_service_req service_req;
		struct e1oip_redir_cmd redir_cmd;
		struct e1oip_auth_req auth_req;
		struct e1oip_auth_resp auth_resp;
		struct e1oip_service_ack service_ack;
		struct e1oip_service_rej service_rej;
		struct e1oip_error_ind error_ind;
	} u;
} __attribute__ ((packed));
