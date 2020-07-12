#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/tlv.h>

#include "frame_relay.h"

#define DFR DLGLOBAL

/* Table 4-2/Q.931 */
enum q931_msgtype {
	/* Call establishment message */
	Q931_MSGT_ALERTING		= 0x01,
	Q931_MSGT_CALL_PROCEEDING	= 0x02,
	Q931_MSGT_CONNECT		= 0x07,
	Q931_MSGT_CONNECT_ACK		= 0x0f,
	Q931_MSGT_PROGRESS		= 0x03,
	Q931_MSGT_SETUP			= 0x05,
	Q931_MSGT_SETUP_ACK		= 0x0d,
	/* Call information phase message */
	Q931_MSGT_RESUME		= 0x26,
	Q931_MSGT_RESUME_ACK		= 0x2e,
	Q931_MSGT_RESUME_REJ		= 0x22,
	Q931_MSGT_SUSPEND		= 0x25,
	Q931_MSGT_SUSPEND_ACK		= 0x2d,
	Q931_MSGT_USER_INFO		= 0x20,
	/* Call clearing message */
	Q931_MSGT_DISCONNECT		= 0x45,
	Q931_MSGT_RELEASE		= 0x4d,
	Q931_MSGT_RELEASE_COMPLETE	= 0x5a,
	Q931_MSGT_RESTART		= 0x46,
	Q931_MSGT_RESTART_ACK		= 0x4e,
	/* Miscellaneous messages */
	Q931_MSGT_SEGMENT		= 0x60,
	Q931_MSGT_CONGESTION_CONTROL	= 0x79,
	Q931_MSGT_IFORMATION		= 0x7b,
	Q931_MSGT_NOTIFY		= 0x6e,
	Q931_MSGT_STATUS		= 0x7d,
	Q931_MSGT_STATUS_ENQUIRY	= 0x75,
};


/* Figure A.1/Q.933 Report type information element */
enum q933_type_of_report {
	Q933_REPT_FULL_STATUS		= 0x00,
	Q933_REPT_LINK_INTEGRITY_VERIF	= 0x01,
	Q933_REPT_SINGLE_PVC_ASYNC_STS	= 0x02,
};

/* Q.933 Section A.3 */
enum q933_iei {
	Q933_IEI_REPORT_TYPE		= 0x51,
	Q933_IEI_LINK_INT_VERIF		= 0x53,
	Q933_IEI_PVC_STATUS		= 0x57,
};

#define LAPF_UI			0x03	/* UI control word */
#define Q931_PDISC_CC		0x08	/* protocol discriminator */
#define LMI_Q933A_CALLREF	0x00	/* NULL call-ref */

/* LMI DLCI values */
#define LMI_Q933A_DLCI		0	/* Q.933A DLCI */
#define LMI_CISCO_DLCI		1023	/* Cisco DLCI */


/* Message header of the L3 payload of a Q.933 Annex A message */
struct q933_a_hdr {
	uint8_t prot_disc;
	uint8_t call_ref;
	uint8_t msg_type;
} __attribute__((packed));

/* Value part of the Q.933 Annex A.3.3 IE */
struct q933_a_pvc_sts {
	uint8_t ext0:1,
		spare:1,
		dlci_msb:6;
	uint8_t ext1:1,
		dlci_lsb:4,
		spare1:3;
	uint8_t ext2:1,
		spare2:3,
		new:1,
		delete:1,
		active:1,
		reserved:1;
} __attribute__((packed));

// RX Message: 14 [ 00 01 03 08 00 75  95 01 01 00 03 02 01 00 ]
// RX Message: 13 [ 00 01 03 08 00 75  51 01 00  53 02 01 00 ]

/* Table A.4/Q.933 */
struct osmo_tdef fr_tdefs[] = {
	{
		.T=391,
		.default_val = 10,
		.min_val = 5,
		.max_val = 30,
		.desc = "Link integrity verification polling timer"
	}, {
		.T=392,
		.default_val = 15,
		.min_val = 5,
		.max_val = 30,
		.desc = "Polling verification timer"
	},
	{}
};

static const struct tlv_definition q933_att_tlvdef = {
	.def = {
		[Q933_IEI_REPORT_TYPE] = { TLV_TYPE_TLV },
		[Q933_IEI_LINK_INT_VERIF] = { TLV_TYPE_TLV },
		[Q933_IEI_PVC_STATUS] = { TLV_TYPE_TLV },
	},
};

static inline uint16_t q922_to_dlci(const uint8_t *hdr)
{
	return ((hdr[0] & 0xFC) << 2) | ((hdr[1] & 0xF0) >> 4);
}


static inline void dlci_to_q922(uint8_t *hdr, uint16_t dlci)
{
	hdr[0] = (dlci >> 2) & 0xFC;
	hdr[1] = ((dlci << 4) & 0xF0) | 0x01;
}

/* allocate a message buffer and put Q.933 Annex A headers (L2 + L3) */
static struct msgb *q933_msgb_alloc(uint16_t dlci, uint8_t prot_disc, uint8_t msg_type)
{
	struct msgb *msg = msgb_alloc_headroom(1600+64, 64, "FR Q.933 Tx");
	struct q933_a_hdr *qh;

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, 2);
	dlci_to_q922(msg->l1h, dlci);

	/* LAPF UI control */
	msg->l2h = msgb_put(msg, 1);
	*msg->l2h = LAPF_UI;

	msg->l3h = msgb_put(msg, sizeof(*qh));
	qh = (struct q933_a_hdr *) msg->l3h;
	qh->prot_disc = prot_disc;
	qh->call_ref = LMI_Q933A_CALLREF;
	qh->msg_type = msg_type;

	return msg;
}

/* obtain the [next] transmit sequence number */
static uint8_t fr_link_get_tx_seq(struct fr_link *link)
{
	/* The {user equipment, network} increments the send sequence
	 * counter using modulo 256. The value zero is skipped. */
	link->last_tx_seq++;
	if (link->last_tx_seq == 0)
		link->last_tx_seq++;

	return link->last_tx_seq;
}

/* Append PVC Status IE according to Q.933 A.3.2 */
static void msgb_put_link_int_verif(struct msgb *msg, struct fr_link *link)
{
	uint8_t link_int_tx[2];
	link_int_tx[0] = fr_link_get_tx_seq(link);
	link_int_tx[1] = link->last_rx_seq;
	msgb_tlv_put(msg, Q933_IEI_LINK_INT_VERIF, 2, link_int_tx);
}

static void dlc_destroy(struct fr_dlc *dlc)
{
	llist_del(&dlc->list);
	talloc_free(dlc);
}

/* Append PVC Status IE according to Q.933 A.3.3 */
static void msgb_put_pvc_status(struct msgb *msg, struct fr_dlc *dlc)
{
	uint8_t ie[3];

	ie[0] = (dlc->dlci >> 4) & 0x3f;
	ie[1] = 0x80 | ((dlc->dlci & 0xf) << 3);
	ie[2] = 0x80;

	if (dlc->active)
		ie[2] |= 0x02;

	if (dlc->new) {
		ie[2] |= 0x08;
		/* we've reported it as new once, reset the status */
		dlc->new = false;
	}

	if (dlc->del) {
		ie[2] |= 0x04;
		/* we've reported it as deleted once, destroy it */
		dlc_destroy(dlc);
	}

	msgb_tlv_put(msg, Q933_IEI_PVC_STATUS, 3, ie);
}

/* Send a Q.933 STATUS ENQUIRY given type over given link */
static int tx_lmi_q933_status_enq(struct fr_link *link, uint8_t rep_type)
{
	struct msgb *resp;

	resp = q933_msgb_alloc(0, Q931_PDISC_CC, Q931_MSGT_STATUS_ENQUIRY);
	if (!resp)
		return -1;
	resp->dst = link;

	/* Table A.2/Q.933 */
	msgb_tlv_put(resp, Q933_IEI_REPORT_TYPE, 1, &rep_type);
	msgb_put_link_int_verif(resp, link);

	return fr_tx(resp);
}

/* Send a Q.933 STATUS of given type over given link */
static int tx_lmi_q933_status(struct fr_link *link, uint8_t rep_type)
{
	struct fr_dlc *dlc, *dlc2;
	struct msgb *resp;

	resp = q933_msgb_alloc(0, Q931_PDISC_CC, Q931_MSGT_STATUS);
	if (!resp)
		return -1;
	resp->dst = link;

	/* Table A.1/Q.933 */
	msgb_tlv_put(resp, Q933_IEI_REPORT_TYPE, 1, &rep_type);
	switch (rep_type) {
	case Q933_REPT_FULL_STATUS:
		msgb_put_link_int_verif(resp, link);
		llist_for_each_entry_safe(dlc, dlc2, &link->dlc_list, list)
			msgb_put_pvc_status(resp, dlc);
		break;
	case Q933_REPT_LINK_INTEGRITY_VERIF:
		msgb_put_link_int_verif(resp, link);
		break;
	case Q933_REPT_SINGLE_PVC_ASYNC_STS:
		llist_for_each_entry_safe(dlc, dlc2, &link->dlc_list, list)
			msgb_put_pvc_status(resp, dlc);
		break;
	}

	return fr_tx(resp);
}


/* Q.933 */
static int rx_lmi_q933_status_enq(struct msgb *msg, struct tlv_parsed *tp)
{
	struct fr_link *link = msg->dst;
	const uint8_t *link_int_rx;
	uint8_t rep_type;

	/* check for mandatory IEs */
	if (!TLVP_PRES_LEN(tp, Q933_IEI_REPORT_TYPE, 1) ||
	    !TLVP_PRES_LEN(tp, Q933_IEI_LINK_INT_VERIF, 2))
		return -1;

	rep_type = *TLVP_VAL(tp, Q933_IEI_REPORT_TYPE);

	link_int_rx = TLVP_VAL(tp, Q933_IEI_LINK_INT_VERIF);
	link->last_rx_seq = link_int_rx[0];

	/* the network checks the receive sequence number received from
	 * the user equipment against its send sequence counter */
	if (link_int_rx[1] != link->last_tx_seq)
		link->err_count++;

	/* The network responds to each STATUS ENQUIRY message with a
	 * STATUS message and resets the T392 timer */
	osmo_timer_schedule(&link->t392, osmo_tdef_get(link->net->T_defs, 392, OSMO_TDEF_S, 15), 0);

	return tx_lmi_q933_status(link, rep_type);
}

static int rx_lmi_q933_status(struct msgb *msg, struct tlv_parsed *tp)
{
	struct fr_link *link = msg->dst;
	const uint8_t *link_int_rx;
	uint8_t rep_type;

	/* check for mandatory IEs */
	if (!TLVP_PRES_LEN(tp, Q933_IEI_REPORT_TYPE, 1))
		return -1;
	rep_type = *TLVP_VAL(tp, Q933_IEI_REPORT_TYPE);

	switch (rep_type) {
	case Q933_REPT_FULL_STATUS:
	case Q933_REPT_LINK_INTEGRITY_VERIF:
		if (!TLVP_PRES_LEN(tp, Q933_IEI_LINK_INT_VERIF, 2))
			return -1;
		link_int_rx = TLVP_VAL(tp, Q933_IEI_LINK_INT_VERIF);
		link->last_rx_seq = link_int_rx[0];
		/* The received receive sequence number is not valid if
		 * it is not equal to the last transmitted send sequence
		 * number. Ignore messages containing this error. As a
		 * result, timer T391 expires and the user then
		 * increments the error count. */
		if (link_int_rx[1] != link->last_tx_seq)
			return 0;
		break;
	case Q933_REPT_SINGLE_PVC_ASYNC_STS:
		break;
	default:
		return -1;
	}

	/* FIXME: process any PVC Status IEs */

	/* The network responds to each STATUS ENQUIRY message with a
	 * STATUS message and resets the T392 timer */
	osmo_timer_schedule(&link->t392, osmo_tdef_get(link->net->T_defs, 392, OSMO_TDEF_S, 15), 0);

	return tx_lmi_q933_status(link, rep_type);
}


static int fr_rx_lmi_q922(struct msgb *msg)
{
	struct q933_a_hdr *qh;
	struct tlv_parsed tp;
	uint8_t *lapf;
	int rc;

	if (msgb_l2len(msg) < 1)
		return -1;
	lapf = msgb_l2(msg);

	/* we only support LAPF UI frames */
	if (lapf[0] != LAPF_UI)
		return -1;

	msg->l3h = msg->l2h + 1;
	if (msgb_l3len(msg) < 3)
		return -1;

	qh = (struct q933_a_hdr *) msgb_l3(msg);
	if (qh->prot_disc != Q931_PDISC_CC) {
		LOGP(DFR, LOGL_NOTICE, "Rx unsupported LMI protocol discriminator %u\n", qh->prot_disc);
		return -1;
	}

	tlv_parse(&tp, &q933_att_tlvdef, msgb_l3(msg) + sizeof(*qh), msgb_l3len(msg) - sizeof(*qh), 0, 0);

	switch (qh->msg_type) {
	case Q931_MSGT_STATUS_ENQUIRY:
		rc = rx_lmi_q933_status_enq(msg, &tp);
		break;
	case Q931_MSGT_STATUS:
		rc = rx_lmi_q933_status(msg, &tp);
		break;
	default:
		LOGP(DFR, LOGL_NOTICE, "Rx unsupported LMI message type %u\n", qh->msg_type);
		rc = -1;
		break;
	}
	msgb_free(msg);

	return rc;
}

int fr_rx(struct fr_link *link, struct msgb *msg)
{
	uint8_t *frh;
	uint16_t dlci;
	struct fr_dlc *dlc;

	msg->dst = link;

	if (msgb_length(msg) < 2) {
		LOGP(DFR, LOGL_ERROR, "Short FR header: %u bytes\n", msgb_length(msg));
		msgb_free(msg);
		return -1;
	}

	frh = msg->l1h = msgb_data(msg);
	if (frh[0] & 0x01) {
		LOGP(DFR, LOGL_NOTICE, "Unsupported single-byte FR address\n");
		msgb_free(msg);
		return 1;
	}
	if ((frh[1] & 0x0f) != 0x01) {
		LOGP(DFR, LOGL_NOTICE, "Unknown second FR octet 0x%02x\n", frh[1]);
		msgb_free(msg);
		return -1;
	}
	dlci = q922_to_dlci(frh);
	msg->l2h = frh + 2;

	switch (dlci) {
	case LMI_Q933A_DLCI:
		return fr_rx_lmi_q922(msg);
	case LMI_CISCO_DLCI:
		LOGP(DFR, LOGL_NOTICE, "Unsupported FR DLCI %u\n", dlci);
		msgb_free(msg);
		return 0;
	}

	llist_for_each_entry(dlc, &link->dlc_list, list) {
		if (dlc->dlci == dlci) {
			/* dispatch to handler of respective DLC */
			return dlc->rx_cb(dlc, msg);
		}
	}

	if (link->unknown_dlc_rx_cb)
		return link->unknown_dlc_rx_cb(NULL, msg);
	else
		LOGP(DFR, LOGL_NOTICE, "DLCI %u doesn't exist, discarding\n", dlci);

	return 0;
}





/* Every T391 seconds, the user equipment sends a STATUS ENQUIRY
 * message to the network and resets its polling timer (T391). */
static void fr_t391_cb(void *data)
{
	struct fr_link *link = data;

	if (link->polling_count % link->net->n391 == 0)
		tx_lmi_q933_status_enq(link, Q933_REPT_FULL_STATUS);
	else
		tx_lmi_q933_status_enq(link, Q933_REPT_LINK_INTEGRITY_VERIF);
	link->polling_count++;
	osmo_timer_schedule(&link->t391, osmo_tdef_get(link->net->T_defs, 391, OSMO_TDEF_S, 10), 0);
}

static void fr_t392_cb(void *data)
{
	struct fr_link *link = data;
	/* A.5 The network increments the error count .. Non-receipt of
	 * a STATUS ENQUIRY within T392, which results in restarting
	 * T392 */
	link->err_count++;
	osmo_timer_schedule(&link->t392, osmo_tdef_get(link->net->T_defs, 392, OSMO_TDEF_S, 15), 0);
}

/* allocate a frame relay network */
struct fr_network *fr_network_alloc(void *ctx)
{
	struct fr_network *net = talloc_zero(ctx, struct fr_network);

	INIT_LLIST_HEAD(&net->links);
	net->T_defs = fr_tdefs;
	net->n391 = 6;
	net->n392 = 3;
	net->n393 = 4;

	return net;
}

/* allocate a frame relay link in a given network */
struct fr_link *fr_link_alloc(struct fr_network *net)
{
	struct fr_link *link = talloc_zero(net, struct fr_link);
	if (!link)
		return NULL;

	link->net = net;
	INIT_LLIST_HEAD(&link->dlc_list);
	osmo_timer_setup(&link->t391, fr_t391_cb, link);
	osmo_timer_setup(&link->t392, fr_t392_cb, link);

	/* TODO: schedule any timers */

	llist_add_tail(&link->list, &net->links);

	return link;
}

/* allocate a data link connectoin on a given framerelay link */
struct fr_dlc *fr_dlc_alloc(struct fr_link *link, uint16_t dlci)
{
	struct fr_dlc *dlc = talloc_zero(link, struct fr_dlc);
	if (!dlc)
		return NULL;

	dlc->link = link;
	dlc->dlci = dlci;
	dlc->active = true; // FIXME: HACK

	llist_add_tail(&dlc->list, &link->dlc_list);

	dlc->new = true;
	tx_lmi_q933_status(link, Q933_IEI_PVC_STATUS);

	return dlc;
}
