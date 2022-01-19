/*
 * octoi_fsm.c - OCTOI Protocol / Finite State Machine interface
 *
 * (C) 2022 by Harald Welte <laforge@osmocom.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>

#include <osmocom/octoi/e1oip_proto.h>

#include "octoi_sock.h"
#include "octoi_fsm.h"


const struct value_string octoi_fsm_event_names[] = {
	{ OCTOI_EV_RX_TDM_DATA,		"RX_TDM_DATA" },
	{ OCTOI_EV_RX_ECHO_REQ,		"RX_ECHO_REQ" },
	{ OCTOI_EV_RX_ECHO_RESP,	"RX_ECHO_RESP" },
	{ OCTOI_EV_RX_ERROR_IND,	"RX_ERROR_IND" },

	{ OCTOI_SRV_EV_RX_SERVICE_REQ,	"RX_SERVICE_REQ" },
	{ OCTOI_SRV_EV_RX_AUTH_VEC,	"RX_AUTH_VEC" },
	{ OCTOI_SRV_EV_RX_AUTH_RESP,	"RX_AUTH_RESP" },

	{ OCTOI_CLNT_EV_REQUEST_SERVICE,"REQUEST_SERVICE" },
	{ OCTOI_CLNT_EV_RX_AUTH_REQ,	"RX_AUTH_REQ" },
	{ OCTOI_CLNT_EV_RX_SVC_ACK,	"RX_SERVICE_ACK" },
	{ OCTOI_CLNT_EV_RX_SVC_REJ,	"RX_SERVICE_REJ" },
	{ OCTOI_CLNT_EV_RX_REDIR_CMD,	"RX_REDIR_CMD" },
	{ 0, NULL }
};

/* ensure given fixed-length string is zero-terminated */
#define ENSURE_ZERO_TERM(x) ensure_zero_term(x, sizeof(x))
static void ensure_zero_term(char *buf, size_t len)
{
	for (unsigned int i = 0; i < len; i++) {
		if (buf[i] == '\0')
			return;
	}
	buf[len-1] = '\0';
}

/* verify if the given OCTOI message is consistent */
static bool octoi_msg_validate(struct osmo_fsm_inst *fi, struct msgb *msg)
{
	struct e1oip_msg *eip = msgb_l1(msg);

	/* ensure that the minimum length is >= header length, and that the version matches */
	if (msgb_l1len(msg) < sizeof(eip->hdr)) {
		LOGPFSML(fi, LOGL_INFO, "Rx short message (%u < %zu)\n", msgb_l1len(msg), sizeof(eip->hdr));
		return false;
	}
	if (eip->hdr.version != E1OIP_VERSION) {
		LOGPFSML(fi, LOGL_INFO, "Rx unsupported version (%u != %u)\n", eip->hdr.version,
			 E1OIP_VERSION);
		return false;
	}

	switch (eip->hdr.msg_type) {
	case E1OIP_MSGT_ECHO_REQ:
		if (msgb_l2len(msg) < sizeof(eip->u.echo))
			goto err_msg_len;
		break;
	case E1OIP_MSGT_ECHO_RESP:
		if (msgb_l2len(msg) < sizeof(eip->u.echo))
			goto err_msg_len;
		break;
	case E1OIP_MSGT_TDM_DATA:
		if (msgb_l2len(msg) < sizeof(eip->u.tdm_hdr))
			goto err_msg_len;
		break;
	case E1OIP_MSGT_SERVICE_REQ:
		if (msgb_l2len(msg) < sizeof(eip->u.service_req))
			goto err_msg_len;
		ENSURE_ZERO_TERM(eip->u.service_req.subscriber_id);
		ENSURE_ZERO_TERM(eip->u.service_req.software_id);
		ENSURE_ZERO_TERM(eip->u.service_req.software_version);
		break;
	case E1OIP_MSGT_SERVICE_ACK:
		if (msgb_l2len(msg) < sizeof(eip->u.service_ack))
			goto err_msg_len;
		ENSURE_ZERO_TERM(eip->u.service_ack.server_id);
		ENSURE_ZERO_TERM(eip->u.service_ack.software_id);
		ENSURE_ZERO_TERM(eip->u.service_ack.software_version);
		break;
	case E1OIP_MSGT_SERVICE_REJ:
		if (msgb_l2len(msg) < sizeof(eip->u.service_rej))
			goto err_msg_len;
		ENSURE_ZERO_TERM(eip->u.service_rej.reject_message);
		break;
	case E1OIP_MSGT_REDIR_CMD:
		if (msgb_l2len(msg) < sizeof(eip->u.redir_cmd))
			goto err_msg_len;
		ENSURE_ZERO_TERM(eip->u.redir_cmd.server_ip);
		break;
	case E1OIP_MSGT_AUTH_REQ:
		if (msgb_l2len(msg) < sizeof(eip->u.auth_req))
			goto err_msg_len;
		if (eip->u.auth_req.rand_len > sizeof(eip->u.auth_req.rand))
			goto err_ie_len;
		if (eip->u.auth_req.autn_len > sizeof(eip->u.auth_req.autn))
			goto err_ie_len;
		break;
	case E1OIP_MSGT_AUTH_RESP:
		if (msgb_l2len(msg) < sizeof(eip->u.auth_resp))
			goto err_msg_len;
		if (eip->u.auth_resp.res_len > sizeof(eip->u.auth_resp.res))
			goto err_ie_len;
		if (eip->u.auth_resp.auts_len > sizeof(eip->u.auth_resp.auts))
			goto err_ie_len;
		break;
	case E1OIP_MSGT_ERROR_IND:
		if (msgb_l2len(msg) < sizeof(eip->u.error_ind))
			goto err_msg_len;
		ENSURE_ZERO_TERM(eip->u.error_ind.error_message);
		break;
	default:
		LOGPFSML(fi, LOGL_NOTICE, "Rx unknown OCTOI message type 0x%02x\n", eip->hdr.msg_type);
		return false;
	}

	return true;

err_msg_len:
	LOGPFSML(fi, LOGL_NOTICE, "Rx truncated OCTOI message 0x%02x\n", eip->hdr.msg_type);
	return false;

err_ie_len:
	LOGPFSML(fi, LOGL_NOTICE, "Rx invalid IE length in OCTOI message 0x%02x\n", eip->hdr.msg_type);
	return false;
}


/* call-back function for every received OCTOI socket message for given peer */
int _octoi_fsm_rx_cb(struct octoi_peer *peer, struct msgb *msg)
{
	struct osmo_fsm_inst *fi = peer->priv;
	struct e1oip_hdr *e1h = msgb_l1(msg);

	OSMO_ASSERT(fi);
	OSMO_ASSERT(msgb_l1(msg));
	OSMO_ASSERT(msgb_l2(msg));

	if (!octoi_msg_validate(fi, msg))
		return -1;

	switch (e1h->msg_type) {
	case E1OIP_MSGT_TDM_DATA:
		osmo_fsm_inst_dispatch(fi, OCTOI_EV_RX_TDM_DATA, msg);
		break;
	case E1OIP_MSGT_ECHO_REQ:
		osmo_fsm_inst_dispatch(fi, OCTOI_EV_RX_ECHO_REQ, msg);
		break;
	case E1OIP_MSGT_ECHO_RESP:
		osmo_fsm_inst_dispatch(fi, OCTOI_EV_RX_ECHO_RESP, msg);
		break;
	case E1OIP_MSGT_ERROR_IND:
		osmo_fsm_inst_dispatch(fi, OCTOI_EV_RX_ERROR_IND, msg);
		break;

	case E1OIP_MSGT_SERVICE_REQ:
		osmo_fsm_inst_dispatch(fi, OCTOI_SRV_EV_RX_SERVICE_REQ, msg);
		break;
	case E1OIP_MSGT_AUTH_RESP:
		osmo_fsm_inst_dispatch(fi, OCTOI_SRV_EV_RX_AUTH_RESP, msg);
		break;

	case E1OIP_MSGT_SERVICE_ACK:
		osmo_fsm_inst_dispatch(fi, OCTOI_CLNT_EV_RX_SVC_ACK, msg);
		break;
	case E1OIP_MSGT_SERVICE_REJ:
		osmo_fsm_inst_dispatch(fi, OCTOI_CLNT_EV_RX_SVC_REJ, msg);
		break;
	case E1OIP_MSGT_REDIR_CMD:
		osmo_fsm_inst_dispatch(fi, OCTOI_CLNT_EV_RX_REDIR_CMD, msg);
		break;
	case E1OIP_MSGT_AUTH_REQ:
		osmo_fsm_inst_dispatch(fi, OCTOI_CLNT_EV_RX_AUTH_REQ, msg);
		break;

	default:
		LOGPFSML(fi, LOGL_NOTICE, "Rx Unknown OCTOI message type 0x%02x\n", e1h->msg_type);
		break;
	}

	msgb_free(msg);
	return 0;
}

#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>
#include "e1oip.h"

void vty_show_octoi_sock(struct vty *vty, struct octoi_sock *sock)
{
	struct octoi_peer *peer;

	vty_out(vty, "OCTOI %s Socket on "OSMO_SOCKADDR_STR_FMT"%s",
		sock->cfg.server_mode ? "Server" : "Client",
		OSMO_SOCKADDR_STR_FMT_ARGS(&sock->cfg.local), VTY_NEWLINE);

	llist_for_each_entry(peer, &sock->peers, list) {
		vty_out(vty, " Peer '%s', Remote "OSMO_SOCKADDR_STR_FMT", State %s%s",
			peer->name, OSMO_SOCKADDR_STR_FMT_ARGS(&peer->cfg.remote),
			osmo_fsm_inst_state_name(peer->priv), VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, "  ", peer->iline->ctrs);
		vty_out_stat_item_group(vty, "  ", peer->iline->stats);
	}
}
