/*
 * octoi_clnt_fsm.c - OCTOI Client-side Finite State Machine
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

#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>

#include <osmocom/octoi/octoi.h>
#include <osmocom/octoi/e1oip_proto.h>

#include "octoi_sock.h"
#include "octoi_fsm.h"
#include "e1oip.h"

enum octoi_client_fsm_state {
	CLNT_ST_INIT,
	CLNT_ST_SVC_REQ_SENT,
	CLNT_ST_ACCEPTED,
	CLNT_ST_REJECTED,
	CLNT_ST_REDIRECTED,
};

struct clnt_state {
	struct octoi_peer *peer;

	/* fields filled in locally */
	uint32_t service;
	uint32_t capability_flags;
	struct osmo_timer_list rx_alive_timer;
	struct octoi_account *acc;

	/* fields below are all filled in once received from the remote server side */
	struct {
		char *server_id;
		char *software_id;
		char *software_version;
		uint32_t capability_flags;
	} remote;
};

static void clnt_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct clnt_state *st = fi->priv;

	switch (event) {
	case OCTOI_CLNT_EV_REQUEST_SERVICE:
		octoi_tx_service_req(st->peer, st->service, st->acc->user_id,
				     PACKAGE_NAME, PACKAGE_VERSION, st->capability_flags);
		osmo_fsm_inst_state_chg(fi, CLNT_ST_SVC_REQ_SENT, 10, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void clnt_st_svc_req_sent(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct clnt_state *st = fi->priv;
	struct msgb *msg = NULL;
	//struct e1oip_auth_req *auth_req = NULL;
	struct e1oip_service_ack *svc_ack = NULL;
	struct e1oip_service_rej *svc_rej = NULL;
	//struct e1oip_redir_cmd *redir_cmd = NULL;

	switch (event) {
	case OCTOI_CLNT_EV_RX_AUTH_REQ:
		msg = data;
		//auth_req = msgb_l2(msg);
		/* TODO: implement authentication */
		break;
	case OCTOI_CLNT_EV_RX_SVC_ACK:
		msg = data;
		svc_ack = msgb_l2(msg);
		osmo_talloc_replace_string(st->peer, &st->remote.server_id, svc_ack->server_id);
		osmo_talloc_replace_string(st->peer, &st->remote.software_id, svc_ack->software_id);
		osmo_talloc_replace_string(st->peer, &st->remote.software_version, svc_ack->software_version);
		LOGPFSML(fi, LOGL_NOTICE, "Rx SERVICE_ACK (service=%u, server_id='%s', software_id='%s', "
			 "software_version='%s'\n", ntohl(svc_ack->assigned_service),
			 st->remote.server_id, st->remote.software_id, st->remote.software_version);
		osmo_fsm_inst_state_chg(fi, CLNT_ST_ACCEPTED, 0, 0);
		break;
	case OCTOI_CLNT_EV_RX_SVC_REJ:
		msg = data;
		svc_rej = msgb_l2(msg);
		LOGPFSML(fi, LOGL_NOTICE, "Rx SERVICE_REJ (service=%u, message='%s')\n",
			 ntohl(svc_rej->rejected_service), svc_rej->reject_message);
		osmo_fsm_inst_state_chg(fi, CLNT_ST_REJECTED, 0, 0);
		break;
	case OCTOI_CLNT_EV_RX_REDIR_CMD:
		msg = data;
		//redir_cmd = msgb_l2(msg);
		LOGPFSML(fi, LOGL_NOTICE, "Rx REDIR_CMD, but not yet supported\n");
		osmo_fsm_inst_state_chg(fi, CLNT_ST_REDIRECTED, 0, 0);
		break;
	}
}

static void clnt_st_accepted_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct clnt_state *st = fi->priv;

	st->peer->tdm_permitted = true;
	osmo_timer_schedule(&st->rx_alive_timer, 3, 0);
}

static void clnt_st_accepted(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct clnt_state *st = fi->priv;

	switch (event) {
	case OCTOI_CLNT_EV_RX_AUTH_REQ:
		/* TODO: implement authentication */
		LOGPFSML(fi, LOGL_NOTICE, "Rx AUTH_REQ, but no authentication supported yet!\n");
		break;
	case OCTOI_EV_RX_TDM_DATA:
		e1oip_rcvmsg_tdm_data(st->peer->iline, data);
		break;
	}
}

static void clnt_st_accepted_onleave(struct osmo_fsm_inst *fi, uint32_t next_state)
{
	struct clnt_state *st = fi->priv;

	osmo_timer_del(&st->rx_alive_timer);
	st->peer->tdm_permitted = false;
}

static void clnt_st_rejected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	LOGPFSML(fi, LOGL_ERROR, "Server has rejected service, will not retry until program restart\n");
}

static void clnt_st_redirected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct clnt_state *st = fi->priv;
}


static const struct osmo_fsm_state client_fsm_states[] = {
	[CLNT_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(OCTOI_CLNT_EV_REQUEST_SERVICE),
		.out_state_mask = S(CLNT_ST_SVC_REQ_SENT),
		.action = clnt_st_init,
	},
	[CLNT_ST_SVC_REQ_SENT] = {
		.name = "SVC_REQ_SENT",
		.in_event_mask = S(OCTOI_CLNT_EV_RX_AUTH_REQ) |
				 S(OCTOI_CLNT_EV_RX_SVC_ACK) |
				 S(OCTOI_CLNT_EV_RX_SVC_REJ) |
				 S(OCTOI_CLNT_EV_RX_REDIR_CMD),
		.out_state_mask = S(CLNT_ST_SVC_REQ_SENT) |
				  S(CLNT_ST_ACCEPTED) |
				  S(CLNT_ST_REJECTED) |
				  S(CLNT_ST_REDIRECTED),
		.action = clnt_st_svc_req_sent,
	},
	[CLNT_ST_ACCEPTED] = {
		.name = "ACCEPTED",
		.in_event_mask = S(OCTOI_CLNT_EV_RX_AUTH_REQ) |
				 S(OCTOI_EV_RX_TDM_DATA),
		.out_state_mask = S(CLNT_ST_INIT),
		.action = clnt_st_accepted,
		.onenter = clnt_st_accepted_onenter,
		.onleave = clnt_st_accepted_onleave,
	},
	[CLNT_ST_REJECTED] = {
		.name = "REJECTED",
		.in_event_mask = 0,
		.out_state_mask = 0,
		.onenter = clnt_st_rejected_onenter,
	},
	[CLNT_ST_REDIRECTED] = {
		.name = "REDIRECTED",
		.in_event_mask = 0,
		.out_state_mask = S(CLNT_ST_SVC_REQ_SENT),
		.action = clnt_st_redirected,
	},
};

static void clnt_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct clnt_state *st = fi->priv;
	struct msgb *msg = data;
	struct e1oip_echo *echo_req;
	struct e1oip_error_ind *err_ind;

	switch (event) {
	case OCTOI_EV_RX_ECHO_REQ:
		echo_req = msgb_l2(msg);
		octoi_tx_echo_resp(st->peer, ntohs(echo_req->seq_nr), echo_req->data, msgb_l2len(msg));
		break;
	case OCTOI_EV_RX_ECHO_RESP:
		/* FIXME: update state, peer has responded! */
		break;
	case OCTOI_EV_RX_ERROR_IND:
		err_ind = msgb_l2(msg);
		LOGPFSML(fi, LOGL_ERROR, "Rx OCTOI ERROR IND (cause=0x%08x, msg=%s)\n",
			 ntohl(err_ind->cause), err_ind->error_message);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int clnt_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct clnt_state *st = fi->priv;

	switch (fi->state) {
	case CLNT_ST_SVC_REQ_SENT:
		/* retransmit timer */
		LOGPFSML(fi, LOGL_INFO, "Re-transmitting SERVICE_REQ\n");
		octoi_tx_service_req(st->peer, st->service, st->acc->user_id,
				     PACKAGE_NAME, PACKAGE_VERSION, st->capability_flags);
		osmo_fsm_inst_state_chg(fi, CLNT_ST_SVC_REQ_SENT, 10, 0);
		break;
	}
	return 0;
}

struct osmo_fsm octoi_client_fsm = {
	.name = "OCTOI_CLIENT",
	.states = client_fsm_states,
	.num_states = ARRAY_SIZE(client_fsm_states),
	.allstate_event_mask = S(OCTOI_EV_RX_ECHO_REQ) |
			       S(OCTOI_EV_RX_ECHO_RESP) |
			       S(OCTOI_EV_RX_ERROR_IND),
	.allstate_action = clnt_allstate_action,
	.timer_cb = clnt_fsm_timer_cb,
	.log_subsys = DLINP,
	.event_names = octoi_fsm_event_names,
};

static void clnt_rx_alive_timer_cb(void *data)
{
	struct osmo_fsm_inst *fi = data;
	struct clnt_state *st = fi->priv;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ts.tv_sec - st->peer->last_rx_tdm > 3) {
		LOGPFSML(fi, LOGL_NOTICE, "No TDM data received for >= 3 seconds, declaring peer dead\n");
		osmo_fsm_inst_state_chg(fi, CLNT_ST_INIT, 0, 0);
		osmo_fsm_inst_dispatch(fi, OCTOI_CLNT_EV_REQUEST_SERVICE, NULL);
	} else
		osmo_timer_schedule(&st->rx_alive_timer, 3, 0);
}


/* call-back function for every received OCTOI socket message for given peer */
int octoi_clnt_fsm_rx_cb(struct octoi_peer *peer, struct msgb *msg)
{
	/* ensure peer->priv points to a fsm_inst */
	if (!peer->priv) {
		struct osmo_fsm_inst *fi;
		struct clnt_state *st;

		fi = osmo_fsm_inst_alloc(&octoi_client_fsm, peer, NULL, LOGL_DEBUG, NULL);
		OSMO_ASSERT(fi);

		st = talloc_zero(fi, struct clnt_state);
		OSMO_ASSERT(st);
		st->peer = peer;
		fi->priv = st;

		peer->priv = fi;
	}
	OSMO_ASSERT(peer->priv);

	return _octoi_fsm_rx_cb(peer, msg);
}

/* start the OCTO client FSM for a specified peer */
void octoi_clnt_start_for_peer(struct octoi_peer *peer, struct octoi_account *acc)
{
	OSMO_ASSERT(!peer->sock->cfg.server_mode)

	/* ensure peer->priv points to a fsm_inst */
	if (!peer->priv) {
		struct osmo_fsm_inst *fi;
		struct clnt_state *st;

		fi = osmo_fsm_inst_alloc(&octoi_client_fsm, peer, NULL, LOGL_DEBUG, acc->user_id);
		OSMO_ASSERT(fi);

		st = talloc_zero(fi, struct clnt_state);
		OSMO_ASSERT(st);
		st->peer = peer;
		st->acc = acc;
		st->service = E1OIP_SERVICE_E1_FRAMED;
		st->capability_flags = 0;
		osmo_timer_setup(&st->rx_alive_timer, clnt_rx_alive_timer_cb, fi);
		fi->priv = st;

		peer->priv = fi;
	}
	if (!peer->iline)
		peer->iline = e1oip_line_alloc(peer);

	osmo_fsm_inst_dispatch(peer->priv, OCTOI_CLNT_EV_REQUEST_SERVICE, NULL);
}