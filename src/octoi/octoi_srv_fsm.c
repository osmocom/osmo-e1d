/*
 * octoi_srv_fsm.c - OCTOI Server-side Finite State Machine
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
#include <osmocom/core/timer.h>

#include <osmocom/octoi/octoi.h>
#include <osmocom/octoi/e1oip_proto.h>

#include "octoi.h"
#include "octoi_sock.h"
#include "octoi_fsm.h"
#include "e1oip.h"

#define SUPPORTED_CAPABILITIES	0x00000000

enum octoi_server_fsm_state {
	SRV_ST_INIT,			/* just created [for new client] */
	SRV_ST_WAIT_AUTH_VEC,		/* service request from client */
	SRV_ST_WAIT_AUTH_RESP,		/* auth req sent, wait for auth resp */
	SRV_ST_ACCEPTED,		/* service accepted */
	SRV_ST_REJECTED,		/* service rejected */
	SRV_ST_REDIRECTED,		/* service redirected */
};

struct srv_state {
	struct octoi_peer *peer;	/* peer to which we belong */
	uint32_t service;		/* service we are providing */
	uint32_t capability_flags;	/* negotiated capabilities */
	struct {
		char *subscriber_id;
		char *software_id;
		char *software_version;
		uint32_t capability_flags;
	} remote;
	struct osmo_timer_list rx_alive_timer;
	struct octoi_account *acc;
	void *app_priv;			/* application private data */
	const char *rej_str;
	struct {
		struct osmo_timer_list timer;
		struct timespec last_tx_ts;
		uint16_t last_tx_seq;
	} echo_req;
};

static void srv_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct srv_state *st = fi->priv;
	struct octoi_server *srv = st->peer->priv;
	struct octoi_account *acc;
	struct msgb *msg = data;
	struct e1oip_service_req *srv_req = NULL;
	uint32_t service;

	switch (event) {
	case OCTOI_SRV_EV_RX_SERVICE_REQ:
		srv_req = (struct e1oip_service_req *) msgb_l2(msg);
		service = ntohl(srv_req->requested_service);
		LOGPFSML(fi, LOGL_INFO, "Rx SERVICE REQ (service=%u, subscriber='%s', "
			 "software='%s'/'%s', capabilities=0x%08x)\n", service,
			srv_req->subscriber_id, srv_req->software_id, srv_req->software_version,
			htonl(srv_req->capability_flags));
		if (service != E1OIP_SERVICE_E1_FRAMED) {
			osmo_fsm_inst_state_chg(fi, SRV_ST_REJECTED, 0, 0);
			octoi_tx_service_rej(st->peer, service, "Unsupported service");
			break;
		}
		/* fill peer structure with parameters received */
		st->service = service;
		osmo_fsm_inst_update_id(fi, srv_req->subscriber_id);
		osmo_talloc_replace_string(st->peer, &st->remote.subscriber_id, srv_req->subscriber_id);
		osmo_talloc_replace_string(st->peer, &st->remote.software_id, srv_req->software_id);
		osmo_talloc_replace_string(st->peer, &st->remote.software_version, srv_req->software_version);
		st->remote.capability_flags = ntohl(srv_req->capability_flags);
		/* intersect capabilities */
		st->capability_flags = st->remote.capability_flags & SUPPORTED_CAPABILITIES;

		/* TODO: later we would want to start looking up the subscriber in the HLR
		 * and request authentication tuples. */

		/* check subscriber */
		acc = octoi_account_find(st->peer->sock->priv, st->remote.subscriber_id);
		if (!acc) {
			LOGPFSML(fi, LOGL_NOTICE, "Could not find user account %s, rejecting\n",
				 st->remote.subscriber_id);
			st->rej_str = "Unknown user";
			goto reject;
		}
		st->acc = acc;

		switch (acc->mode) {
		case ACCOUNT_MODE_ICE1USB:
		case ACCOUNT_MODE_DAHDI_TRUNKDEV:
			/* check if a matching device exists for that account */
			st->app_priv = g_octoi->ops->client_connected(srv, st->peer, acc);
			if (!st->app_priv) {
				LOGPFSML(fi, LOGL_NOTICE, "Could not find E1 line for account %s, "
					 "rejecting\n", acc->user_id);
				st->rej_str = "No line for user";
				goto reject;
			}
			osmo_talloc_replace_string(st->peer, &st->peer->name, acc->user_id);
			e1oip_line_set_name(st->peer->iline, acc->user_id);
			osmo_fsm_inst_state_chg(fi, SRV_ST_ACCEPTED, 0, 0);
			octoi_tx_service_ack(st->peer, st->service, "TODO-SRV", PACKAGE_NAME,
						PACKAGE_VERSION, st->capability_flags);
			break;
		case ACCOUNT_MODE_REDIRECT:
			octoi_tx_redir_cmd(st->peer, acc->u.redirect.to.ip, acc->u.redirect.to.port);
			osmo_fsm_inst_state_chg(fi, SRV_ST_REDIRECTED, 10, 0);
			break;
		case ACCOUNT_MODE_NONE:
			LOGPFSML(fi, LOGL_NOTICE, "User account %s has mode 'none', rejecting\n",
				 acc->user_id);
			/* fall through */
		default:
			st->rej_str = "Unsupported mode for user";
			goto reject;
			break;
		}
		break;
	default:
		OSMO_ASSERT(0);
	}

	return;

reject:
	octoi_tx_service_rej(st->peer, st->service, st->rej_str);
	osmo_fsm_inst_state_chg(fi, SRV_ST_REJECTED, 10, 0);
}

static void srv_st_wait_auth_vec(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case OCTOI_SRV_EV_RX_AUTH_VEC:
		/* TODO */
		//octoi_tx_auth_req(peer,
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srv_st_wait_auth_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case OCTOI_SRV_EV_RX_AUTH_RESP:
		/* TODO */
	default:
		OSMO_ASSERT(0);
	}
}

static void srv_st_accepted_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct srv_state *st = fi->priv;

	e1oip_line_configure(st->peer->iline, st->acc->batching_factor,
			     st->acc->prefill_frame_count);
	/* reset RIFO/FIFO etc. */
	e1oip_line_reset(st->peer->iline);
	iline_ctr_add(st->peer->iline, LINE_CTR_E1oIP_CONNECT_ACCEPT, 1);

	st->peer->tdm_permitted = true;
	osmo_timer_schedule(&st->rx_alive_timer, 3, 0);
	osmo_timer_schedule(&st->echo_req.timer, 10, 0);
}

static void srv_st_accepted(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct srv_state *st = fi->priv;

	switch (event) {
	case OCTOI_SRV_EV_RX_AUTH_RESP: /* Rx re-transmission from client side */
		/* re-transmit ack */
		octoi_tx_service_ack(st->peer, st->service, "TODO-SRV", PACKAGE_NAME,
					PACKAGE_VERSION, st->capability_flags);
		osmo_timer_schedule(&st->rx_alive_timer, 3, 0);
		break;
	case OCTOI_EV_RX_TDM_DATA:
		e1oip_rcvmsg_tdm_data(st->peer->iline, data);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srv_st_accepted_onleave(struct osmo_fsm_inst *fi, uint32_t next_state)
{
	struct srv_state *st = fi->priv;

	osmo_timer_del(&st->echo_req.timer);
	osmo_timer_del(&st->rx_alive_timer);
	st->peer->tdm_permitted = false;
}

static void srv_st_rejected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct srv_state *st = fi->priv;

	switch (event) {
	case OCTOI_SRV_EV_RX_SERVICE_REQ:
	case OCTOI_SRV_EV_RX_AUTH_RESP: /* Rx re-transmission from client side */
		octoi_tx_service_rej(st->peer, st->service, st->rej_str);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void srv_st_redirected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct srv_state *st = fi->priv;

	switch (event) {
	case OCTOI_SRV_EV_RX_SERVICE_REQ:
	case OCTOI_SRV_EV_RX_AUTH_RESP: /* Rx re-transmission from client side */
		octoi_tx_redir_cmd(st->peer, st->acc->u.redirect.to.ip, st->acc->u.redirect.to.port);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static const struct osmo_fsm_state server_fsm_states[] = {
	[SRV_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(OCTOI_SRV_EV_RX_SERVICE_REQ), /* retransmit */
		.out_state_mask = S(SRV_ST_WAIT_AUTH_VEC) | S(SRV_ST_ACCEPTED) | S(SRV_ST_REJECTED),
		.action = srv_st_init,
	},
	[SRV_ST_WAIT_AUTH_VEC] = {
		.name = "WAIT_AUTH_VEC",
		.in_event_mask = S(OCTOI_SRV_EV_RX_AUTH_VEC),
		.out_state_mask = S(SRV_ST_WAIT_AUTH_RESP) | S(SRV_ST_REJECTED),
		.action = srv_st_wait_auth_vec,
	},
	[SRV_ST_WAIT_AUTH_RESP] = {
		.name = "WAIT_AUTH_RESP",
		.in_event_mask = S(OCTOI_SRV_EV_RX_AUTH_RESP),
		.out_state_mask = S(SRV_ST_ACCEPTED) | S(SRV_ST_REJECTED) | S(SRV_ST_REDIRECTED),
		.action = srv_st_wait_auth_resp,
	},
	[SRV_ST_ACCEPTED] = {
		.name = "ACCEPTED",
		.in_event_mask = S(OCTOI_SRV_EV_RX_AUTH_RESP) | /* retransmit */
				 S(OCTOI_EV_RX_TDM_DATA),
		.action = srv_st_accepted,
		.onenter = srv_st_accepted_onenter,
		.onleave = srv_st_accepted_onleave,
	},
	[SRV_ST_REJECTED] = {
		.name = "REJECTED",
		.in_event_mask = S(OCTOI_SRV_EV_RX_SERVICE_REQ) | /* retransmit */
				 S(OCTOI_SRV_EV_RX_AUTH_RESP), /* retransmit */
		.action = srv_st_rejected,
	},
	[SRV_ST_REDIRECTED] = {
		.name = "REDIRECTED",
		.in_event_mask = S(OCTOI_SRV_EV_RX_SERVICE_REQ) | /* retransmit */
				 S(OCTOI_SRV_EV_RX_AUTH_RESP), /* retransmit */
		.action = srv_st_redirected,
	},
};

static void srv_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct srv_state *st = fi->priv;
	struct msgb *msg = data;
	struct e1oip_echo *echo_req, *echo_resp;
	struct e1oip_error_ind *err_ind;
	int32_t rtt_us;

	switch (event) {
	case OCTOI_EV_RX_ECHO_REQ:
		echo_req = msgb_l2(msg);
		LOGPFSML(fi, LOGL_DEBUG, "Rx OCTOI ECHO_REQ (seq=%u)\n", ntohs(echo_req->seq_nr));
		octoi_tx_echo_resp(st->peer, ntohs(echo_req->seq_nr), echo_req->data, msgb_l2len(msg));
		break;
	case OCTOI_EV_RX_ECHO_RESP:
		echo_resp = msgb_l2(msg);
		if (ntohs(echo_resp->seq_nr) != st->echo_req.last_tx_seq) {
			LOGPFSML(fi, LOGL_NOTICE, "Rx OCTOI ECHO RESP (seq=%u) doesn't match our last "
				 "request (seq=%u)\n", ntohs(echo_resp->seq_nr), st->echo_req.last_tx_seq);
			break;
		}
		rtt_us = ts_us_ago(&st->echo_req.last_tx_ts);
		iline_stat_set(st->peer->iline, LINE_STAT_E1oIP_RTT, rtt_us);
		LOGPFSML(fi, LOGL_INFO, "Rx OCTOI ECHO_RESP (seq=%u, rtt=%d)\n",
			 ntohs(echo_resp->seq_nr), rtt_us);
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

static int srv_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->state) {
	case SRV_ST_REJECTED:
	case SRV_ST_REDIRECTED:
		/* 10s timeout has expired, we can now forget about this peer */
		/* request termination */
		return 1;
	}

	return 0;
}

static void srv_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct srv_state *st = fi->priv;

	osmo_timer_del(&st->rx_alive_timer);
	osmo_timer_del(&st->echo_req.timer);

	/* as long as 'fi' lives within 'peer' we cannot recursively destroy peer */
	talloc_steal(OTC_SELECT, fi);

	if (g_octoi->ops->peer_disconnected)
		g_octoi->ops->peer_disconnected(st->peer);

	octoi_peer_destroy(st->peer);
}

struct osmo_fsm octoi_server_fsm = {
	.name = "OCTOI_SERVER",
	.states = server_fsm_states,
	.num_states = ARRAY_SIZE(server_fsm_states),
	.allstate_event_mask = S(OCTOI_EV_RX_ECHO_REQ) |
			       S(OCTOI_EV_RX_ECHO_RESP) |
			       S(OCTOI_EV_RX_ERROR_IND),
	.allstate_action = srv_allstate_action,
	.timer_cb = srv_fsm_timer_cb,
	.log_subsys = DLINP,
	.event_names = octoi_fsm_event_names,
	.cleanup = srv_fsm_cleanup,
};


static void srv_rx_alive_timer_cb(void *data)
{
	struct osmo_fsm_inst *fi = data;
	struct srv_state *st = fi->priv;
	struct timespec ts;
	uint64_t rate;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ts.tv_sec - st->peer->last_rx_tdm > 3) {
		LOGPFSML(fi, LOGL_NOTICE, "No TDM data received for >= 3 seconds, declaring peer dead\n");
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_TIMEOUT, NULL);
		return;
	}

	rate = iline_ctr_get_rate_1s(st->peer->iline, LINE_CTR_E1oIP_UNDERRUN);
	if (rate > FRAMES_PER_SEC_THRESHOLD) {
		LOGPFSML(fi, LOGL_ERROR, "More than %u RIFO underruns per second: "
			 "Peer clock is too slow. Disconnecting.\n", FRAMES_PER_SEC_THRESHOLD);
		goto term;
	}

	rate = iline_ctr_get_rate_1s(st->peer->iline, LINE_CTR_E1oIP_E1T_OVERFLOW);
	if (rate > FRAMES_PER_SEC_THRESHOLD) {
		LOGPFSML(fi, LOGL_ERROR, "More than %u RIFO overflows per second: "
			 "Peer clock is too fast. Disconnecting.\n", FRAMES_PER_SEC_THRESHOLD);
		goto term;
	}

	osmo_timer_schedule(&st->rx_alive_timer, 3, 0);
	return;

term:
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
}

static void srv_echo_req_timer_cb(void *data)
{
	struct osmo_fsm_inst *fi = data;
	struct srv_state *st = fi->priv;

	/* trigger sending of an OCTOI ECHO REQ */
	clock_gettime(CLOCK_MONOTONIC, &st->echo_req.last_tx_ts);
	octoi_tx_echo_req(st->peer, ++st->echo_req.last_tx_seq, NULL, 0);
	LOGPFSML(fi, LOGL_DEBUG, "Tx OCTOI ECHO_REQ (seq=%u)\n", st->echo_req.last_tx_seq);
	osmo_timer_schedule(&st->echo_req.timer, 10, 0);
}

/* call-back function for every received OCTOI socket message for given peer */
int octoi_srv_fsm_rx_cb(struct octoi_peer *peer, struct msgb *msg)
{

	/* ensure peer->priv points to a fsm_inst */
	if (!peer->priv) {
		struct osmo_fsm_inst *fi;
		struct srv_state *st;

		fi = osmo_fsm_inst_alloc(&octoi_server_fsm, peer, NULL, LOGL_DEBUG, NULL);
		OSMO_ASSERT(fi);

		st = talloc_zero(fi, struct srv_state);
		OSMO_ASSERT(st);
		st->peer = peer;
		osmo_timer_setup(&st->rx_alive_timer, srv_rx_alive_timer_cb, fi);
		osmo_timer_setup(&st->echo_req.timer, srv_echo_req_timer_cb, fi);
		fi->priv = st;

		peer->priv = fi;
	}
	OSMO_ASSERT(peer->priv);
	if (!peer->iline)
		peer->iline = e1oip_line_alloc(peer);

	return _octoi_fsm_rx_cb(peer, msg);
}
