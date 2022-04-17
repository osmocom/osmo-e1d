/*
 * octoi.c
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
#include <osmocom/octoi/octoi.h>

#include "e1oip.h"
#include "octoi.h"
#include "octoi_sock.h"
#include "frame_fifo.h"

struct octoi_daemon *g_octoi;

static struct octoi_client *client4account(struct octoi_account *acc)
{
	struct octoi_client *clnt;

	llist_for_each_entry(clnt, &g_octoi->clients, list) {
		if (clnt->cfg.account == acc)
			return clnt;
	}

	return NULL;
}

int octoi_vty_go_parent(struct vty *vty)
{
	struct octoi_account *acc;

	switch (vty->node) {
	case OCTOI_ACCOUNT_NODE:
		vty->node = OCTOI_SRV_NODE;
		vty->index = g_octoi->server;
		break;
	case OCTOI_CLNT_ACCOUNT_NODE:
		acc = vty->index;
		vty->node = OCTOI_CLNT_NODE;
		vty->index = client4account(acc);
		break;
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	}
	return 0;
}

void octoi_init(void *ctx, void *priv, const struct octoi_ops *ops)
{
	OSMO_ASSERT(!g_octoi);

	osmo_fsm_register(&octoi_server_fsm);
	osmo_fsm_register(&octoi_client_fsm);

	g_octoi = talloc_zero(ctx, struct octoi_daemon);
	OSMO_ASSERT(g_octoi);

	g_octoi->priv = priv;
	g_octoi->ops = ops;
	INIT_LLIST_HEAD(&g_octoi->clients);

	octoi_server_vty_init();
	octoi_client_vty_init();
}

/* resolve the octoi_peer for a specified octoi_client */
struct octoi_peer *octoi_client_get_peer(struct octoi_client *clnt)
{
	return octoi_sock_client_get_peer(clnt->sock);
}


/*! E1 interface has received some E1 frames, forward in E1->IP direction.
 *  \param[in] peer The peer for which E1 frames were received
 *  \param[in] buf Buffer holding the just-received E1 frames
 *  \param[in] ftr Number of 32-byte frames in buf */
void octoi_peer_e1o_in(struct octoi_peer *peer, const uint8_t *buf, int ftr)
{
	struct e1oip_line *iline = peer->iline;
	int rc;

	if (!peer->tdm_permitted)
		return;

	rc = frame_fifo_in_multi(&iline->e1o.fifo, buf, ftr);
	if (rc < ftr)
		iline_ctr_add(iline, LINE_CTR_E1oIP_OVERFLOW, ftr - rc);

	iline_stat_set(iline, LINE_STAT_E1oIP_E1O_FIFO, frame_fifo_frames(&iline->e1o.fifo));
}

/*! E1 interface needs to transmit some E1 frames, E1<-IP direction.
 *  \param[in] peer The peer from which E1 frames are needed
 *  \param[in] buf Caller-provided output buffer to which frames are written.
 *  \param[in] fts Number of 32-byte frames to be written to buf. */
void octoi_peer_e1t_out(struct octoi_peer *peer, uint8_t *buf, int fts)
{
	struct e1oip_line *iline = peer->iline;
	int rc;

	if (!peer->tdm_permitted)
		return;

	if (!iline->e1t.primed_rx_tdm) {
		if (frame_rifo_frames(&iline->e1t.rifo) > iline->cfg.prefill_frame_count)
			iline->e1t.primed_rx_tdm = true;
		return;
	}

	for (int i = 0; i < fts; i++) {
		uint8_t *cur = buf + BYTES_PER_FRAME*i;
		rc = frame_rifo_out(&iline->e1t.rifo, cur);
		if (rc < 0) {
			iline_ctr_add(iline, LINE_CTR_E1oIP_UNDERRUN, 1);
			/* substitute with last received frame */
			memcpy(cur, iline->e1t.last_frame, BYTES_PER_FRAME);
		}
	}
	iline_stat_set(iline, LINE_STAT_E1oIP_E1T_FIFO, frame_rifo_depth(&iline->e1t.rifo));
}
