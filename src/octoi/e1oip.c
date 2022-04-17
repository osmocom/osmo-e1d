/*
 * e1oip.c - Actual TDM/E1oIP handling within OCTOI
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

#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <talloc.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/octoi/e1oip_proto.h>

#include "octoi_sock.h"
#include "frame_fifo.h"
#include "e1oip.h"

static const struct rate_ctr_desc iline_ctr_description[] = {
	[LINE_CTR_E1oIP_UNDERRUN] = { "e1oip:underrun", "Frames missing/substituted in IP->E1 direction"},
	[LINE_CTR_E1oIP_OVERFLOW] = { "e1oip:overflow", "Frames overflowed in IP->E1 direction"},
	[LINE_CTR_E1oIP_RX_OUT_OF_ORDER] = { "e1oip:rx:pkt_out_of_order", "Packets out-of-order in IP->E1 direction"},
	[LINE_CTR_E1oIP_RX_OUT_OF_WIN] = { "e1oip:rx:pkt_out_of_win", "Packets out-of-rx-window in IP->E1 direction"},
};

static const struct rate_ctr_group_desc iline_ctrg_desc = {
	.group_name_prefix = "e1oip_line",
	.group_description = "Counters for E1oIP line",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(iline_ctr_description),
	.ctr_desc = iline_ctr_description,
};

static const struct osmo_stat_item_desc iline_stat_description[] = {
	[LINE_STAT_E1oIP_RTT] = { "e1oip:rtt", "Round Trip Time (in ms)" },
	[LINE_STAT_E1oIP_E1O_FIFO] = { "e1oip:e1o_fifo_level", "E1 originated FIFO level" },
	[LINE_STAT_E1oIP_E1T_FIFO] = { "e1oip:e1t_fifo_level", "E1 terminated FIFO level" },
};

static const struct osmo_stat_item_group_desc iline_stats_desc = {
	.group_name_prefix = "e1oip_line",
	.group_description = "Stat items for E1oIP line",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(iline_stat_description),
	.item_desc = iline_stat_description,
};


/* E1 -> IP FIFO threshold reached: send one packet */
static void fifo_threshold_cb(struct frame_fifo *fifo, unsigned int frames, void *priv)
{
	struct e1oip_line *iline = priv;
	struct msgb *msg;
	struct e1oip_tdm_hdr *eith;
	unsigned int n_frames = fifo->threshold;
	uint8_t buf[n_frames][BYTES_PER_FRAME];
	const uint8_t *ref_frame;
	uint32_t ts_mask = 0;
	unsigned int num_ts = 0;
	unsigned int i;
	uint8_t *cur;
	int rc;

	msg = msgb_alloc_c(iline, 2048, "E1oIP UDP Tx");
	OSMO_ASSERT(msg);
	eith = (struct e1oip_tdm_hdr *) msgb_put(msg, sizeof(*eith));

	eith->frame_nr = htons(iline->e1o.next_seq);

	//printf("%s: n_frames=%u\n", __func__, n_frames);

	/* first pull all the frames to a local buffer */
	for (i = 0; i < n_frames; i++) {
		rc = frame_fifo_out(&iline->e1o.fifo, buf[i]);
		if (rc < 0) {
			/* this situation cannot really happen: The FIFO called us that
			 * a certain threshold is reached, but now it cannot provide
			 * frames? */
			LOGPEER(iline->peer, LOGL_ERROR,
				"frame_fifo_out failure for frame %u/%u\n", iline->e1o.next_seq + i, i);
		}
	}
	iline_stat_set(iline, LINE_STAT_E1oIP_E1O_FIFO, frame_fifo_frames(&iline->e1o.fifo));

	/* then compute the ts_mask */
	for (i = 0, ref_frame = iline->e1o.last_frame; i < n_frames; i++, ref_frame = buf[i-1]) {
		/* FIXME: what to do about TS0? */
		for (unsigned int j = 1; j < BYTES_PER_FRAME; j++) {
			if (buf[i][j] != ref_frame[j])
				ts_mask |= (1U << j);
		}
	}
	eith->ts_mask = htonl(ts_mask);

	for (i = 0; i < BYTES_PER_FRAME; i++) {
		if (ts_mask & (1U << i))
			num_ts++;
	}

	/* finally, encode the payload */
	if (num_ts == 0) {
		/* explicitly encode the number of frames, as the receiver can not determine it
		 * if we don't include any data */
		msgb_put_u8(msg, n_frames);
	} else {
		cur = msgb_put(msg, num_ts * n_frames);
		for (i = 0; i < n_frames; i++) {
			for (unsigned int j = 0; j < BYTES_PER_FRAME; j++) {
				if (ts_mask & (1U << j))
					*cur++ = buf[i][j];
			}
		}
	}

	/* send the packet to the peer */
	octoi_tx(iline->peer, E1OIP_MSGT_TDM_DATA, 0, msgb_data(msg), msgb_length(msg));
	msgb_free(msg);

	/* update the local state */
	iline->e1o.next_seq += n_frames;
	if (n_frames)
		memcpy(iline->e1o.last_frame, buf[n_frames-1], BYTES_PER_FRAME);
}

/* build a table indexed by offset inside the EoIP TDM frame resulting in TS number */
static unsigned int ts_mask2idx(uint8_t *out, uint32_t ts_mask)
{
	unsigned int i;
	uint8_t *cur = out;

	memset(out, 0xff, BYTES_PER_FRAME);

	for (i = 0; i < BYTES_PER_FRAME; i++) {
		if (ts_mask & (1U << i))
			*cur++ = i;
	}

	return (cur - out);
}

/* An E1OIP_MSGT_TDM_DATA message was received from a remote IP peer */
int e1oip_rcvmsg_tdm_data(struct e1oip_line *iline, struct msgb *msg)
{
	const int WIN = 8000;
	struct octoi_peer *peer = iline->peer;
	const struct e1oip_tdm_hdr *e1th;
	uint16_t frame_nr;
	uint32_t fn32;
	bool update_next;
	uint32_t ts_mask;
	uint8_t idx2ts[BYTES_PER_FRAME];
	unsigned int n_frames;
	uint8_t frame_buf[BYTES_PER_FRAME];
	unsigned int num_ts;
	uint16_t exp_next_seq = iline->e1t.next_fn32 & 0xffff;
	struct timespec ts;

	/* update the timestamp at which we last received data from this peer */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	peer->last_rx_tdm = ts.tv_sec;

	if (!peer->tdm_permitted)
		return -EPERM;

	if (msgb_l2len(msg) < sizeof(*e1th))
		return -EINVAL;

	/* read header */
	e1th = (const struct e1oip_tdm_hdr *) msgb_l2(msg);
	msg->l3h = msgb_l2(msg) + sizeof(*e1th);
	frame_nr = ntohs(e1th->frame_nr);
	ts_mask = ntohl(e1th->ts_mask);

	if (frame_nr != exp_next_seq) {
		uint16_t frame_nr_ofs;

		LOGPEER(peer, LOGL_NOTICE, "RxIP: frame_nr=%u, but expected %u\n",
			frame_nr, exp_next_seq);

		frame_nr_ofs = frame_nr - (exp_next_seq - WIN);
		if (frame_nr_ofs > (2 * WIN)) {
			/* Outside window, throw packet away */
			LOGPEER(peer, LOGL_NOTICE, "RxIP: frame_nr=%u at exp_next_fn32=%u; "
				"received frame outside +/- 1s window of expected frame\n",
				frame_nr, iline->e1t.next_fn32);
			iline_ctr_add(iline, LINE_CTR_E1oIP_RX_OUT_OF_WIN, 1);
			return -EINVAL;
		}

		iline_ctr_add(iline, LINE_CTR_E1oIP_RX_OUT_OF_ORDER, 1);

		fn32 = iline->e1t.next_fn32 + frame_nr_ofs - WIN;
		update_next = frame_nr_ofs >= WIN;
	} else {
		fn32 = iline->e1t.next_fn32;
		update_next = true;
	}

	/* compute E1oIP idx to timeslot table */
	num_ts = ts_mask2idx(idx2ts, ts_mask);
	if (num_ts > 0) {
		n_frames = msgb_l3len(msg) / num_ts;
		if (msgb_l3len(msg) % num_ts) {
			LOGPEER(peer, LOGL_NOTICE,
				"RxIP: %u extraneous bytes (len=%u, num_ts=%u, n_frames=%u)\n",
				msgb_length(msg) % num_ts, msgb_length(msg), num_ts, n_frames);
		}
		LOGPEER(peer, LOGL_INFO, "RxIP: frame=%05u ts_mask=0x%08x num_ts=%02u, n_frames=%u\n",
			frame_nr, ts_mask, num_ts, n_frames);
	} else {
		if (msgb_l3len(msg) < 1) {
			LOGPEER(peer, LOGL_ERROR, "RxIP: num_ts==0 but no n_frames octet!\n");
			n_frames = BYTES_PER_FRAME; /* hackish assumption */
		} else
			n_frames = msg->l3h[0];
	}

	memcpy(frame_buf, iline->e1t.last_frame, BYTES_PER_FRAME);
	for (unsigned int i = 0; i < n_frames; i++) {
		for (unsigned int j = 0; j < num_ts; j++) {
			uint8_t ts_nr = idx2ts[j];
			frame_buf[ts_nr] = e1th->data[i*num_ts + j];
		}
		/* FIXME: what to do about TS0? */
		frame_rifo_in(&iline->e1t.rifo, frame_buf, fn32+i);
	}
	/* update local state */
	memcpy(iline->e1t.last_frame, frame_buf, BYTES_PER_FRAME);
	if (update_next)
		iline->e1t.next_fn32 = fn32 + n_frames;

	iline_stat_set(iline, LINE_STAT_E1oIP_E1T_FIFO, frame_rifo_depth(&iline->e1t.rifo));

	return 0;
}

static int g_ctr_idx = 0;

void e1oip_line_set_name(struct e1oip_line *iline, const char *name)
{
	rate_ctr_group_set_name(iline->ctrs, name);
	osmo_stat_item_group_set_name(iline->stats, name);
}

struct e1oip_line *e1oip_line_alloc(struct octoi_peer *peer)
{
	struct e1oip_line *iline;
	int ctr_idx = g_ctr_idx++;

	if (peer->iline)
		return NULL;

	iline = talloc_zero(peer, struct e1oip_line);
	if (!iline)
		return NULL;

	iline->ctrs = rate_ctr_group_alloc(iline, &iline_ctrg_desc, ctr_idx);
	iline->stats = osmo_stat_item_group_alloc(iline, &iline_stats_desc, ctr_idx);
	e1oip_line_set_name(iline, peer->name);

	iline->cfg.batching_factor = 32;
	iline->cfg.prefill_frame_count = 200; /* 25ms */

	e1oip_line_reset(iline);

	iline->peer = peer;
	peer->iline = iline;

	return iline;
}

void e1oip_line_reset(struct e1oip_line *iline)
{
	frame_fifo_init(&iline->e1o.fifo, iline->cfg.batching_factor, fifo_threshold_cb, iline);
	memset(&iline->e1o.last_frame, 0xff, sizeof(iline->e1o.last_frame));
	iline->e1o.next_seq = 0;

	frame_rifo_init(&iline->e1t.rifo);
	memset(&iline->e1t.last_frame, 0xff, sizeof(iline->e1t.last_frame));
	iline->e1t.next_fn32 = 0;
	iline->e1t.primed_rx_tdm = false;
}

void e1oip_line_destroy(struct e1oip_line *iline)
{
	if (!iline)
		return;

	rate_ctr_group_free(iline->ctrs);
	osmo_stat_item_group_free(iline->stats);
	if (iline->peer)
		iline->peer->iline = NULL;
	iline->peer = NULL;
	talloc_free(iline);
}
