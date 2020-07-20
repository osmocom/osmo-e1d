/*
 * ctl.c
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <osmocom/e1d/proto.h>
#include <osmocom/e1d/proto_srv.h>

#include "e1d.h"
#include "log.h"


struct e1_intf *
e1d_find_intf(struct e1_daemon *e1d, uint8_t id)
{
	struct e1_intf *intf;

	llist_for_each_entry(intf, &e1d->interfaces, list)
		if (intf->id == id)
			return intf;

	return NULL;
}

struct e1_line *
e1_intf_find_line(struct e1_intf *intf, uint8_t id)
{
	struct e1_line *line;

	llist_for_each_entry(line, &intf->lines, list)
		if (line->id == id)
			return line;

	return NULL;
}

static struct e1_ts *
_e1d_get_ts(struct e1_line *line, uint8_t ts)
{
	if (ts < 32)
		return &line->ts[ts];
	else if (ts == E1DP_TS_SUPERCHAN)
		return &line->superchan;
	else
		return NULL;
}

static void
_e1d_fill_intf_info(struct osmo_e1dp_intf_info *ii, struct e1_intf *intf)
{
	ii->id = intf->id;
	ii->n_lines = llist_count(&intf->lines);
}

static void
_e1d_fill_line_info(struct osmo_e1dp_line_info *li, struct e1_line *line)
{
	li->id = line->id;
	switch (line->mode) {
	case E1_LINE_MODE_CHANNELIZED:
		li->cfg.mode = E1DP_LMODE_CHANNELIZED;
		break;
	case E1_LINE_MODE_SUPERCHANNEL:
		li->cfg.mode = E1DP_LMODE_SUPERCHANNEL;
		break;
	default:
		OSMO_ASSERT(0);
	}
	li->status = 0x00;
}

static void
_e1d_fill_ts_info(struct osmo_e1dp_ts_info *ti, struct e1_ts *ts)
{
	ti->id = ts->id;
	ti->cfg.mode = 0;
	ti->status = 0;
}


void
e1_ts_stop(struct e1_ts *ts)
{
	LOGPTS(ts, DE1D, LOGL_INFO, "Stopping\n");

	ts->mode = E1_TS_MODE_OFF;

	if (ts->fd >= 0) {
		close(ts->fd);
		ts->fd = -1;
	}

	talloc_free(ts->raw.rx_buf);
	ts->raw.rx_buf = NULL;
	ts->raw.rx_buf_size = 0;
	ts->raw.rx_buf_used = 0;
}

static void
_e1d_ts_raw_buf_realloc(struct e1_ts *ts, unsigned int size)
{
	ts->raw.rx_buf = talloc_realloc_size(ts->line, ts->raw.rx_buf, size);
	OSMO_ASSERT(ts->raw.rx_buf);
	ts->raw.rx_buf_size = size;
	ts->raw.rx_buf_used = 0;
}

static int
_e1d_ts_start(struct e1_ts *ts, enum e1_ts_mode mode, uint16_t bufsize)
{
	int ret, sd[2];
	int sock_type;

	LOGPTS(ts, DE1D, LOGL_INFO, "Starting in mode %s\n", get_value_string(e1_ts_mode_names, mode));

	switch (mode) {
	case E1_TS_MODE_HDLCFCS:
		sock_type = SOCK_SEQPACKET;
		break;
	case E1_TS_MODE_RAW:
		sock_type = SOCK_STREAM;
		_e1d_ts_raw_buf_realloc(ts, bufsize);
		break;
	default:
		return -EINVAL;
	}

	ret = socketpair(AF_UNIX, sock_type, 0, sd);
	if (ret < 0)
		return ret;

	ts->fd = sd[0];
	ts->mode = mode;

	if (mode == E1_TS_MODE_HDLCFCS) {
		osmo_isdnhdlc_out_init(&ts->hdlc.tx, OSMO_HDLC_F_BITREVERSE);
		osmo_isdnhdlc_rcv_init(&ts->hdlc.rx, OSMO_HDLC_F_BITREVERSE);
	}

	int flags = fcntl(ts->fd, F_GETFL);
	fcntl(ts->fd, F_SETFL, flags | O_NONBLOCK);

	return sd[1];
}


static int
_e1d_ctl_intf_query(void *data, struct msgb *msgb, struct msgb *rmsgb, int *rfd)
{
	struct e1_daemon *e1d = (struct e1_daemon *)data;
	struct osmo_e1dp_msg_hdr *hdr = msgb_l1(msgb);
	struct osmo_e1dp_intf_info *ii;
	struct e1_intf *intf = NULL;
	int n;

	/* Process query and find interface */
	if (hdr->intf != E1DP_INVALID) {
		intf = e1d_find_intf(e1d, hdr->intf);
		n = intf ? 1 : 0;
	} else {
		n = llist_count(&e1d->interfaces);
	}

	if (!n)
		return 0;

	/* Allocate reponse */
	rmsgb->l2h = msgb_put(rmsgb, n * sizeof(struct osmo_e1dp_intf_info));
	ii = msgb_l2(rmsgb);

	memset(ii, 0x00, n * sizeof(struct osmo_e1dp_intf_info));

	/* Fill response */
	if (intf) {
		_e1d_fill_intf_info(ii, intf);
	} else {
		llist_for_each_entry(intf, &e1d->interfaces, list)
			_e1d_fill_intf_info(ii++, intf);
	}

	return 0;
}

static int
_e1d_ctl_line_query(void *data, struct msgb *msgb, struct msgb *rmsgb, int *rfd)
{
	struct e1_daemon *e1d = (struct e1_daemon *)data;
	struct osmo_e1dp_msg_hdr *hdr = msgb_l1(msgb);
	struct osmo_e1dp_line_info *li;
	struct e1_intf *intf = NULL;
	struct e1_line *line = NULL;
	int n;
	
	/* Process query and find line */
	intf = e1d_find_intf(e1d, hdr->intf);
	if (!intf)
		return 0;

	if (hdr->line != E1DP_INVALID) {
		line = e1_intf_find_line(intf, hdr->line);
		n = line ? 1 : 0;
	} else{
		n = llist_count(&intf->lines);
	}

	if (!n)
		return 0;

	/* Allocate reponse */
	rmsgb->l2h = msgb_put(rmsgb, n * sizeof(struct osmo_e1dp_line_info));
	li = msgb_l2(rmsgb);

	memset(li, 0x00, n * sizeof(struct osmo_e1dp_line_info));

	/* Fill response */
	if (line) {
		_e1d_fill_line_info(li, line);
	} else {
		llist_for_each_entry(line, &intf->lines, list)
			_e1d_fill_line_info(li++, line);
	}

	return 0;
}

static int
_e1d_ctl_ts_query(void *data, struct msgb *msgb, struct msgb *rmsgb, int *rfd)
{
	struct e1_daemon *e1d = (struct e1_daemon *)data;
	struct osmo_e1dp_msg_hdr *hdr = msgb_l1(msgb);
	struct osmo_e1dp_ts_info *ti;
	struct e1_intf *intf = NULL;
	struct e1_line *line = NULL;
	int n;

	/* Process query and find timeslot */
	intf = e1d_find_intf(e1d, hdr->intf);
	if (!intf)
		return 0;

	line = e1_intf_find_line(intf, hdr->line);
	if (!line)
		return 0;

	n = (hdr->ts == E1DP_INVALID) ? 32 : (
		((hdr->ts >= 0) && (hdr->ts < 31)) ? 1 : 0
	);

	if (!n)
		return 0;

	/* Allocate reponse */
	rmsgb->l2h = msgb_put(rmsgb, n * sizeof(struct osmo_e1dp_ts_info));
	ti = msgb_l2(rmsgb);

	memset(ti, 0x00, n * sizeof(struct osmo_e1dp_line_info));

	/* Fill response */
	if (n == 1) {
		_e1d_fill_ts_info(ti, &line->ts[hdr->ts]);
	} else {
		for (int i=0; i<32; i++)
			_e1d_fill_ts_info(ti++, &line->ts[i]);
	}

	return 0;
}

static int
_e1d_ctl_line_config(void *data, struct msgb *msgb, struct msgb *rmsgb, int *rfd)
{
	struct e1_daemon *e1d = (struct e1_daemon *)data;
	struct osmo_e1dp_msg_hdr *hdr = msgb_l1(msgb);
	struct osmo_e1dp_line_config *cfg = msgb_l2(msgb);
	struct osmo_e1dp_line_info *info;
	struct e1_intf *intf = NULL;
	struct e1_line *line = NULL;

	/* Process query and find timeslot */
	intf = e1d_find_intf(e1d, hdr->intf);
	if (!intf)
		return 0;

	line = e1_intf_find_line(intf, hdr->line);
	if (!line)
		return 0;

	LOGPLI(line, DE1D, LOGL_NOTICE, "Setting line mode from %s to %s\n",
		get_value_string(e1_line_mode_names, line->mode),
		get_value_string(osmo_e1dp_line_mode_names, cfg->mode));
	/* Select mode */
	switch (cfg->mode) {
	case E1DP_LMODE_CHANNELIZED:
		line->mode = E1_LINE_MODE_CHANNELIZED;
		break;
	case E1DP_LMODE_SUPERCHANNEL:
		line->mode = E1_LINE_MODE_SUPERCHANNEL;
		break;
	default:
		return 0;
	}

	/* Allocate response */
	rmsgb->l2h = msgb_put(rmsgb, sizeof(struct osmo_e1dp_line_info));
	info = msgb_l2(rmsgb);

	memset(info, 0x00, sizeof(struct osmo_e1dp_line_info));

	/* Fill reponse */
	_e1d_fill_line_info(info, line);

	return 0;
}


static int
_e1d_ctl_ts_open(void *data, struct msgb *msgb, struct msgb *rmsgb, int *rfd)
{
	struct e1_daemon *e1d = (struct e1_daemon *)data;
	struct osmo_e1dp_msg_hdr *hdr = msgb_l1(msgb);
	struct osmo_e1dp_ts_config *cfg = msgb_l2(msgb);
	struct osmo_e1dp_ts_info *ti;
	struct e1_intf *intf = NULL;
	struct e1_line *line = NULL;
	struct e1_ts *ts = NULL;
	enum e1_ts_mode mode;
	int ret;

	/* Process query and find timeslot */
	intf = e1d_find_intf(e1d, hdr->intf);
	if (!intf)
		return 0;

	line = e1_intf_find_line(intf, hdr->line);
	if (!line)
		return 0;

	ts = _e1d_get_ts(line, hdr->ts);
	if (!ts)
		return 0;

	/* Select mode */
	switch (cfg->mode) {
	case E1DP_TSMODE_RAW:
		mode = E1_TS_MODE_RAW;
		break;
	case E1DP_TSMODE_HDLCFCS:
		mode = E1_TS_MODE_HDLCFCS;
		break;
	default:
		return 0;
	}

	if (cfg->read_bufsize == 0)
		return 0;

	/* If already open, close previous */
	e1_ts_stop(ts);

	/* Init */
	ret = _e1d_ts_start(ts, mode, cfg->read_bufsize);
	if (ret < 0)
		return ret;

	*rfd = ret;

	/* Allocate response */
	rmsgb->l2h = msgb_put(rmsgb, sizeof(struct osmo_e1dp_ts_info));
	ti = msgb_l2(rmsgb);

	memset(ti, 0x00, sizeof(struct osmo_e1dp_line_info));

	/* Fill reponse */
	ti->id = hdr->ts;
	ti->cfg.mode = cfg->mode;
	ti->status = 0xa5;

	return 0;
}


struct osmo_e1dp_server_handler e1d_ctl_handlers[] = {
	{
		.type = E1DP_CMD_INTF_QUERY,
		.flags = E1DP_SF_INTF_OPT,
		.payload_len = 0,
		.fn = _e1d_ctl_intf_query,
	},
	{
		.type = E1DP_CMD_LINE_QUERY,
		.flags = E1DP_SF_INTF_REQ | E1DP_SF_LINE_OPT,
		.payload_len = 0,
		.fn = _e1d_ctl_line_query,
	},
	{
		.type = E1DP_CMD_TS_QUERY,
		.flags = E1DP_SF_INTF_REQ | E1DP_SF_LINE_REQ | E1DP_SF_TS_OPT,
		.payload_len = 0,
		.fn = _e1d_ctl_ts_query,
	},
	{
		.type = E1DP_CMD_LINE_CONFIG,
		.flags = E1DP_SF_INTF_REQ | E1DP_SF_LINE_REQ,
		.payload_len = sizeof(struct osmo_e1dp_line_config),
		.fn = _e1d_ctl_line_config,
	},
	{
		.type = E1DP_CMD_TS_OPEN,
		.flags = E1DP_SF_INTF_REQ | E1DP_SF_LINE_REQ | E1DP_SF_TS_REQ,
		.payload_len = sizeof(struct osmo_e1dp_ts_config),
		.fn = _e1d_ctl_ts_open,
	},
	{ /* guard */ },
};
