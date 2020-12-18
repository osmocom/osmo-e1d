/*
 * intf_line.c
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
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

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <talloc.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/e1d/proto.h>

#include "e1d.h"
#include "log.h"

const struct value_string e1_driver_names[] = {
	{ E1_DRIVER_USB, "usb" },
	{ E1_DRIVER_VPAIR, "vpair" },
	{ 0, NULL }
};

static const struct rate_ctr_desc line_ctr_description[] = {
	[LINE_CTR_LOS] =	{ "rx:signal_lost",		"Rx Signal Lost" },
	[LINE_CTR_LOA] =	{ "rx:alignment_lost",		"Rx Alignment Lost" },
	[LINE_CTR_CRC_ERR] =	{ "rx:crc_errors",		"E1 Rx CRC Errors" },
	[LINE_CTR_RX_OVFL] =	{ "rx:overflow",		"E1 Rx Overflow" },
	[LINE_CTR_TX_UNFL] =	{ "tx:underflow",		"E1 Tx Underflow" },
};

static const struct rate_ctr_group_desc line_ctrg_desc = {
	.group_name_prefix = "e1d_line",
	.group_description = "Counters for each line in e1d",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(line_ctr_description),
	.ctr_desc = line_ctr_description,
};

// ---------------------------------------------------------------------------
// e1d structures
// ---------------------------------------------------------------------------

struct e1_intf *
e1_intf_new(struct e1_daemon *e1d, void *drv_data)
{
	struct e1_intf *intf;

	intf = talloc_zero(e1d->ctx, struct e1_intf);
	OSMO_ASSERT(intf);

	intf->e1d = e1d;
	intf->drv_data = drv_data;

	INIT_LLIST_HEAD(&intf->list);
	INIT_LLIST_HEAD(&intf->lines);

	if (!llist_empty(&e1d->interfaces)) {
		struct e1_intf *f = llist_last_entry(&e1d->interfaces, struct e1_intf, list);
		intf->id = f->id + 1;
	}

	llist_add_tail(&intf->list, &e1d->interfaces);

	LOGPIF(intf, DE1D, LOGL_NOTICE, "Created\n");

	return intf;
}

void
e1_intf_destroy(struct e1_intf *intf)
{
	struct e1_line *line, *line2;

	LOGPIF(intf, DE1D, LOGL_NOTICE, "Destroying\n");

	/* destroy all lines */
	llist_for_each_entry_safe(line, line2, &intf->lines, list)
		e1_line_destroy(line);

	/* remove from global list of interfaces */
	llist_del(&intf->list);

	talloc_free(intf);
}

static void
_ts_init(struct e1_ts *ts, struct e1_line *line, int id)
{
	ts->line = line;
	ts->id = id;
	ts->fd = -1;
}

struct e1_line *
e1_line_new(struct e1_intf *intf, void *drv_data)
{
	struct e1_line *line;

	line = talloc_zero(intf->e1d->ctx, struct e1_line);
	OSMO_ASSERT(line);

	line->intf = intf;
	line->drv_data = drv_data;
	line->mode = E1_LINE_MODE_CHANNELIZED;

	for (int i=0; i<32; i++)
		_ts_init(&line->ts[i], line, i);
	_ts_init(&line->superchan, line, E1DP_TS_SUPERCHAN);

	INIT_LLIST_HEAD(&line->list);

	if (!llist_empty(&intf->lines)) {
		struct e1_line *l = llist_last_entry(&intf->lines, struct e1_line, list);
		line->id = l->id + 1;
	}

	line->ctrs = rate_ctr_group_alloc(line, &line_ctrg_desc, line->id);
	OSMO_ASSERT(line->ctrs);

	llist_add_tail(&line->list, &intf->lines);

	LOGPLI(line, DE1D, LOGL_NOTICE, "Created\n");

	return line;
}

void
e1_line_destroy(struct e1_line *line)
{
	LOGPLI(line, DE1D, LOGL_NOTICE, "Destroying\n");

	/* close all [peer] file descriptors */
	for (int i=0; i<32; i++)
		e1_ts_stop(&line->ts[i]);

	/* remove from per-interface list of lines */
	llist_del(&line->list);

	talloc_free(line);
}



