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
#include <osmocom/core/timer.h>
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
	[LINE_CTR_RX_REMOTE_E] ={ "rx:remote_crc_errors",	"Rx Frames Reporting Remote CRC Error"},
	[LINE_CTR_RX_REMOTE_A] ={ "rx:remote_alarm",		"Rx Frames Reporting Remote Alarm"},
};

static const struct rate_ctr_group_desc line_ctrg_desc = {
	.group_name_prefix = "e1d_line",
	.group_description = "Counters for each line in e1d",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(line_ctr_description),
	.ctr_desc = line_ctr_description,
};

/* watchdog timer, called once per second to check if we still receive data on the line */
static void line_watchdog_cb(void *data)
{
	struct e1_line *line = data;

	if (line->watchdog.rx_bytes < 240000) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Received Only %u bytes/s (expected: 262144): Line dead?\n",
			line->watchdog.rx_bytes);
	}

	line->watchdog.rx_bytes = 0;
	osmo_timer_schedule(&line->watchdog.timer, 1, 0);
}

// ---------------------------------------------------------------------------
// e1d structures
// ---------------------------------------------------------------------------

struct e1_intf *
e1d_find_intf(struct e1_daemon *e1d, uint8_t id)
{
	struct e1_intf *intf;

	llist_for_each_entry(intf, &e1d->interfaces, list)
		if (intf->id == id)
			return intf;

	return NULL;
}

struct e1_intf *
e1d_find_intf_by_usb_serial(struct e1_daemon *e1d, const char *serial_str)
{
	struct e1_intf *intf;

	if (!serial_str)
		return NULL;

	llist_for_each_entry(intf, &e1d->interfaces, list) {
		if (intf->usb.serial_str && !strcmp(intf->usb.serial_str, serial_str))
			return intf;
	}

	return NULL;
}

struct e1_line *
e1_intf_find_line(struct e1_intf *intf, uint8_t id)
{
	struct e1_line *line;

	llist_for_each_entry(line, &intf->lines, list) {
		if (line->id == id)
			return line;
	}

	return NULL;
}

/* intf_id can be specified as '-1' to mean "auto-allocate intf->id" */
struct e1_intf *
e1_intf_new(struct e1_daemon *e1d, int intf_id, void *drv_data)
{
	struct e1_intf *intf;

	if (intf_id != -1) {
		/* ensure non-duplicate interface number */
		intf = e1d_find_intf(e1d, intf_id);
		if (intf) {
			LOGPIF(intf, DE1D, LOGL_ERROR, "Cannot create duplicate interface %d\n", intf_id);
			return NULL;
		}
	}

	intf = talloc_zero(e1d->ctx, struct e1_intf);
	OSMO_ASSERT(intf);

	intf->e1d = e1d;
	intf->drv_data = drv_data;

	INIT_LLIST_HEAD(&intf->list);
	INIT_LLIST_HEAD(&intf->lines);

	if (intf_id == -1) {
		if (!llist_empty(&e1d->interfaces)) {
			struct e1_intf *f = llist_last_entry(&e1d->interfaces, struct e1_intf, list);
			intf->id = f->id + 1;
		} else
			intf->id = 0;
	} else
		intf->id = intf_id;

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
_ts0_tmr_cb(void *_line)
{
	struct e1_line *line = (struct e1_line *) _line;

	if ((line->ts0.cur_errmask & E1L_TS0_RX_CRC4_ERR) !=
	    (line->ts0.prev_errmask & E1L_TS0_RX_CRC4_ERR)) {
		LOGPLI(line, DE1D, LOGL_NOTICE, "Remote CRC4 Error report %s\n",
			line->ts0.cur_errmask & E1L_TS0_RX_CRC4_ERR ? "STARTED" : "CEASED");
	}

	if ((line->ts0.cur_errmask & E1L_TS0_RX_ALARM) !=
	    (line->ts0.prev_errmask & E1L_TS0_RX_ALARM)) {
		LOGPLI(line, DE1D, LOGL_NOTICE, "Remote ALARM condition %s\n",
			line->ts0.cur_errmask & E1L_TS0_RX_ALARM ? "STARTED" : "CEASED");
	}

	line->ts0.prev_errmask = line->ts0.cur_errmask;
	line->ts0.cur_errmask = 0;
	osmo_timer_schedule(&line->ts0.timer, 1, 0);
}

static void
_ts_init(struct e1_ts *ts, struct e1_line *line, int id)
{
	ts->line = line;
	ts->id = id;
	ts->fd = -1;
}

/* line_id can be specified as '-1' to mean "auto-allocate intf->id" */
struct e1_line *
e1_line_new(struct e1_intf *intf, int line_id, void *drv_data)
{
	struct e1_line *line;

	if (line_id != -1) {
		line = e1_intf_find_line(intf, line_id);
		if (line) {
			LOGPLI(line, DE1D, LOGL_ERROR, "Cannot create duplicate line %d\n", line_id);
			return NULL;
		}
	}

	line = talloc_zero(intf->e1d->ctx, struct e1_line);
	OSMO_ASSERT(line);

	line->intf = intf;
	line->drv_data = drv_data;
	line->mode = E1_LINE_MODE_CHANNELIZED;

	for (int i = 0; i < 32; i++)
		_ts_init(&line->ts[i], line, i);
	_ts_init(&line->superchan, line, E1DP_TS_SUPERCHAN);

	INIT_LLIST_HEAD(&line->list);

	if (line_id == -1) {
		if (!llist_empty(&intf->lines)) {
			struct e1_line *l = llist_last_entry(&intf->lines, struct e1_line, list);
			line->id = l->id + 1;
		} else
			line->id = 0;
	} else
		line->id = line_id;

	line->ctrs = rate_ctr_group_alloc(line, &line_ctrg_desc, line->id);
	OSMO_ASSERT(line->ctrs);

	osmo_timer_setup(&line->ts0.timer, _ts0_tmr_cb, line);
	osmo_timer_schedule(&line->ts0.timer, 1, 0);

	llist_add_tail(&line->list, &intf->lines);

	/* start watchdog timer */
	osmo_timer_setup(&line->watchdog.timer, line_watchdog_cb, line);
	osmo_timer_schedule(&line->watchdog.timer, 1, 0);

	LOGPLI(line, DE1D, LOGL_NOTICE, "Created\n");

	return line;
}

void
e1_line_destroy(struct e1_line *line)
{
	LOGPLI(line, DE1D, LOGL_NOTICE, "Destroying\n");

	osmo_timer_del(&line->watchdog.timer);

	/* close all [peer] file descriptors */
	for (int i = 0; i < 32; i++)
		e1_ts_stop(&line->ts[i]);

	/* remove from per-interface list of lines */
	llist_del(&line->list);

	talloc_free(line);
}
