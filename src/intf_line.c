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
#include <osmocom/core/stat_item.h>
#include <osmocom/core/timer.h>
#include <osmocom/e1d/proto.h>

#include "e1d.h"
#include "log.h"
#include <osmocom/octoi/octoi.h>

const struct value_string e1_driver_names[] = {
	{ E1_DRIVER_USB, "usb" },
	{ E1_DRIVER_VPAIR, "vpair" },
	{ E1_DRIVER_DAHDI_TRUNKDEV, "dahdi-trunkdev" },
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
	[LINE_CTR_FRAMES_MUXED_E1T] = { "tx:frames_muxed",	"E1 Tx Frames multiplexed" },
	[LINE_CTR_FRAMES_DEMUXED_E1O] = { "rx:frames_demuxed",	"E1 Rx Frames demultiplexed" },
	[LINE_CTR_USB_ISO_TRUNC] = { "rx:usb_iso_trunc",	"USB ISO packets truncated" },
};

static const struct rate_ctr_group_desc line_ctrg_desc = {
	.group_name_prefix = "e1d_line",
	.group_description = "Counters for each line in e1d",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_ctr = ARRAY_SIZE(line_ctr_description),
	.ctr_desc = line_ctr_description,
};

static const struct osmo_stat_item_desc line_stat_description[] = {
	[LINE_GPSDO_STATE]	= { "gpsdo:state", "GPSDO State" },
	[LINE_GPSDO_ANTENNA]	= { "gpsdo:antenna", "GSPDO Antenna State" },
	[LINE_GPSDO_TUNE_COARSE]= { "gpsdo:tune:coarse", "GSPDO Coarse Tuning" },
	[LINE_GPSDO_TUNE_FINE]	= { "gpsdo:tune:fine", "GSPDO Fine Tuning" },
	[LINE_GPSDO_FREQ_EST]	= { "gpsdo:freq_est", "GSPDO Frequency Estimate" },
	[LINE_GPSDO_ERR_ACC]    = { "gpsdo:err_acc", "GPSDO Accumulated Error" },
};

static const struct osmo_stat_item_group_desc line_stats_desc = {
	.group_name_prefix = "e1d_line",
	.group_description = "Stat items for E1 line",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(line_stat_description),
	.item_desc = line_stat_description,
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

struct e1_intf *
e1d_find_intf_by_trunkdev_name(struct e1_daemon *e1d, const char *name)
{
	struct e1_intf *intf;

	if (!name)
		return NULL;

	llist_for_each_entry(intf, &e1d->interfaces, list) {
		if (intf->dahdi_trunkdev.name && !strcmp(intf->dahdi_trunkdev.name, name))
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
	line->ts0.cur_errmask &= ~E1L_TS0_RX_CRC4_ERR;
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
	char name[32];

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
	line->ts0.tx_frame = 0xff;
	line->ts0.rx_frame = 0xff;

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

	line->ctrs = rate_ctr_group_alloc(line, &line_ctrg_desc, intf->id << 8 | line->id);
	OSMO_ASSERT(line->ctrs);

	line->stats = osmo_stat_item_group_alloc(line, &line_stats_desc, intf->id << 8 | line->id);
	OSMO_ASSERT(line->stats);

	snprintf(name, sizeof(name), "I%u:L%u", intf->id, line->id);
	rate_ctr_group_set_name(line->ctrs, name);
	osmo_stat_item_group_set_name(line->stats, name);

	llist_add_tail(&line->list, &intf->lines);

	LOGPLI(line, DE1D, LOGL_NOTICE, "Created\n");

	return line;
}

/* find an octoi client (if any) for the given line */
static struct octoi_client *octoi_client_by_line(struct e1_line *line)
{
	struct octoi_client *clnt;

	llist_for_each_entry(clnt, &g_octoi->clients, list) {
		struct octoi_account *acc = clnt->cfg.account;
		switch (acc->mode) {
		case ACCOUNT_MODE_ICE1USB:
			if (!strcmp(line->intf->usb.serial_str, acc->u.ice1usb.usb_serial) &&
			    line->id == acc->u.ice1usb.line_nr)
				return clnt;
			break;
		case ACCOUNT_MODE_DAHDI_TRUNKDEV:
			if (!strcmp(line->intf->dahdi_trunkdev.name, acc->u.dahdi_trunkdev.name) &&
			    line->id == acc->u.dahdi_trunkdev.line_nr)
				return clnt;
			break;
		case ACCOUNT_MODE_NONE:
		case ACCOUNT_MODE_REDIRECT:
			break;
		default:
			OSMO_ASSERT(0);
		}
	}
	return NULL;
}

/* mark given line as 'active' (hardware present + enabled) */
void
e1_line_active(struct e1_line *line)
{
	struct octoi_client *clnt;

	LOGPLI(line, DE1D, LOGL_NOTICE, "Activated\n");

	osmo_timer_setup(&line->ts0.timer, _ts0_tmr_cb, line);
	osmo_timer_schedule(&line->ts0.timer, 1, 0);

	/* start watchdog timer */
	osmo_timer_setup(&line->watchdog.timer, line_watchdog_cb, line);
	osmo_timer_schedule(&line->watchdog.timer, 1, 0);

	switch (line->mode) {
	case E1_LINE_MODE_E1OIP:
		OSMO_ASSERT(!line->octoi_peer);
		/* find a client for this line */
		clnt = octoi_client_by_line(line);
		if (!clnt)
			return;
		/* start the peer for this client */
		line->octoi_peer = octoi_client_get_peer(clnt);
		OSMO_ASSERT(line->octoi_peer);
		octoi_clnt_start_for_peer(line->octoi_peer, clnt->cfg.account);
		break;
	default:
		break;
	}
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
