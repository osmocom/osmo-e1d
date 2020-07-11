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
#include <osmocom/e1d/proto.h>

#include "e1d.h"
#include "log.h"

const struct value_string e1_driver_names[] = {
	{ E1_DRIVER_USB, "usb" },
	{ E1_DRIVER_VPAIR, "vpair" },
	{ 0, NULL }
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


// ---------------------------------------------------------------------------
// data transfer
// ---------------------------------------------------------------------------

static int
_e1_rx_hdlcfs(struct e1_ts *ts, const uint8_t *buf, int len)
{
	int rv, cl, oi;

	oi = 0;

	while (oi < len) {
		rv = osmo_isdnhdlc_decode(&ts->hdlc_rx,
			&buf[oi], len-oi, &cl,
			ts->rx_buf, sizeof(ts->rx_buf)
		);

		if (rv > 0) {
			int bytes_to_write = rv;
			LOGPTS(ts, DXFR, LOGL_DEBUG, "RX Message: %d [ %s]\n",
				rv, osmo_hexdump(ts->rx_buf, rv));
			rv = write(ts->fd, ts->rx_buf, bytes_to_write);
			if (rv < 0)
				return rv;
		} else  if (rv < 0 && ts->id == 4) {
			LOGPTS(ts, DXFR, LOGL_ERROR, "ERR RX: %d %d %d [ %s]\n",
				rv,oi,cl, osmo_hexdump(buf, len));
		}

		oi += cl;
	}

	return 0;
}

static int
_e1_tx_hdlcfs(struct e1_ts *ts, uint8_t *buf, int len)
{
	int rv, oo, cl;

	oo = 0;

	while (oo < len) {
		/* Pending message ? */
		if (!ts->tx_len) {
			rv = recv(ts->fd, ts->tx_buf, sizeof(ts->tx_buf), MSG_TRUNC);
			if (rv > 0) {
				if (rv > sizeof(ts->tx_buf)) {
					LOGPTS(ts, DXFR, LOGL_ERROR, "Truncated message: Client tried to "
						"send %d bytes but our buffer is limited to %lu\n",
						rv, sizeof(ts->tx_buf));
					rv = sizeof(ts->tx_buf);
				}
				LOGPTS(ts, DXFR, LOGL_DEBUG, "TX Message: %d [ %s]\n",
					rv, osmo_hexdump(ts->tx_buf, rv));
				ts->tx_len = rv; 
				ts->tx_ofs = 0;
			} else if (rv < 0 && errno != EAGAIN)
				return rv;
		}

		/* */
		rv = osmo_isdnhdlc_encode(&ts->hdlc_tx,
			&ts->tx_buf[ts->tx_ofs], ts->tx_len - ts->tx_ofs, &cl,
			&buf[oo], len - oo
		);

		if (rv < 0)
			LOGPTS(ts, DXFR, LOGL_ERROR, "ERR TX: %d\n", rv);

		if (ts->tx_ofs < ts->tx_len) {
			LOGPTS(ts, DXFR, LOGL_DEBUG, "TX chunk %d/%d %d [ %s]\n",
				ts->tx_ofs, ts->tx_len, cl, osmo_hexdump(&buf[ts->tx_ofs], rv));
		}

		if (rv > 0)
			oo += rv;

		ts->tx_ofs += cl;
		if (ts->tx_ofs >= ts->tx_len) {
			ts->tx_len = 0;
			ts->tx_ofs = 0;
		}
	}

	return len;
}

/*! generate (multiplex) output data for the specified e1_line
 *  \param[in] line E1 line for which to genrate output data
 *  \param[in] buf caller-allocated output buffer for multiplexed data
 *  \param[in] fts number of E1 frames (32 bytes each) to generate
 *  \return number of bytes written to buf */
int
e1_line_mux_out(struct e1_line *line, uint8_t *buf, int fts)
{
	int tsz;

	/* Prepare */
	tsz = 32 * fts;
	memset(buf, 0xff, tsz);

	/* Scan timeslots */
	for (int tsn=1; tsn<32; tsn++)
	{
		struct e1_ts *ts = &line->ts[tsn];
		uint8_t buf_ts[fts];
		int l;

		if (ts->mode == E1_TS_MODE_OFF)
			continue;

		switch (ts->mode) {
		case E1_TS_MODE_RAW:
			l = read(ts->fd, buf_ts, fts);
			break;
		case E1_TS_MODE_HDLCFCS:
			l = _e1_tx_hdlcfs(ts, buf_ts, fts);
			break;
		default:
			OSMO_ASSERT(0);
			continue;
		}

		if (l < 0 && errno != EAGAIN) {
			LOGPTS(ts, DE1D, LOGL_ERROR, "dead socket during read: %s\n",
				strerror(errno));
			e1_ts_stop(ts);
		}

		if (l <= 0)
			continue;

		for (int i=0; i<l; i++)
			buf[tsn+(i*32)] = buf_ts[i];
	}

	return tsz;
}

/*! de-multiplex E1 line data to the individual timeslots.
 *  \param[in] line E1 line on which we operate.
 *  \param[in] buf buffer containing multiplexed frame-aligned E1 data.
 *  \param[in] size size of 'buf' in octets; assumed to be multiple of E1 frame size (32).
 *  \returns 0 on success; negative on error */
int
e1_line_demux_in(struct e1_line *line, const uint8_t *buf, int size)
{
	int ftr;

	if (size <= 0) {
		LOGPLI(line, DXFR, LOGL_ERROR, "IN ERROR: %d\n", size);
		return -1;
	}

	ftr = size / 32;
	OSMO_ASSERT(size % 32 == 0);

	for (int tsn=1; tsn<32; tsn++)
	{
		struct e1_ts *ts = &line->ts[tsn];
		uint8_t buf_ts[ftr];
		int rv;

		if (ts->mode == E1_TS_MODE_OFF)
			continue;

		for (int i=0; i<ftr; i++)
			buf_ts[i] = buf[tsn+(i*32)];

		switch (ts->mode) {
		case E1_TS_MODE_RAW:
			rv = write(ts->fd, buf_ts, ftr);
			break;
		case E1_TS_MODE_HDLCFCS:
			rv = _e1_rx_hdlcfs(ts, buf_ts, ftr);
			break;
		default:
			OSMO_ASSERT(0);
			continue;
		}
		if (rv < 0 && errno != EAGAIN) {
			LOGPTS(ts, DE1D, LOGL_ERROR, "dead socket during write: %s\n",
				strerror(errno));
			e1_ts_stop(ts);
		}

	}

	return 0;
}
