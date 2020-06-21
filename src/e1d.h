/*
 * e1d.h
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

#include <stdint.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/linuxlist.h>


enum e1_ts_mode {
	E1_TS_MODE_OFF = 0,
	E1_TS_MODE_RAW,
	E1_TS_MODE_HDLCFCS,
};

struct e1_ts {
	struct e1_line *line;
	uint8_t id;

	/* Mode */
	enum e1_ts_mode mode;

	/* HDLC handling */
	struct osmo_isdnhdlc_vars hdlc_tx;
	struct osmo_isdnhdlc_vars hdlc_rx;

	uint8_t rx_buf[264];
	uint8_t tx_buf[264];
	int tx_ofs;
	int tx_len;

	/* Remote end */
	int fd;
};

struct e1_line {
	struct llist_head list;

	struct e1_intf *intf;
	uint8_t id;

	void *drv_data;

	struct e1_ts ts[32];
};

struct e1_intf {
	struct llist_head list;

	struct e1_daemon *e1d;
	uint8_t id;

	void *drv_data;

	struct llist_head lines;
};

struct e1_daemon {
	void *ctx;
	struct llist_head interfaces;
};

struct e1_intf *
e1_intf_new(struct e1_daemon *e1d, void *drv_data);

struct e1_line *
e1_line_new(struct e1_intf *intf, void *drv_data);

int
e1_line_mux_out(struct e1_line *line, uint8_t *buf, int fts);

int
e1_line_demux_in(struct e1_line *line, const uint8_t *buf, int size);
