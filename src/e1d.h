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
extern const struct value_string e1_ts_mode_names[];

struct e1_ts {
	struct e1_line *line;
	uint8_t id;

	/* Mode */
	enum e1_ts_mode mode;

	/* HDLC handling */
	struct {
		struct osmo_isdnhdlc_vars tx;
		struct osmo_isdnhdlc_vars rx;

		uint8_t rx_buf[264];
		uint8_t tx_buf[264];
		int tx_ofs;
		int tx_len;
	} hdlc;

	/* RAW handling */
	struct {
		uint8_t *rx_buf;		/* actual buffer storage */
		unsigned int rx_buf_size;	/* size of 'buf' in bytes */
		unsigned int rx_buf_used;	/* number of bytes used so far */
	} raw;

	/* Remote end */
	int fd;
};

enum e1_line_mode {
	/* 31 individual 64k timeslots, as used on 3GPP Abis, 3GPP A or ISDN */
	E1_LINE_MODE_CHANNELIZED,
	/* 1 channel group spanning all 31 TS, as used e.g. when using Frame Relay
	 * or raw HDLC over channelized E1. */
	E1_LINE_MODE_SUPERCHANNEL,
};

struct e1_line {
	struct llist_head list;

	struct e1_intf *intf;
	uint8_t id;

	enum e1_line_mode mode;

	void *drv_data;

	/* timeslots for channelized mode */
	struct e1_ts ts[32];
	/* superchannel */
	struct e1_ts superchan;
};

enum e1_driver {
	E1_DRIVER_USB,
	E1_DRIVER_VPAIR,
};

extern const struct value_string e1_driver_names[];
extern const struct value_string e1_line_mode_names[];

struct e1_intf {
	struct llist_head list;

	struct e1_daemon *e1d;
	uint8_t id;

	enum e1_driver drv;
	void *drv_data;

	struct llist_head lines;
};

struct e1_daemon {
	void *ctx;
	struct llist_head interfaces;
};

struct e1_intf *
e1_intf_new(struct e1_daemon *e1d, void *drv_data);

struct e1_intf *
e1d_find_intf(struct e1_daemon *e1d, uint8_t id);

void
e1_intf_destroy(struct e1_intf *intf);


struct e1_line *
e1_intf_find_line(struct e1_intf *intf, uint8_t id);

struct e1_line *
e1_line_new(struct e1_intf *intf, void *drv_data);

void
e1_line_destroy(struct e1_line *line);

int
e1_line_mux_out(struct e1_line *line, uint8_t *buf, int fts);

int
e1_line_demux_in(struct e1_line *line, const uint8_t *buf, int size);

void
e1_ts_stop(struct e1_ts *ts);

void
e1d_vty_init(struct e1_daemon *e1d);

int
e1d_vpair_create(struct e1_daemon *e1d, unsigned int num_lines);
