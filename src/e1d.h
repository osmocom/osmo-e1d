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
#pragma once

#include <stdint.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/timer.h>
#include <osmocom/vty/command.h>

#include <osmocom/octoi/octoi.h>
#include <osmocom/e1d/proto.h>

/***********************************************************************
 * core e1d related data structures
 ***********************************************************************/

enum e1d_vty_node {
	E1D_NODE = _LAST_OSMOVTY_NODE + 1,
	INTF_NODE,
	LINE_NODE,
};

#define line_ctr_add(line, idx, add) rate_ctr_add(rate_ctr_group_get_ctr((line)->ctrs, idx), add)

enum e1d_line_ctr {
	LINE_CTR_LOS,
	LINE_CTR_LOA,
	LINE_CTR_CRC_ERR,
	LINE_CTR_RX_OVFL,
	LINE_CTR_TX_UNFL,
	LINE_CTR_RX_REMOTE_E,
	LINE_CTR_RX_REMOTE_A,
};

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

		uint8_t rx_buf[E1DP_MAX_SIZE_HDLC];
		uint8_t tx_buf[E1DP_MAX_SIZE_HDLC];
		int tx_ofs;
		int tx_len;
	} hdlc;

	/* RAW handling */
	struct {
		uint8_t *rx_buf;		/* actual buffer storage */
		unsigned int rx_buf_size;	/* size of 'buf' in bytes */
		unsigned int rx_buf_used;	/* number of bytes used so far */
		bool tx_started;		/* tx started */
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
	/* E1 forwarding over IP */
	E1_LINE_MODE_E1OIP,
};

#define E1L_TS0_RX_CRC4_ERR	0x01
#define E1L_TS0_RX_ALARM	0x02

struct e1_line {
	struct llist_head list;

	struct e1_intf *intf;
	uint8_t id;

	enum e1_line_mode mode;

	void *drv_data;
	struct rate_ctr_group *ctrs;

	/* timeslots for channelized mode */
	struct e1_ts ts[32];
	/* superchannel */
	struct e1_ts superchan;
	struct octoi_peer *octoi_peer;

	struct {
		/*! buffer where we aggregate the E bits each multi-frame */
		uint8_t e_bits;
		/*! did we receive CRC4 / ALARM error reports this second (timer tick) */
		uint8_t cur_errmask;
		/*! did we receive CRC4 / ALARM error reports previous second (timer tick) */
		uint8_t prev_errmask;
		/*! timer to re-set the rx_crc4_err and rx_alarm above */
		struct osmo_timer_list timer;
	} ts0;

	/* watchdog timer to catch situations where no more USB data is received */
	struct {
		struct osmo_timer_list timer;
		uint32_t rx_bytes;
	} watchdog;

	void *e1gen_priv;
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

	struct {
		char *serial_str;
	} usb;

	bool vty_created;
	enum e1_driver drv;
	void *drv_data;

	struct llist_head lines;
};

struct e1_daemon {
	void *ctx;
	struct llist_head interfaces;
};

extern const struct octoi_ops e1d_octoi_ops;

struct e1_line *
e1_intf_find_line(struct e1_intf *intf, uint8_t id);

struct e1_line *
e1_intf_find_line(struct e1_intf *intf, uint8_t id);

struct e1_intf *
e1_intf_new(struct e1_daemon *e1d, int intf_id, void *drv_data);

struct e1_intf *
e1d_find_intf(struct e1_daemon *e1d, uint8_t id);

struct e1_intf *
e1d_find_intf_by_usb_serial(struct e1_daemon *e1d, const char *serial_str);

void
e1_intf_destroy(struct e1_intf *intf);


struct e1_line *
e1_intf_find_line(struct e1_intf *intf, uint8_t id);

struct e1_line *
e1_line_new(struct e1_intf *intf, int line_id, void *drv_data);

void
e1_line_destroy(struct e1_line *line);

void
e1_line_active(struct e1_line *line);

int
e1_line_mux_out(struct e1_line *line, uint8_t *buf, int fts);

int
e1_line_demux_in(struct e1_line *line, const uint8_t *buf, int size, int frame_base);

void
e1_ts_stop(struct e1_ts *ts);

void
e1d_vty_init(struct e1_daemon *e1d);

int
e1d_vpair_create(struct e1_daemon *e1d, unsigned int num_lines);

struct e1_intf *
e1d_vpair_intf_peer(struct e1_intf *intf);

int
e1oip_line_demux_in(struct e1_line *line, const uint8_t *buf, int ftr);

int
e1oip_line_mux_out(struct e1_line *line, uint8_t *buf, int fts);

int
e1d_vty_go_parent(struct vty *vty);
