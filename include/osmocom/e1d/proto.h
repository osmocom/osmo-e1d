/*
 * proto.h
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
 * (C) 2020 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>

#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>


/*	E1DP_CMD_INTF_QUERY
 *	filter: intf (optional)
 *	in: n/a
 *	out: array of osmo_e1dp_intf_info
 *
 * 	E1DP_CMD_LINE_QUERY
 * 	filter: intf (required), line (optional)
 * 	in: n/a
 * 	out: array of osmo_e1dp_line_info
 *
 * 	E1DP_CMD_TS_QUERY
 * 	filter: intf (required), line (required), ts (optional)
 * 	in: n/a
 * 	out: array of osmo_e1dp_ts_info
 *
 *      E1DP_CMD_LINE_CONFIG
 *      filter: intf (required), line (required)
 *      in: osmo_e1dp_line_config
 *      out: osmo_e1dp_line_info
 *
 * 	E1DP_CMD_TS_OPEN
 * 	filter: intf (required), line (required), ts (required)
 * 	in: osmo_e1dp_ts_config
 * 	out: osmo_e1dp_ts_info with the opened TS (or an invalid one with id == -1 for errors)
 * 	    + message with the file descriptor
 */

enum osmo_e1dp_msg_type {
	E1DP_CMD_INTF_QUERY	= 0x00,
	E1DP_CMD_LINE_QUERY	= 0x01,
	E1DP_CMD_TS_QUERY	= 0x02,
	E1DP_CMD_LINE_CONFIG	= 0x03,
	E1DP_CMD_TS_OPEN	= 0x04,
	E1DP_EVT_TYPE		= 0x40,
	E1DP_RESP_TYPE		= 0x80,
	E1DP_ERR_TYPE		= 0xc0,
	E1DP_TYPE_MSK		= 0xc0,
};

enum osmo_e1dp_line_mode {
	E1DP_LMODE_OFF		= 0x00,
	E1DP_LMODE_CHANNELIZED	= 0x20,
	E1DP_LMODE_SUPERCHANNEL	= 0x21,
};

enum osmo_e1dp_ts_mode {
	E1DP_TSMODE_OFF		= 0x00,
	E1DP_TSMODE_RAW		= 0x10,
	E1DP_TSMODE_HDLCFCS	= 0x11,
};


/* the idea here is to use the first byte as a version number, to prevent incompatible
 * clients from connecting to e1d */
#define E1DP_MAGIC	0x00e1
#define E1DP_MAX_LEN	4096
#define E1DP_TS_SUPERCHAN 0xfe
#define E1DP_INVALID	0xff
#define E1DP_DEFAULT_SOCKET "/tmp/osmo-e1d.ctl"


struct osmo_e1dp_msg_hdr {
	uint16_t magic;
	uint16_t len;

	uint8_t  type; 
	uint8_t  intf;
	uint8_t  line;
	uint8_t  ts;
} __attribute__((packed));

struct osmo_e1dp_intf_info {
	uint8_t id;
	uint8_t n_lines;
} __attribute__((packed));

struct osmo_e1dp_line_config {
	uint8_t mode;
} __attribute__((packed));

struct osmo_e1dp_line_info {
	uint8_t id;
	struct osmo_e1dp_line_config cfg;
	uint8_t status;		/* TBD */
} __attribute__((packed));

struct osmo_e1dp_ts_config {
	uint8_t mode;
} __attribute__((packed));

struct osmo_e1dp_ts_info {
	uint8_t id;
	struct osmo_e1dp_ts_config cfg;
	uint8_t status;		/* TBD */
} __attribute__((packed));


struct msgb *osmo_e1dp_recv(struct osmo_fd *ofd, int *fd);
int osmo_e1dp_send(struct osmo_fd *ofd, struct msgb *msgb, int fd);

extern const struct value_string osmo_e1dp_msg_type_names[];
extern const struct value_string osmo_e1dp_line_mode_names[];
extern const struct value_string osmo_e1dp_ts_mode_names[];
