/*! \file proto.h
 *  Specification of the IPC protocol used on the CTL UNIX domain socket between
 *  osmo-e1d and its client programs.
 */

/* (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
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


/*! e1d CTL protocol message type definition. Split in 'type' and 'command' portion. */
enum osmo_e1dp_msg_type {
	/*! Query information about E1 interface(s).
	 * filter: intf (optional); in: n/a out: array of osmo_e1dp_intf_info */
	E1DP_CMD_INTF_QUERY	= 0x00,

	/*! Query information about E1 line(s).
	 * filter: intf (required), line (optional); in: n/a; out: array of osmo_e1dp_line_info */
	E1DP_CMD_LINE_QUERY	= 0x01,

	/*! Query information about E1 timeslot(s).
	 * filter: intf (required), line (required), ts (optional); in: n/a; out: array of osmo_e1dp_ts_info */
	E1DP_CMD_TS_QUERY	= 0x02,

	/*! Configure a given E1 line.
	 * filter: intf (required), line (required); in: osmo_e1dp_line_config; out: osmo_e1dp_line_info */
	E1DP_CMD_LINE_CONFIG	= 0x03,

	/*! Open a given E1 timeslot.
	 * filter: intf (required), line (required), ts (required); in: osmo_e1dp_ts_config;
	 * out: osmo_e1dp_ts_info with the opened TS (or an invalid one with id == -1 for errors)
	 *      + message with the file descriptor */
	E1DP_CMD_TS_OPEN	= 0x04,

	/*! Send Sa bits to line.
	 * filter: intf (required), line (required), ts n/a; in: uint8_t; */
	E1DP_CMD_SABITS		= 0x05,

	/*! Received signal loss from interface. */
	E1DP_EVT_LOS_ON		= 0x40,

	/*! Ceased signal loss from interface. */
	E1DP_EVT_LOS_OFF	= 0x41,

	/*! Received alarm indication signal from interface. */
	E1DP_EVT_AIS_ON		= 0x42,

	/*! Ceased alarm indication signal from interface. */
	E1DP_EVT_AIS_OFF	= 0x43,

	/*! Received remote alarm indication from interface. */
	E1DP_EVT_RAI_ON		= 0x44,

	/*! Ceased remote alarm indication from interface. */
	E1DP_EVT_RAI_OFF	= 0x45,

	/*! Received frame loss from interface. */
	E1DP_EVT_LOF_ON		= 0x46,

	/*! Ceased frame loss from interface. */
	E1DP_EVT_LOF_OFF	= 0x47,

	/*! Received Sa bits from interface.
	 * out: uint8_t; */
	E1DP_EVT_SABITS		= 0x7f,

	/*! Message is an event */
	E1DP_EVT_TYPE		= 0x40,
	/*! Message is a response  */
	E1DP_RESP_TYPE		= 0x80,
	/*! Message is an error */
	E1DP_ERR_TYPE		= 0xc0,
	/*! Mask to separate type from command */
	E1DP_TYPE_MSK		= 0xc0,
};

/*! e1d CTL protocol line mode. */
enum osmo_e1dp_line_mode {
	/*! Line is switched off */
	E1DP_LMODE_OFF		= 0x00,
	/*! Line is used in channelized mode with (64kBps) timeslots */
	E1DP_LMODE_CHANNELIZED	= 0x20,
	/*! Line is used as superchannel (31TS combined together) */
	E1DP_LMODE_SUPERCHANNEL	= 0x21,
	/*! Line is used in E1oIP mode (not available to CTL clients) */
	E1DP_LMODE_E1OIP	= 0x22,
};

/*! e1d CTL protocol timeslot mode. */
enum osmo_e1dp_ts_mode {
	/*! Timeslot is switched off. */
	E1DP_TSMODE_OFF		= 0x00,
	/*! Timeslot is in RAW mode, containing transparent 64kBps bitstream. */
	E1DP_TSMODE_RAW		= 0x10,
	/*! Timeslot is in HLDC-FCS mode; e1d will run software HDLC processor. */
	E1DP_TSMODE_HDLCFCS	= 0x11,
};

/*! Flag that can be used as osmo_e1dp_ts_config.flags to force opening a TS. */
#define E1DP_TS_OPEN_F_FORCE	0x80

/*! Magic value. the idea here is to use the first byte as a version number, to prevent incompatible
 * clients from connecting to e1d */
#define E1DP_MAGIC	0x01e1
/*! Maximum length of a protocol message */
#define E1DP_MAX_LEN	4096
/*! magic value used to indicate superchannel instead of timeslot. */
#define E1DP_TS_SUPERCHAN 0xfe
/*! magic value to indicate given field (interface/line/timeslot) is
 * unspecified/invalid. */
#define E1DP_INVALID	0xff
/*! default location of osmo-e1d CTL protocol UNIX domain socket */
#define E1DP_DEFAULT_SOCKET "/tmp/osmo-e1d.ctl"

/*! Maximum length of HDLC messages */
#define E1DP_MAX_SIZE_HDLC	264

/*! message header of osmo-e1d CTL protocol. */
struct osmo_e1dp_msg_hdr {
	uint16_t magic;		/*< magic value (E1DP_MAGIC) */
	uint16_t len;		/*< length of message (octets) */

	uint8_t  type;		/*< message type (enum osmo_e1dp_msg_type) */
	uint8_t  intf;		/*< E1 interface number (or E1DP_INVALID) */
	uint8_t  line;		/*< E1 line number (or E1DP_INVALID) */
	uint8_t  ts;		/*< timeslot number (or E1DP_INVALID) */
} __attribute__((packed));

/*! Information about an E1 interface */
struct osmo_e1dp_intf_info {
	uint8_t id;		/*< Numeric identifier of E1 interface */
	uint8_t n_lines;	/*< number of E1 lines within this interface */
} __attribute__((packed));

/*! Configuration of an E1 line */
struct osmo_e1dp_line_config {
	uint8_t mode;		/*< E1 line mode (enum osmo_e1dp_line_mode) */
} __attribute__((packed));

/*! Information about an E1 line */
struct osmo_e1dp_line_info {
	uint8_t id;				/*< E1 line number */
	struct osmo_e1dp_line_config cfg;	/*! E1 line configuration */
	uint8_t status;				/*!< TBD */
} __attribute__((packed));

/*! Configuration of an E1 timeslot */
struct osmo_e1dp_ts_config {
	uint8_t mode;		/*< timeslot mode (enum osmo_e1dp_ts_mode) */
	uint8_t flags;		/*< flags (currently only E1DP_TS_OPEN_F_FORCE) */
	uint16_t read_bufsize;	/*< size of read buffer (in octets) */
} __attribute__((packed));

/*! Information about an E1 timeslot */
struct osmo_e1dp_ts_info {
	uint8_t id;				/*< E1 timeslot number */
	struct osmo_e1dp_ts_config cfg;		/*< E1 timeslot configuration */
	uint8_t status;				/*< TBD */
} __attribute__((packed));


struct msgb *osmo_e1dp_recv(struct osmo_fd *ofd, int *fd);
int osmo_e1dp_send(struct osmo_fd *ofd, struct msgb *msgb, int fd);

extern const struct value_string osmo_e1dp_msg_type_names[];
extern const struct value_string osmo_e1dp_line_mode_names[];
extern const struct value_string osmo_e1dp_ts_mode_names[];
