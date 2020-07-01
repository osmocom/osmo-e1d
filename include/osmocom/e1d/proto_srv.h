/*
 * proto_srv.h
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
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

#include <osmocom/core/msgb.h>

struct osmo_e1dp_server;

#define E1DP_SF_INTF_OPT	(1<<0)
#define E1DP_SF_INTF_REQ	(1<<1)
#define E1DP_SF_LINE_OPT	(1<<2)
#define E1DP_SF_LINE_REQ	(1<<3)
#define E1DP_SF_TS_OPT		(1<<4)
#define E1DP_SF_TS_REQ		(1<<5)

typedef int (*osmo_e1dp_server_handler_fn)(void *data, struct msgb *msgb, struct msgb *rmsgb, int *rfd);

struct osmo_e1dp_server_handler {
	uint8_t type;
	int flags;
	int payload_len;
	osmo_e1dp_server_handler_fn fn;
};

struct osmo_e1dp_server *osmo_e1dp_server_create(void *ctx, const char *path,
	struct osmo_e1dp_server_handler *handlers, void *handler_data);
void osmo_e1dp_server_destroy(struct osmo_e1dp_server *srv);
