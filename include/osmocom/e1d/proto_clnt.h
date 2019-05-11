/*
 * proto_clnt.h
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include <osmocom/core/msgb.h>

#include <osmocom/e1d/proto.h>

struct osmo_e1dp_client;

struct osmo_e1dp_client *osmo_e1dp_client_create(void *ctx, const char *path);
void osmo_e1dp_client_destroy(struct osmo_e1dp_client *srv);

int osmo_e1dp_client_intf_query(struct osmo_e1dp_client *clnt,
	struct osmo_e1dp_intf_info **ii, int *n,
	uint8_t intf);
int osmo_e1dp_client_line_query(struct osmo_e1dp_client *clnt,
	struct osmo_e1dp_line_info **li, int *n,
	uint8_t intf, uint8_t line);
int osmo_e1dp_client_ts_query(struct osmo_e1dp_client *clnt,
	struct osmo_e1dp_ts_info **ti, int *n,
	uint8_t intf, uint8_t line, uint8_t ts);
int osmo_e1dp_client_ts_open(struct osmo_e1dp_client *clnt,
	uint8_t intf, uint8_t line, uint8_t ts,
	enum osmo_e1dp_ts_mode mode);
