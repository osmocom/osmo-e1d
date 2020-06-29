/*
 * log.h
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

#include <osmocom/core/logging.h>

enum {
	DE1D,
	DXFR,
};

#define LOGPIF(itf, ss, lvl, fmt, args...) \
	LOGP(ss, lvl, "(I%u) " fmt, (itf)->id, ## args)

#define LOGPLI(li, ss, lvl, fmt, args...) \
	LOGP(ss, lvl, "(I%u:L%u) " fmt, (li)->intf->id, (li)->id, ## args)

#define LOGPTS(ts, ss, lvl, fmt, args...) \
	LOGP(ss, lvl, "(I%u:L%u:T%u) " fmt, (ts)->line->intf->id, (ts)->line->id, (ts)->id, ## args)

extern const struct log_info log_info;
