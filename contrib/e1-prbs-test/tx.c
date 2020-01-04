/* (C) 2019 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>

#include "internal.h"

void process_tx(struct timeslot_state *ts, int len)
{
	uint8_t buf[4096];
	int i, rc;

	for (i = 0; i < len; i++) {
		buf[i] = ts->tx.prbs_pc.bytes[ts->tx.prbs_pc_idx];
		ts->tx.prbs_pc_idx = (ts->tx.prbs_pc_idx + 1) % sizeof(ts->tx.prbs_pc);
	}
	rc = write(ts->ofd.fd, buf, len);
	if (rc != len)
		fprintf(stderr, "E1TS(%02u) write: %d bytes less than %d\n", ts->ofd.priv_nr, rc, len);
}
