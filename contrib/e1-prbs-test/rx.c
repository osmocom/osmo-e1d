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

#define _GNU_SOURCE
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>

#include "internal.h"

static uint8_t next_prbs_pc_byte(struct timeslot_state_rx *tsr)
{
	const struct prbs_precomp *pc = &tsr->prbs_pc[tsr->sync_state.prbs_pc_num];
	uint8_t ret = pc->bytes[tsr->sync_state.prbs_pc_offset];
	tsr->sync_state.prbs_pc_offset = (tsr->sync_state.prbs_pc_offset + 1) % sizeof(pc->bytes);
	return ret;
}

/* compare if received buffer matches PRBS; count number of different bits */
static unsigned int compare_buf(struct timeslot_state_rx *tsr, const uint8_t *data, unsigned int len)
{
	unsigned int i, num_wrong_bits = 0;

	for (i = 0; i < len; i++) {
		uint8_t bt = next_prbs_pc_byte(tsr);
		if (data[i] != bt) {
			uint8_t x = data[i] ^ bt;
			num_wrong_bits += bits_set_in_byte(x);
		}
	}
	return num_wrong_bits;
}

/* process incoming received data; try to correlate with prbs sequence */
void process_rx(struct timeslot_state_rx *tsr, unsigned int ts_nr, const uint8_t *data, unsigned int len)
{
	if (!tsr->sync_state.has_sync) {
		unsigned int pc_num;
		/* we haven't synced yet and must attempt to sync to the pattern.  We will try
		 * to match each pattern */
		for (pc_num = 0; pc_num < ARRAY_SIZE(tsr->prbs_pc); pc_num++) {
			const struct prbs_precomp *pc = &tsr->prbs_pc[pc_num];
			uint8_t *found;
			long int offset;

			OSMO_ASSERT(len > sizeof(pc->bytes));
			found = memmem(data, len, pc->bytes, sizeof(pc->bytes));
			if (!found)
				continue;

			offset = (found - data);
			printf("E1TS(%02u) FOUND SYNC (pc_num=%u, offset=%li)\n", ts_nr,
				pc_num, offset);
			clock_gettime(CLOCK_MONOTONIC, &tsr->sync_state.ts_sync);
			tsr->sync_state.has_sync = true;
			tsr->sync_state.prbs_pc_num = pc_num;
			tsr->sync_state.prbs_pc_offset = (sizeof(pc->bytes) - offset) % sizeof(pc->bytes);
			tsr->sync_state.num_bit_err = 0;
			/* FIXME: compare the remainder of the buffer */
			return;
		}
	}
	if (tsr->sync_state.has_sync) {
		unsigned int num_wrong_bits;
		/* we already have sync */
		num_wrong_bits = compare_buf(tsr, data, len);
		if (num_wrong_bits >= len*8/4) { /* more than 25% of wrong bits */
			struct timespec ts_now;
			clock_gettime(CLOCK_MONOTONIC, &ts_now);
			printf("E1TS(%02u) LOST SYNC after %u of %u wrong bits in one buffer; "
				"until now, total bit errors %u in %lu seconds\n", ts_nr,
				num_wrong_bits, len*8, tsr->sync_state.num_bit_err,
				ts_now.tv_sec - tsr->sync_state.ts_sync.tv_sec);
			tsr->sync_state.has_sync = false;
			tsr->sync_state.num_sync_loss++;
		}
		tsr->sync_state.num_bit_err += num_wrong_bits;
	}
}
