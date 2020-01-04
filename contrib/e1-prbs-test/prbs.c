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

#include <stdint.h>
#include <string.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/prbs.h>

#include "internal.h"

/* according to https://users.ece.cmu.edu/~koopman/lfsr/index.html all below
 * coefficients should render maximal length LFSRs of 11bit (2048) length */
static const uint32_t prbs11_coeff[] = {
	0x402,
	0x40B,
	0x415,
	0x416,
	0x423,
	0x431,
	0x432,
	0x438,
	0x43D,
	0x446,
	0x44A,
	0x44F,
	0x454,
	0x458,
	0x467,
	0x468,
	0x470,
	0x473,
	0x475,
	0x47A,
	0x486,
	0x489,
	0x492,
	0x494,
	0x49D,
	0x49E,
	0x4A2,
	0x4A4,
	0x4A8,
	0x4AD,
	0x4B9,
	0x4BA,
	0x4BF,
	0x4C1,
	0x4C7,
	0x4D5,
	0x4D6,
	0x4DC,
	0x4E3,
	0x4EC,
	0x4F2,
	0x4FB,
	0x500,
	0x503,
	0x509,
	0x50A,
	0x514,
	0x524,
	0x530,
	0x536,
	0x53C,
	0x53F,
	0x542,
	0x548,
	0x54E,
	0x553,
	0x555,
	0x559,
	0x55A,
	0x56A,
	0x56F,
	0x574,
	0x577,
	0x578,
	0x57D,
	0x581,
	0x584,
	0x588,
	0x599,
	0x59F,
	0x5A0,
	0x5A5,
	0x5AC,
	0x5AF,
	0x5B2,
	0x5B7,
	0x5BE,
	0x5C3,
	0x5C5,
	0x5C9,
	0x5CA,
	0x5D7,
	0x5DB,
	0x5DE,
	0x5E4,
	0x5ED,
	0x5EE,
	0x5F3,
	0x5F6,
	0x605,
	0x606,
	0x60C,
	0x60F,
	0x62B,
	0x630,
	0x635,
	0x639,
	0x642,
	0x644,
	0x64B
};

/* build the PRBS description for a given timeslot number */
void prbs_for_ts_nr(struct osmo_prbs *prbs, uint8_t ts_nr)
{

	OSMO_ASSERT(ts_nr < ARRAY_SIZE(prbs11_coeff));
	prbs->name = "custom";
	prbs->len = 11;
	prbs->coeff = prbs11_coeff[ts_nr];
}

/* compute one full sequence of the given PRBS */
void prbs_precomp(struct prbs_precomp *out, const struct osmo_prbs *prbs)
{
	struct osmo_prbs_state prbs_s;
	int i;

	osmo_prbs_state_init(&prbs_s, prbs);
	for (i = 0; i < sizeof(out->bytes); i++) {
		ubit_t ubit[8];
		osmo_prbs_get_ubits(ubit, sizeof(ubit), &prbs_s);
		osmo_ubit2pbit(&out->bytes[i], ubit, sizeof(ubit));
	}
}

void ts_init_prbs_tx(struct timeslot_state *ts, unsigned int prbs_offs_tx)
{
	unsigned int prbs_nr = prbs_offs_tx + ts->ofd.priv_nr;
	/* initialize the transmit-side PRNG for this slot */
	printf("Selecting PRBS11 #%02u for Tx of TS%02u\n", prbs_nr, ts->ofd.priv_nr);
	prbs_for_ts_nr(&ts->tx.prbs, prbs_nr);
	prbs_precomp(&ts->tx.prbs_pc, &ts->tx.prbs);
}

void ts_init_prbs_rx(struct timeslot_state *ts, unsigned int prbs_offs_rx)
{
	unsigned int prbs_nr = prbs_offs_rx + ts->ofd.priv_nr;
	/* initialize the receive-side PRNG for this slot */
	ubit_t ubit[PRBS_LEN*2];
	printf("Selecting PRBS11 #%02u for Rx of TS%02u\n", prbs_nr, ts->ofd.priv_nr);
	prbs_for_ts_nr(&ts->rx.prbs, prbs_nr);
	prbs_precomp(&ts->rx.prbs_pc[0], &ts->rx.prbs);
	osmo_pbit2ubit(ubit, ts->rx.prbs_pc[0].bytes, PRBS_LEN);
	/* copy buffer twice back-to-back */
	memcpy(ubit+PRBS_LEN, ubit, PRBS_LEN);

	/* pre-compute bit-shifted versions */
	for (int i = 1; i < ARRAY_SIZE(ts->rx.prbs_pc); i++) {
		osmo_ubit2pbit_ext(ts->rx.prbs_pc[i].bytes, 0, ubit, i, PRBS_LEN, 0);
		//printf("%d: %s\n", i, osmo_hexdump_nospc(ts->prbs_pc[i].bytes, sizeof(ts->prbs_pc[i].bytes)));
	}
}
