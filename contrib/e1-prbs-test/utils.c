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
#include <sched.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <dahdi/user.h>

#include <osmocom/core/utils.h>

/* we could generate a lookup table at start ... */
uint8_t bits_set_in_byte(uint8_t byte)
{
	uint8_t ret = 0;
	int i;

	for (i = 0; i < 8; i++) {
		if (byte & (1 << i))
			ret += 1;
	}
	return ret;
}

void cfg_dahdi_buffer(int fd)
{
	struct dahdi_bufferinfo bi = {
		.txbufpolicy = DAHDI_POLICY_WHEN_FULL, /* default is immediate */
		.rxbufpolicy = DAHDI_POLICY_WHEN_FULL, /* default is immediate */
		.numbufs = 8, /* default is 2 */
		.bufsize = 1024, /* default is 1024 */
		.readbufs = -1,
		.writebufs = -1,
	};
	OSMO_ASSERT(ioctl(fd, DAHDI_SET_BUFINFO, &bi) == 0);
}

void set_realtime(int rt_prio)
{
	struct sched_param param;
	int rc;

	memset(&param, 0, sizeof(param));
	param.sched_priority = rt_prio;
	rc = sched_setscheduler(getpid(), SCHED_RR, &param);
	OSMO_ASSERT(rc == 0);
}
