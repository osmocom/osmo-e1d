/* Virtual E1 interface pair: Two virtual interfaces with N lines each,
 * where data written to A can be read from B and vice-versa.
 *
 * (C) 2020 by Harald Welte <laforge@osmocom.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>

#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <inttypes.h>

#include "e1d.h"
#include "log.h"

/* number of bits in each frame */
#define BITS_PER_FRAME		(32*8)
/* overall bit-rate of E1 line in bits per second */
#define BITRATE			2048000
/* number of frames per second (8000) */
#define FRAME_RATE		(BITRATE / BITS_PER_FRAME)
/* duration of one frame in nanoseconds (125000) */
#define FRAME_DURATION_NS	(1000000000UL / FRAME_RATE)

/* number of E1 frames (32bytes) to handle for each timer interval */
#define FRAMES_PER_TIMER	10

struct ve1_intf_data {
	/* pointer to other side of the interface pair */
	struct e1_intf *peer;
	struct osmo_fd timerfd;
};

struct ve1_line_data {
	/* pointer to other side of the interface pair */
	struct e1_line *peer;
};

static struct e1_intf *
vintf_create(struct e1_daemon *e1d, unsigned int num_lines)
{
	struct e1_intf *intf;
	struct ve1_intf_data *intf_data;
	unsigned int i;

	intf_data = talloc_zero(e1d->ctx, struct ve1_intf_data);

	intf = e1_intf_new(e1d, intf_data);
	intf->drv = E1_DRIVER_VPAIR;

	for (i = 0; i < num_lines; i++) {
		struct ve1_line_data *line_data;

		line_data = talloc_zero(e1d->ctx, struct ve1_line_data);
		e1_line_new(intf, line_data);
	}

	return intf;
}

static void
vintf_destroy(struct e1_intf *intf)
{
	OSMO_ASSERT(intf->drv == E1_DRIVER_VPAIR);
	e1_intf_destroy(intf);
	talloc_free(intf->drv_data);
}

static int
ve1_timerfd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct e1_intf *intf = ofd->data;
	struct e1_line *line, *peer;
	uint64_t expire_count;
	unsigned int frames_expired;
	int rc;

	if (!(what & OSMO_FD_READ))
		return 0;

	rc = read(ofd->fd, (void *) &expire_count, sizeof(expire_count));
	if (rc < 0 && errno == EAGAIN)
		return 0;
	OSMO_ASSERT(rc == sizeof(expire_count));

	if (expire_count > 1) {
		LOGP(DE1D, LOGL_NOTICE, "vpair timer expire_count=%" PRIu64
			": We missed %" PRIu64 " timers\n", expire_count, expire_count-1);
	}

	OSMO_ASSERT(expire_count < UINT_MAX/FRAMES_PER_TIMER);
	frames_expired = expire_count * FRAMES_PER_TIMER;

	llist_for_each_entry(line, &intf->lines, list) {
		uint8_t buf[32*frames_expired];
		struct ve1_line_data *ldata = line->drv_data;

		peer = ldata->peer;

		/* generate data on current line */
		rc = e1_line_mux_out(line, buf, frames_expired);
		OSMO_ASSERT(rc >= 0);
		/* write data to peer */
		rc = e1_line_demux_in(peer, buf, rc);
		OSMO_ASSERT(rc >= 0);

		/* generate data on peer line */
		rc = e1_line_mux_out(peer, buf, frames_expired);
		OSMO_ASSERT(rc >= 0);
		/* write data to current line */
		rc = e1_line_demux_in(line, buf, rc);
		OSMO_ASSERT(rc >= 0);
	}

	return 0;
}

int
e1d_vpair_create(struct e1_daemon *e1d, unsigned int num_lines)
{
	struct e1_intf *a, *b;
	struct e1_line *al, *bl;
	struct ve1_intf_data *adata, *bdata;
	int rc = -1;

	/* create both interfaces, each with identical line count */
	a = vintf_create(e1d, num_lines);
	if (!a)
		goto err;
	adata = a->drv_data;

	b = vintf_create(e1d, num_lines);
	if (!b)
		goto err_free_a;
	bdata = b->drv_data;

	/* point the interfaces at each other */
	adata->peer = b;
	bdata->peer = a;

	/* point the lines at each other */
	llist_for_each_entry(al, &a->lines, list) {
		struct ve1_line_data *aldata, *bldata;
		bl = e1_intf_find_line(b, al->id);
		OSMO_ASSERT(bl);
		aldata = al->drv_data;
		bldata = bl->drv_data;

		aldata->peer = bl;
		bldata->peer = al;
	}

	/* schedule timer only for 'a' side; handles both directions */
	struct timespec interval = {
		.tv_sec = 0,
		.tv_nsec = FRAME_DURATION_NS*FRAMES_PER_TIMER,
	};
	adata->timerfd.fd = -1;
	rc = osmo_timerfd_setup(&adata->timerfd, ve1_timerfd_cb, a);
	if (rc < 0)
		goto err_free_b;
	rc = osmo_timerfd_schedule(&adata->timerfd, NULL, &interval);
	if (rc < 0)
		goto err_free_b;

	return 0;

err_free_b:
	vintf_destroy(b);
err_free_a:
	vintf_destroy(a);
err:
	return rc;
}
