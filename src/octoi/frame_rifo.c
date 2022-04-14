/*
 * frame_rifo.c
 *
 * This is for the IP -> E1 direction, where IP packets may arrive with
 * re-ordering.  So this "Random [order] In, First Out" is reconstructing
 * the original order.
 *
 * (C) 2022 by Harald Welte <laforge@osmocom.org>
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

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <osmocom/core/utils.h>

#include "frame_rifo.h"


/***********************************************************************
 * Frame RIFO
 ***********************************************************************/

/* return the absolute bucket number (0.. FRAMES_PER_FIFO-1) for given fn */
static inline uint32_t bucket_for_fn(const struct frame_rifo *rifo, uint32_t fn)
{
	uint32_t next_out_bucket = (rifo->next_out - rifo->buf) / BYTES_PER_FRAME;
	/* offset in frames compared to next_out */
	uint32_t offset = (fn - rifo->next_out_fn) % FRAMES_PER_FIFO;
	return (next_out_bucket + offset) % FRAMES_PER_FIFO;
}

/* set the bucket bit for given bucket number */
static void bucket_bit_set(struct frame_rifo *rifo, uint32_t bucket_nr)
{
	uint8_t byte = bucket_nr/8;
	uint8_t bit = bucket_nr%8;

	OSMO_ASSERT(byte < sizeof(rifo->bitvec));

	rifo->bitvec[byte] |= (1 << bit);
}

/* clear the bucket bit for given bucket number */
static void bucket_bit_clear(struct frame_rifo *rifo, uint32_t bucket_nr)
{
	uint8_t byte = bucket_nr/8;
	uint8_t bit = bucket_nr%8;

	OSMO_ASSERT(byte < sizeof(rifo->bitvec));

	rifo->bitvec[byte] &= ~(1 << bit);
}

/* is the given bucket bit number set? */
static bool bucket_bit_get(struct frame_rifo *rifo, uint32_t bucket_nr)
{
	uint8_t byte = bucket_nr/8;
	uint8_t bit = bucket_nr%8;

	OSMO_ASSERT(byte < sizeof(rifo->bitvec));

	return rifo->bitvec[byte] & (1 << bit);
}

void rifo_dump(struct frame_rifo *rifo)
{
	printf("buf=%p, size=%zu, next_out=%lu, next_out_fn=%u\n", rifo->buf, sizeof(rifo->buf),
		rifo->next_out - rifo->buf, rifo->next_out_fn);
}

/*! Initialize a frame RIFO.
 *  \param rifo Caller-allocated memory for RIFO data structure */
void frame_rifo_init(struct frame_rifo *rifo)
{
	memset(rifo->buf, 0xff, sizeof(rifo->buf));
	rifo->next_out = rifo->buf;
	rifo->next_out_fn = 0;
	memset(rifo->bitvec, 0, sizeof(rifo->bitvec));
}

#define RIFO_BUF_END(f)	((f)->buf + sizeof((f)->buf))

/*! put one received frame into the RIFO at a given specified frame number.
 *  \param rifo The RIFO to which we want to put (append) multiple frames
 *  \param frame Pointer to memory containing the frame data
 *  \param fn Absolute frame number at which to insert the frame.
 *  \returns 0 on success; -1 on error (overflow) */
int frame_rifo_in(struct frame_rifo *rifo, const uint8_t *frame, uint32_t fn)
{
	uint32_t bucket;
	uint8_t *dst;

	if (!frame_rifo_fn_in_range(rifo, fn))
	{
		return -ERANGE;
	}

	bucket = bucket_for_fn(rifo, fn);
	dst = rifo->buf + bucket * BYTES_PER_FRAME;
	OSMO_ASSERT(dst + BYTES_PER_FRAME <= RIFO_BUF_END(rifo));
	memcpy(dst, frame, BYTES_PER_FRAME);
	bucket_bit_set(rifo, bucket);

	return 0;
}


/*! pull one frames out of the RIFO.
 *  \param rifo The RIFO from which we want to pull frames
 *  \param out Caller-allocated output buffer
 *  \returns 0 on success; -1 on error (no frame available) */
int frame_rifo_out(struct frame_rifo *rifo, uint8_t *out)
{
	uint32_t next_out_bucket = (rifo->next_out - rifo->buf) / BYTES_PER_FRAME;
	bool bucket_bit = bucket_bit_get(rifo, next_out_bucket);
	int rc = 0;

	if (!bucket_bit) {
		/* caller is supposed to copy/duplicate previous frame */
		rc = -1;
	} else {
		memcpy(out, rifo->next_out, BYTES_PER_FRAME);
		bucket_bit_clear(rifo, next_out_bucket);
	}

	/* advance by one frame */
	rifo->next_out += BYTES_PER_FRAME;
	rifo->next_out_fn += 1;
	if (rifo->next_out >= RIFO_BUF_END(rifo))
		rifo->next_out -= sizeof(rifo->buf);

	return rc;
}
