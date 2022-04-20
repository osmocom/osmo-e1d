/*
 * frame_fifo.c
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
 */

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <osmocom/core/utils.h>

#include "frame_fifo.h"


/***********************************************************************
 * Frame FIFO
 ***********************************************************************/

/*! Initialize a frame FIFO.
 *  \param fifo Caller-allocated memory for FIFO data structure
 *  \param threshold After how many available frames shall we call threshold_cb
 *  \param threshold_cb Optional call-back to call whenever FIFO contains more than 'threshold' frames
 *  \param priv Opaque pointer passed to threshold_cb */
void frame_fifo_init(struct frame_fifo *fifo, unsigned int threshold,
		     void (*threshold_cb)(struct frame_fifo *fifo, unsigned int frames, void *priv),
		     void *priv)
{
	memset(fifo->buf, 0xff, sizeof(fifo->buf));
	fifo->next_in = fifo->buf;
	fifo->next_out = fifo->buf;
	fifo->threshold = threshold;
	fifo->threshold_cb = threshold_cb;
	fifo->priv = priv;
}

#define FIFO_BUF_END(f)	((f)->buf + sizeof((f)->buf))

/*! put one received frames into the FIFO.
 *  \param fifo The FIFO to which we want to put (append) multiple frames
 *  \param frame Pointer to memory containing the frame data
 *  \param count Number of frames to put into FIFO.
 *  \returns 0 on success; -1 on error (overflow */
int frame_fifo_in(struct frame_fifo *fifo, const uint8_t *frame)
{
	OSMO_ASSERT(fifo->next_in + BYTES_PER_FRAME <= FIFO_BUF_END(fifo));

	memcpy(fifo->next_in, frame, BYTES_PER_FRAME);

	fifo->next_in += BYTES_PER_FRAME;
	if (fifo->next_in >= FIFO_BUF_END(fifo))
		fifo->next_in -= sizeof(fifo->buf);

	/* FIXME: detect overflow */

	if (fifo->threshold_cb) {
		unsigned int frames_avail = frame_fifo_frames(fifo);
		if (frames_avail >= fifo->threshold)
			fifo->threshold_cb(fifo, frames_avail, fifo->priv);
	}

	return 0;
}

/*! put (append) multiple received frames into the FIFO.
 *  \param fifo The FIFO to which we want to put (append) multiple frames
 *  \param frame Pointer to memory containing the frame data
 *  \param count Number of frames to put into FIFO.
 *  \returns Number of frames actually put to FIFO; can be less than 'count' */
int frame_fifo_in_multi(struct frame_fifo *fifo, const uint8_t *frame, size_t count)
{
	const uint8_t *cur = frame;
	unsigned int i;
	int rc;

	for (i = 0; i < count; i++) {
		rc = frame_fifo_in(fifo, cur);
		/* abort on the first failing frame, there's no point in trying further */
		if (rc < 0)
			return (int) i;
		cur += BYTES_PER_FRAME;
	}
	return (int) i;
}

/*! pull one frames out of the FIFO.
 *  \param fifo The FIFO from which we want to pull frames
 *  \param out Caller-allocated output buffer
 *  \returns 0 on success; -1 on error (no frame available) */
int frame_fifo_out(struct frame_fifo *fifo, uint8_t *out)
{
	if (frame_fifo_frames(fifo) < 1)
		return -1;
	memcpy(out, fifo->next_out, BYTES_PER_FRAME);
	fifo->next_out += BYTES_PER_FRAME;

	if (fifo->next_out >= FIFO_BUF_END(fifo))
		fifo->next_out -= sizeof(fifo->buf);

	return 0;
}

/*! pull multiple frames out of the FIFO.
 *  \param fifo The FIFO from which we want ot pull frames
 *  \param out Caller-allocated output buffer
 *  \param count Number of frames to pull
 *  \returns number of frames pulled; can be 0 or less than count */
int frame_fifo_out_multi(struct frame_fifo *fifo, uint8_t *out, size_t count)
{
	uint8_t *cur = out;
	unsigned int i;
	int rc = 0;

	for (i = 0; i < count; i++) {
		rc = frame_fifo_out(fifo, cur);
		/* if there's no data in the FIFO, return number of frames
		 * pulled so far, could be 0. */
		if (rc < 0)
			return (int) i;
		cur += BYTES_PER_FRAME;
	}
	return (int) i;
}
