#pragma once

#include "frame_fifo.h"

struct frame_rifo {
	uint8_t *next_out;	/* where to read next output from FIFO */

	uint8_t buf[BYTES_PER_FRAME * FRAMES_PER_FIFO];

	uint32_t next_out_fn;	/* frame number of next output frame */
	uint8_t bitvec[FRAMES_PER_FIFO/8];
				/* bit-vector of occupied (data received) slots in FIFO,
				   indexed by physical offset in buf */
};

/* maximum frame number we currently can store in the rifo */
static inline uint32_t frame_rifo_max_in_fn(const struct frame_rifo *ff)
{
	return ff->next_out_fn + FRAMES_PER_FIFO - 1;
}

void frame_rifo_init(struct frame_rifo *rifo);

/* number of frames currently available in FIFO */
static inline unsigned int frame_rifo_frames(struct frame_rifo *rifo)
{
	unsigned int byte, bit;
	unsigned int frame_count = 0;

	for (byte = 0; byte < sizeof(rifo->bitvec); byte++) {
		for (bit = 0; bit < 8; bit++) {
			if (rifo->bitvec[byte] & (1 << bit))
				frame_count++;
		}
	}
	return frame_count;
}

/* put a received frame into the FIFO */
int frame_rifo_in(struct frame_rifo *rifo, const uint8_t *frame, uint32_t fn);

/* pull one frame out of the FIFO */
int frame_rifo_out(struct frame_rifo *rifo, uint8_t *out);
