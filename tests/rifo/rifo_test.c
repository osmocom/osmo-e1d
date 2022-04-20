#include <stdint.h>
#include <string.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "log.h"
#include "frame_rifo.h"

static void *g_e1d_ctx;
static uint32_t init_next_out_fn;

static void rifo_init(struct frame_rifo *rifo)
{
	frame_rifo_init(rifo);
	rifo->next_out_fn = init_next_out_fn;
	rifo->last_in_fn  = init_next_out_fn - 1;
}

static void rifo_in(struct frame_rifo *rifo, uint8_t *frame, uint32_t fn)
{
	int rc = frame_rifo_in(rifo, frame, fn);
	printf("RIFO_IN(%s, %u)=%d [depth=%u, frames=%u]\n",
		osmo_hexdump_nospc(frame, BYTES_PER_FRAME), fn, rc,
		frame_rifo_depth(rifo), frame_rifo_frames(rifo));
}

static int rifo_out(struct frame_rifo *rifo, uint8_t *out)
{
	int rc = frame_rifo_out(rifo, out);
	printf("RIFO_OUT(%s)=%d [depth=%u, frames=%u]\n", osmo_hexdump_nospc(out, BYTES_PER_FRAME),
		rc, frame_rifo_depth(rifo), frame_rifo_frames(rifo));
	return rc;
}

static void missing_frames(uint8_t modulo)
{
	struct frame_rifo rifo;
	frame_rifo_init(&rifo);
	rifo.next_out_fn = init_next_out_fn;
	rifo.last_in_fn  = init_next_out_fn - 1;

	printf("\nTEST: %s, starting at FN: %u\n", __func__, init_next_out_fn);

	for (int i = 0; i < 10; i++) {
		uint8_t frame[32];
		memset(frame, i, sizeof(frame));

		if (i % 2 == modulo) {
			rifo_in(&rifo, frame, init_next_out_fn + i);
		}
	}

	for (int i = 0; i < 10; i++) {
		uint8_t frame[32];
		memset(frame, 0xff, sizeof(frame));
		rifo_out(&rifo, frame);
	}
}

static void reordered_in(void)
{
	struct frame_rifo rifo;
	rifo_init(&rifo);

	printf("\nTEST: %s, starting at FN: %u\n", __func__, init_next_out_fn);

	const uint8_t in[] = { 0, 1, 4, 3, 5, 2, 6, 7, 8, 9 };
	for (int i = 0; i < sizeof(in); i++) {
		uint8_t frame[32];
		memset(frame, in[i], sizeof(frame));
		rifo_in(&rifo, frame, init_next_out_fn + in[i]);
	}

	for (int i = 0; i < 10; i++) {
		uint8_t frame[32];
		memset(frame, 0xff, sizeof(frame));
		rifo_out(&rifo, frame);
	}
}

static void correct_order(void)
{
	struct frame_rifo rifo;
	rifo_init(&rifo);

	printf("\nTEST: %s, starting at FN: %u\n", __func__, init_next_out_fn);

	const uint8_t in[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	for (int i = 0; i < sizeof(in); i++) {
		uint8_t frame[32];
		memset(frame, in[i], sizeof(frame));
		rifo_in(&rifo, frame, init_next_out_fn + in[i]);
	}

	for (int i = 0; i < 10; i++) {
		uint8_t frame[32];
		memset(frame, 0xff, sizeof(frame));
		rifo_out(&rifo, frame);
	}
}

static void too_old_frames(void)
{
	struct frame_rifo rifo;
	rifo_init(&rifo);

	printf("\nTEST: %s, starting at FN: %u\n", __func__, init_next_out_fn);

	// Put 10 frames at absolute frame numbers 850-860
	// (to get outside of the 800 frame buffer)
	const uint8_t in[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	for (int i = 0; i < sizeof(in); i++) {
		uint8_t frame[32];
		memset(frame, in[i], sizeof(frame));
		rifo_in(&rifo, frame, init_next_out_fn + in[i] + 850);
	}

	// Skip the first 850 frames
	for (int i = 0; i < 850; i++) {
		uint8_t frame[32];
		memset(frame, 0xff, sizeof(frame));
		// Note: frame_rifo_out instead of rifo_out
		// (just to ignore the output)
		frame_rifo_out(&rifo, frame);
	}

	// Try to read the 10 real frames (which shouldn't be in the buffer)
	for (int i = 0; i < 10; i++) {
		uint8_t frame[32];
		memset(frame, 0xff, sizeof(frame));
		rifo_out(&rifo, frame);
	}
}

static void bound_check(void)
{
	uint8_t frame[32];
	struct frame_rifo rifo;
	rifo_init(&rifo);

	printf("\nTEST: %s, starting at FN: %u\n", __func__, init_next_out_fn);

	// Put 1 frame and get it
	memset(frame, 0xa5, sizeof(frame));
	frame_rifo_in(&rifo, frame, init_next_out_fn);
	frame_rifo_out(&rifo, frame);

	// Put 11 frames at absolute frame numbers 791-801
	const uint8_t in[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
	for (int i = 0; i < sizeof(in); i++) {
		memset(frame, in[i], sizeof(frame));
		rifo_in(&rifo, frame, init_next_out_fn + in[i] + 791);
	}

	// Add frame at start offset
	memset(frame, 0xa5, sizeof(frame));
	rifo_in(&rifo, frame, init_next_out_fn);

	// Skip the first 790 frames
	for (int i = 0; i < 790; i++) {
		memset(frame, 0xff, sizeof(frame));
		// Note: frame_rifo_out instead of rifo_out
		// (just to ignore the output)
		frame_rifo_out(&rifo, frame);
	}

	// Try to read the 10 real frames
	for (int i = 0; i < 10; i++) {
		memset(frame, 0xff, sizeof(frame));
		rifo_out(&rifo, frame);
	}
}

void run_all_tests(void)
{
	missing_frames(0);
	missing_frames(1);
	reordered_in();
	correct_order();
	too_old_frames();
	bound_check();
}

int main(int argc, char **argv)
{
	g_e1d_ctx = talloc_named_const(NULL, 0, "osmo-e1d");
	osmo_init_logging2(g_e1d_ctx, &log_info);

	// run all tests starting with a framenumber of 0
	init_next_out_fn = 0;
	run_all_tests();

	// re-run all tests at the edge of a framenumber rollover
	init_next_out_fn = 0xFFFFFFFF - 5;
	run_all_tests();
}
