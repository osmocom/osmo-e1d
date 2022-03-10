#include <stdint.h>
#include <string.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include "log.h"
#include "frame_rifo.h"

static void *g_e1d_ctx;

static void rifo_in(struct frame_rifo *rifo, uint8_t *frame, uint32_t fn)
{
	printf("RIFO_IN(%s, %u)\n", osmo_hexdump_nospc(frame, BYTES_PER_FRAME), fn);
	OSMO_ASSERT(frame_rifo_in(rifo, frame, fn) == 0);
}

static int rifo_out(struct frame_rifo *rifo, uint8_t *out)
{
	int rc = frame_rifo_out(rifo, out);
	printf("RIFO_OUT(%s)=%d\n", osmo_hexdump_nospc(out, BYTES_PER_FRAME), rc);
	return rc;
}


static void missing_frames(void)
{
	struct frame_rifo rifo;
	frame_rifo_init(&rifo);

	printf("\nTEST: %s\n", __func__);

	for (int i = 0; i < 10; i++) {
		uint8_t frame[32];
		memset(frame, i, sizeof(frame));
		rifo_in(&rifo, frame, 2*i);
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
	frame_rifo_init(&rifo);

	printf("\nTEST: %s\n", __func__);

	const uint8_t in[] = { 0, 1, 4, 3, 5, 2, 6, 7, 8, 9 };
	for (int i = 0; i < sizeof(in); i++) {
		uint8_t frame[32];
		memset(frame, in[i], sizeof(frame));
		rifo_in(&rifo, frame, in[i]);
	}

	for (int i = 0; i < 10; i++) {
		uint8_t frame[32];
		memset(frame, 0xff, sizeof(frame));
		rifo_out(&rifo, frame);
	}
}


int main(int argc, char **argv)
{
	g_e1d_ctx = talloc_named_const(NULL, 0, "osmo-e1d");
	osmo_init_logging2(g_e1d_ctx, &log_info);
	missing_frames();
	reordered_in();

}
