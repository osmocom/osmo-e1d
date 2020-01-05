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
#include <sys/ioctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dahdi/user.h>

#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/prbs.h>

#include "internal.h"

static struct test_state g_tst;
static int g_prbs_offs_rx;
static uint8_t g_usb_endpoint = 0x81;

#define E1_CHUNK_HDR_MAGIC	0xe115600d /* E1 is good */
struct e1_chunk_hdr {
	uint32_t magic;
	struct {
		uint64_t sec;
		uint64_t usec;
	} time;
	uint16_t len;		/* length of following payload */
	uint8_t ep;		/* USB endpoint */
} __attribute__((packed));

struct ts_buf {
	uint8_t bytes[1024];
};
struct line_ts_buf {
	struct ts_buf ts_buf[32];
	unsigned int next_offset;
};
static struct line_ts_buf g_line_ts_buf;

static int demux_in(struct test_state *tst, const uint8_t *data, size_t len)
{
	int i;

	if (len % 32)
		fprintf(stderr, "Length %zu is not multiple of 32\n", len);

	for (i = 0; i < len; i++) {
		uint32_t ts_nr = i % 32;
		g_line_ts_buf.ts_buf[ts_nr].bytes[g_line_ts_buf.next_offset] = data[i];

		/* go to next offset in all per-timeslot buffers */
		if (ts_nr == 31)
			g_line_ts_buf.next_offset++;

		/* if per-ts buffers are full, hand them to decoder */
		if (g_line_ts_buf.next_offset >= sizeof(g_line_ts_buf.ts_buf[0].bytes)) {
			uint8_t j;
			for (j = 0; j < 32; j++) {
				struct timeslot_state *ts = &tst->ts[j];
				//printf("process_rx(%u, %s)\n", j, osmo_hexdump(g_line_ts_buf.ts_buf[j].bytes, g_line_ts_buf.next_offset));
				process_rx(&ts->rx, j, g_line_ts_buf.ts_buf[j].bytes, g_line_ts_buf.next_offset);
			}
			memset(&g_line_ts_buf, 0, sizeof(g_line_ts_buf));
			g_line_ts_buf.next_offset = 0;
		}
	}
	return 0;
}


static int process_file(struct test_state *tst, int fd)
{
	struct e1_chunk_hdr hdr;
	unsigned long offset = 0;
	uint8_t buf[65535];
	int rc;

	while (1) {
		/* first read header */
		rc = read(fd, &hdr, sizeof(hdr));
		if (rc < 0)
			return rc;
		if (rc != sizeof(hdr)) {
			fprintf(stderr, "%d is less than header size (%zd)\n", rc, sizeof(hdr));
			return -1;
		}
		offset += rc;
		if (hdr.magic != E1_CHUNK_HDR_MAGIC) {
			fprintf(stderr, "offset %lu: Wrong magic 0x%08x\n", offset, hdr.magic);
			return -1;
		}

		/* then read payload */
		rc = read(fd, buf, hdr.len);
		if (rc < 0)
			return rc;
		offset += rc;
		if (rc != hdr.len) {
			fprintf(stderr, "%d is less than payload size (%d)\n", rc, hdr.len);
			return -1;
		}

		/* filter on the endpoint (direction) specified by the user */
		if (hdr.ep != g_usb_endpoint)
			continue;

		if (hdr.len <= 4)
			continue;

		//printf("> %s\n", osmo_hexdump(buf, hdr.len));
		demux_in(tst, buf+4, hdr.len-4);
	}
}

static int open_file(struct test_state *tst, const char *fname)
{
	int i;
	for (i = 0; i < 32; i++) {
		struct timeslot_state *ts = &tst->ts[i];
		ts->ofd.priv_nr = i;
		ts_init_prbs_rx(ts, g_prbs_offs_rx);
	}

	return open(fname, O_RDONLY);
}

static void print_report(void)
{
	struct timespec ts_now;
	int i;

	clock_gettime(CLOCK_MONOTONIC, &ts_now);

	for (i = 0; i < ARRAY_SIZE(g_tst.ts); i++) {
		const struct timeslot_state *ts = &g_tst.ts[i];
		printf("E1TS(%02u) STATS: sync_losses=%u, bit_errs=%u in %lu seconds\n",
			ts->ofd.priv_nr, ts->rx.sync_state.num_sync_loss, ts->rx.sync_state.num_bit_err,
			ts_now.tv_sec - ts->rx.sync_state.ts_sync.tv_sec);
	}
}

static void sig_handler(int signal)
{
	switch (signal) {
	case SIGINT:
		print_report();
		exit(0);
		break;
	case SIGHUP:
		print_report();
		break;
	}
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int c;
		static const struct option long_opts[] = {
			{ "rx-prbs-offset", 1, 0, 'r' },
			{ "endpoint", 1, 0, 'e' },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "r:e:", long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'r':
			g_prbs_offs_rx = atoi(optarg);
			break;
		case 'e':
			g_usb_endpoint = strtoul(optarg, NULL, 16);
			break;
		default:
			exit(1);
		}
	}
}

int main(int argc, char **argv)
{
	char *fname;
	int rc;

	handle_options(argc, argv);

	if (argc <= optind) {
		fprintf(stderr, "You must specify the file name of the ICE40-E1 capture\n");
		exit(1);
	}
	fname = argv[optind];

	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);

	rc = open_file(&g_tst, fname);
	if (rc < 0) {
		fprintf(stderr, "Error opening %s: %s\n", fname, strerror(errno));
		exit(1);
	}
	process_file(&g_tst, rc);
	print_report();
}
