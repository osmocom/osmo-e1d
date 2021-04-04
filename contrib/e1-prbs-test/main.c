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
#include <osmocom/core/application.h>

#include <osmocom/e1d/proto_clnt.h>

#include "internal.h"

static struct test_state g_tst;
static int g_prbs_offs_rx;
static int g_prbs_offs_tx;

static int e1_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct timeslot_state *ts = ofd->data;
	uint8_t buf[4096];
	int rc, len;

	OSMO_ASSERT(what & OSMO_FD_READ);

	/* read whatever data */
	rc = read(ofd->fd, buf, sizeof(buf));
	if (rc < 0) {
		fprintf(stderr, "E1TS(%d) read: %d (%s)\n", ofd->priv_nr, rc, strerror(errno));
		return rc;
	}
	len = rc;
	process_rx(&ts->rx, ofd->priv_nr, buf, len);

	/* generate as many bytes as were read */
	process_tx(ts, len);

	return 0;
}

static void init_timeslot(struct timeslot_state *ts)
{
	osmo_fd_register(&ts->ofd);
	printf("E1TS(%02u) opened\n", ts->ofd.priv_nr);

	ts_init_prbs_tx(ts, g_prbs_offs_tx);
	ts_init_prbs_rx(ts, g_prbs_offs_rx);

	/* start to put something into the transmit queue, before we get read-triggered
	 * later on */
	process_tx(ts, 1024);
}

static int open_slots_e1d(struct test_state *tst, int intf_nr, int line_nr)
{
	struct osmo_e1dp_client *clnt = osmo_e1dp_client_create(NULL, E1DP_DEFAULT_SOCKET);
	int i, rc, num_slots = 0;

	if (!clnt) {
		fprintf(stderr, "Unable to connect to osmo-e1d\n");
		return -1;
	}

	for (i = 1; i < 32; i++) {
		struct timeslot_state *ts;
		rc = osmo_e1dp_client_ts_open(clnt, intf_nr, line_nr, i, E1DP_TSMODE_RAW, 1024);
		if (rc < 0) {
			fprintf(stderr, "Error opening %d: %d (%s)\n", i, rc, strerror(errno));
			return -1;
		}
		ts = &tst->ts[tst->next_unused_ts++];

		/* open the respective file descriptor */
		osmo_fd_setup(&ts->ofd, rc, OSMO_FD_READ, e1_fd_cb, ts, i);

		init_timeslot(ts);
		num_slots++;
	}

	return num_slots;
}

static int open_slots(struct test_state *tst, char *basedir)
{
	DIR *dir;
	struct dirent *ent;
	int rc, num_slots = 0;

	if (!strncmp(basedir, "e1d", 3)) {
		int intf = 0, line = 0;
		char *intf_str, *line_str;
		strtok(basedir, ":");
		intf_str = strtok(NULL, ":");
		if (intf_str) {
			intf = atoi(intf_str);
			line_str = strtok(NULL, ":");
			if (line_str)
				line = atoi(line_str);
		}
		return open_slots_e1d(tst, intf, line);
	}

	dir = opendir(basedir);
	if (!dir)
		return -ENOENT;

	while ((ent = readdir(dir))) {
		struct timeslot_state *ts;
		switch (ent->d_type) {
		case DT_CHR:
		case DT_FIFO:
		case DT_SOCK:
			break;
		default:
			printf("%s: skipping\n", ent->d_name);
			continue;
		}

		rc = openat(dirfd(dir), ent->d_name, O_RDWR);
		if (rc < 0) {
			fprintf(stderr, "Error opening %s: %d (%s)\n", ent->d_name, rc, strerror(errno));
			return -1;
		}
		ts = &tst->ts[tst->next_unused_ts++];

		/* open the respective file descriptor */
		osmo_fd_setup(&ts->ofd, rc, OSMO_FD_READ, e1_fd_cb, ts, atoi(ent->d_name));

		cfg_dahdi_buffer(ts->ofd.fd);
		struct dahdi_bufferinfo bi;
		rc = ioctl(ts->ofd.fd, DAHDI_GET_BUFINFO, &bi);
		OSMO_ASSERT(rc == 0);
		printf("tx_pol=%d, rx_pol=%d, num=%d, size=%d, nread=%d, nwrite=%d\n",
			bi.txbufpolicy, bi.rxbufpolicy, bi.numbufs, bi.bufsize, bi.readbufs, bi.writebufs); 

		init_timeslot(ts);
		num_slots++;
	}
	closedir(dir);
	return num_slots;
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

static int g_ctrlc_count = 0;

static void sig_handler(int signal)
{
	switch (signal) {
	case SIGINT:
		g_ctrlc_count++;
		if (g_ctrlc_count == 1) {
			print_report();
			printf("\nPlease stop remote end before pressing Ctrl+C another time\n");
		}
		if (g_ctrlc_count > 1)
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
			{ "tx-prbs-offset", 1, 0, 't' },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "r:t:", long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'r':
			g_prbs_offs_rx = atoi(optarg);
			break;
		case 't':
			g_prbs_offs_tx = atoi(optarg);
			break;
		default:
			exit(1);
		}
	}
}

int main(int argc, char **argv)
{
	char *basedir;
	int rc;
	void *g_ctx;

	handle_options(argc, argv);

	if (argc <= optind) {
		fprintf(stderr, "You must specify the base-path of your DAHDI span "
			"like /dev/dahdi/chan/001 or e1d:0:0\n");
		exit(1);
	}
	basedir = argv[optind];

	g_ctx = talloc_named_const(NULL, 0, "g_ctx");
	OSMO_ASSERT(g_ctx);
	osmo_init_logging2(g_ctx, NULL);

	set_realtime(10);
	rc = open_slots(&g_tst, basedir);
	if (rc < 0)
		exit(1);
	printf("==> opened a total of %d slots\n", rc);

	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);
	while (1) {
		osmo_select_main(0);
	}
}
