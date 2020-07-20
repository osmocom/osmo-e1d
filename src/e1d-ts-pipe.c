/* E1 timeslot "pipe" utility: Open a 64k timeslot of osmo-e1d and connect to stdin/stdout
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

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>

#include <osmocom/e1d/proto_clnt.h>


static void *g_ctx;
static struct osmo_e1dp_client *g_client;
static struct osmo_fd ts_ofd;
static int outfd = 1;
static int infd = 0;


static int ts_open(uint8_t intf_nr, uint8_t line_nr, uint8_t ts_nr,
		   enum osmo_e1dp_ts_mode mode, uint16_t bufsize)
{
	int  rc = osmo_e1dp_client_ts_open(g_client, intf_nr, line_nr, ts_nr, mode, bufsize);
	if (rc < 0)
		fprintf(stderr, "Cannot open e1d timeslot %u:%u:%u\n", intf_nr, line_nr, ts_nr);
	return rc;
}

static int ts_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	uint8_t buf[32*10];
	int rc, count;

	if (what & OSMO_FD_READ) {
		rc = read(ofd->fd, buf, sizeof(buf));
		if (rc < 0 && errno != EAGAIN)
			exit(3);
		else if (rc > 0) {
			count = rc;
			rc = write(outfd, buf, count);
			if (rc < 0 && errno != EAGAIN)
				exit(3);
		}
	}

	if (what & OSMO_FD_WRITE) {
		rc = read(infd, buf, sizeof(buf));
		if (rc < 0 && errno != EAGAIN)
			exit(4);
		else if (rc == 0) { /* EOF */
			rc = lseek(infd, 0, SEEK_SET);
			if (rc < 0) {
				perror("rewind input file");
				exit(5);
			}
		} else if (rc > 0) {
			count = rc;
			rc = write(ofd->fd, buf, count);
			if (rc < 0 && errno != EAGAIN)
				exit(4);
		}

	}

	return 0;
}

static int set_nonblock(int fd)
{
	int rc, flags;

	flags = fcntl(fd, F_GETFL);
	OSMO_ASSERT(flags >= 0);

	rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	OSMO_ASSERT(rc >= 0);

	return 0;
}

static void print_help(void)
{
	printf(
	" -h --help                     This help message\n"
	" -p --path PATH                Path of the osmo-e1d control socket\n"
	" -i --interface <0-255>        E1 Interface Number\n"
	" -l --line <0-255>             E1 Line Number\n"
	" -t --timeslot <0-31>          E1 Timeslot Number\n"
	" -m --mode (RAW|HDLC-FCS)      E1 Timeslot Mode\n"
	" -r --read FILE                Read from FILE instead of STDIN\n"
	);
}

int main(int argc, char **argv)
{
	int intf_nr = -1, line_nr = -1, ts_nr = -1;
	enum osmo_e1dp_ts_mode mode = E1DP_TSMODE_RAW;
	char *path = E1DP_DEFAULT_SOCKET;
	int bufsize = 160;
	int tsfd;
	int option_index, rc;

	g_ctx = talloc_named_const(NULL, 0, "g_ctx");
	OSMO_ASSERT(g_ctx);

	osmo_init_logging2(g_ctx, NULL);

	/* FIXME: handle options */
	while (1) {
		int c;
		static const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "path", 1, 0, 'p' },
			{ "interface", 1, 0, 'i' },
			{ "line", 1, 0, 'l' },
			{ "timeslot", 1, 0, 't' },
			{ "mode", 1, 0, 'm' },
			{ "read", 1, 0, 'r' },
			{ "read-bufsize", 1, 0, 'b' },
			{ 0,0,0,0 }
		};

		c = getopt_long(argc, argv, "hp:i:l:t:m:r:b:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
		case 'p':
			path = optarg;
			break;
		case 'i':
			intf_nr = atoi(optarg);
			break;
		case 'l':
			line_nr = atoi(optarg);
			break;
		case 't':
			ts_nr = atoi(optarg);
			break;
		case 'm':
			rc = get_string_value(osmo_e1dp_ts_mode_names, optarg);
			if (rc < 0) {
				fprintf(stderr, "Unknown mode '%s'\n", optarg);
				exit(2);
			}
			mode = rc;
			break;
		case 'r':
			rc = open(optarg, 0, O_RDONLY);
			if (rc < 0) {
				fprintf(stderr, "Unable to open '%s': %s\n", optarg, strerror(errno));
				exit(2);
			}
			infd = rc;
			break;
		case 'b':
			bufsize = atoi(optarg);
			break;
		}
	}

	if (intf_nr == -1 || line_nr == -1 || ts_nr == -1) {
		fprintf(stderr, "You must at least specify interface, line and timeslot numbers\n");
		exit(2);
	}

	g_client = osmo_e1dp_client_create(g_ctx, path);
	if (!g_client) {
		fprintf(stderr, "Cannot establish connection to osmo-e1d at %s\n", path);
		exit(1);
	}

	tsfd = ts_open(intf_nr, line_nr, ts_nr, mode, bufsize);
	if (tsfd < 0)
		exit(2);

	osmo_fd_setup(&ts_ofd, tsfd, OSMO_FD_READ|OSMO_FD_WRITE, ts_fd_cb, NULL, 0);
	osmo_fd_register(&ts_ofd);

	set_nonblock(infd);
	set_nonblock(outfd);

	while (1) {
		osmo_select_main(0);
	}
}

