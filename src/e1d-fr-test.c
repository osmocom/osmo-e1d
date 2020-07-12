/* osmo-e1d client program implementing Frame Relay / ITU-T Q.933 Annex A LMI
 * This can be used to verify the new "superchannel" support in osmo-e1d for
 * transporting (among other things) frame relay.
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

#include "frame_relay.h"


static void *g_ctx;
static struct osmo_e1dp_client *g_client;
static struct osmo_fd ts_ofd;
struct fr_link *g_link;


static int ts_open(uint8_t intf_nr, uint8_t line_nr, uint8_t ts_nr,
		   enum osmo_e1dp_ts_mode mode)
{
	int  rc = osmo_e1dp_client_ts_open(g_client, intf_nr, line_nr, ts_nr, mode, 1600);
	if (rc < 0)
		fprintf(stderr, "Cannot open e1d timeslot %u:%u:%u\n", intf_nr, line_nr, ts_nr);
	return rc;
}

int fr_tx(struct msgb *msg)
{
	int rc;

	OSMO_ASSERT(g_link == msg->dst);

	printf("Tx: %s\n", msgb_hexdump(msg));
	rc = write(ts_ofd.fd, msgb_data(msg), msgb_length(msg));
	if (rc != msgb_length(msg))
		exit(23);

	msgb_free(msg);

	return rc;
}

static int dlc_rx_cb(struct fr_dlc *dlc, struct msgb *msg)
{
	printf("Rx DLCI %u: %s\n", dlc->dlci, msgb_hexdump(msg));
	msgb_free(msg);
	return 0;
}

static int ts_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int rc;

	if (what & OSMO_FD_READ) {
		struct msgb *rx = msgb_alloc(1600, "E1 Rx");
		rc = read(ofd->fd, msgb_data(rx), msgb_tailroom(rx));
		if (rc < 0 && errno != EAGAIN)
			exit(3);
		else if (rc == 0)
			exit(4);
		else if (rc > 0) {
			msgb_put(rx, rc);
			printf("Rx: %s\n", msgb_hexdump(rx));
			fr_rx(g_link, rx);
		}
	}

#if 0
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
#endif

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
	char *path = E1DP_DEFAULT_SOCKET;
	int tsfd;
	int option_index;

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
			{ 0,0,0,0 }
		};

		c = getopt_long(argc, argv, "hp:i:l:t:m:r:", long_options, &option_index);
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

	tsfd = ts_open(intf_nr, line_nr, ts_nr, E1DP_TSMODE_HDLCFCS);
	if (tsfd < 0)
		exit(2);

	int rc = osmo_e1dp_client_line_config(g_client, intf_nr, line_nr, E1DP_LMODE_SUPERCHANNEL);
	if (rc != 0)
		exit(3);

	osmo_fd_setup(&ts_ofd, tsfd, OSMO_FD_READ/*|OSMO_FD_WRITE*/, ts_fd_cb, NULL, 0);
	osmo_fd_register(&ts_ofd);

	struct fr_network *net = fr_network_alloc(NULL);
	g_link = fr_link_alloc(net);
	struct fr_dlc *dlc = fr_dlc_alloc(g_link, 23);
	dlc->rx_cb = dlc_rx_cb;

	while (1) {
		osmo_select_main(0);
	}
}

