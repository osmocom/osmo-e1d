
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/e1d/proto_clnt.h>

static struct osmo_e1dp_client *g_client;
static struct osmo_fd g_ts_ofd[2];
static uint8_t g_counter;


static int ts_fd_read_cb(struct osmo_fd *ofd, unsigned int what)
{
	uint8_t buf[4096];
	int rc, nbytes;

	if (!(what & OSMO_FD_READ))
		return 0;

	/* read + print */
	rc = read(ofd->fd, buf, sizeof(buf));
	OSMO_ASSERT(rc > 0);
	nbytes = rc;
	printf("%u: %s\n", ofd->priv_nr, osmo_hexdump_nospc(buf, nbytes));

#if 0
	/* write just as many bytes back */
	memset(buf, g_counter, nbytes);
	rc = write(ofd->fd, buf, nbytes);
	OSMO_ASSERT(rc == nbytes);
#else
	/* write twice as many bytes on every 2nd frame */
	if (g_counter % 2 == 0) {
		memset(buf, g_counter, nbytes);
		memset(buf+nbytes, g_counter+1, nbytes);
		rc = write(ofd->fd, buf, nbytes*2);
		OSMO_ASSERT(rc == nbytes*2);
	}
#endif
	g_counter++;

	return 0;
}


int main(int argc, char **argv)
{
	int ts_fd;

	osmo_init_logging2(NULL, NULL);

	g_client = osmo_e1dp_client_create(NULL, E1DP_DEFAULT_SOCKET);
	OSMO_ASSERT(g_client);

	/* open two file descriptors of a vpair */
	ts_fd = osmo_e1dp_client_ts_open(g_client, 0, 0, 10, E1DP_TSMODE_RAW, 160);
	OSMO_ASSERT(ts_fd >= 0);
	osmo_fd_setup(&g_ts_ofd[0], ts_fd, OSMO_FD_READ, ts_fd_read_cb, NULL, 0);
	osmo_fd_register(&g_ts_ofd[0]);

	ts_fd = osmo_e1dp_client_ts_open(g_client, 1, 0, 10, E1DP_TSMODE_RAW, 160);
	OSMO_ASSERT(ts_fd >= 0);
	osmo_fd_setup(&g_ts_ofd[1], ts_fd, OSMO_FD_READ, ts_fd_read_cb, NULL, 1);
	osmo_fd_register(&g_ts_ofd[1]);

	while (1) {
		osmo_select_main(0);
	}
}
