/*
 * trunkdev.c
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
#include <talloc.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <osmocom/core/utils.h>

#include <dahdi/user.h>

#include "e1d.h"
#include "log.h"

/***********************************************************************
 * low-level trunkdev routines
 ***********************************************************************/

static int trunkdev_specify(int fd, const char *name)
{
	struct dahdi_trunkdev_open td_o = { 0 };

	OSMO_STRLCPY_ARRAY(td_o.name, name);

	return ioctl(fd, DAHDI_TRUNKDEV_OPEN, &td_o);
}

/***********************************************************************
 * osmo-e1d interface
 ***********************************************************************/

/* default dahdi chunk size: 8 chunks (in this case E1 frames) per read/write */
#define DAHDI_CHUNKSIZE		8
#define BYTES_PER_FRAME		32

/* one E1 line (DAHDI span) inside the trunkdev */
struct e1_trunkdev_line_data {
	unsigned int basechan;		/* so far, only 0 supported */
	unsigned int numchans;		/* so far, onlt 32 supported */
};

/* one DAHDI trunkdev */
struct e1_trunkdev_intf_data {
	/* file descriptor to the character device /dev/dahdi/trunkdev */
	struct osmo_fd ofd;
};

/* file-descriptor call-back.  Triggered by DAHDI via poll(), whenever
 * there is new E1 frame data available to read from trunkdev.  The flow
 * control in transmit side is simple: We write as * many frames as we are reading */
static int dahdi_trunkdev_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct e1_intf *e1i = ofd->data;
	struct e1_line *e1l = e1_intf_find_line(e1i, 0);
	uint8_t buf[DAHDI_CHUNKSIZE*BYTES_PER_FRAME];
	int rc, len;

	OSMO_ASSERT(what & OSMO_FD_READ);

	len = read(ofd->fd, buf, sizeof(buf));
	if (len <= 0) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Error %d during trunkdev read: %s\n", len,
			strerror(errno));
		return len;
	} else if (len < (int) sizeof(buf)) {
		/* for some not yet known reason this happens quite often, typically 244 of 256 bytes,
		 * followed by the remaining 32 bytes in the next read.  No data is lost, it just
		 * costs a lot of extra syscalls / context switches */
		LOGPIF(e1i, DTRUNKDEV, LOGL_DEBUG, "Short read during trunkdev read: %d < %zu\n",
			len, sizeof(buf));
	}
	if (len % BYTES_PER_FRAME) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Odd number of bytes during read: %d\n", len);
		return -EIO;
	}

	if (!e1l) {
		/* no line: discard input; transmit all-ff (BLUE) */
		memset(buf, 0xff, len);
	} else {
		/* DAHDI trunkdev currently only supports one span/line per trunk */
		rc = e1_line_demux_in(e1l, buf, len, -1);
#if 0
		if (rc < 0) {
			LOGPLI(e1l, DTRUNKDEV, LOGL_ERROR, "Error %d during e1_line_demux_in()\n", rc);
			return rc;
		}
#endif
		/* only pull as many frames out of our muxer as we have just read from the trunk */
		len = e1_line_mux_out(e1l, buf, len/BYTES_PER_FRAME);
		if (len < 0) {
			LOGPLI(e1l, DTRUNKDEV, LOGL_ERROR, "Error %d during mux_out\n", len);
			return len;
		}
	}

	rc = write(ofd->fd, buf, len);
	if (rc <= 0) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Error %d during trunkdev write: %s\n", rc,
			strerror(errno));
		return rc;
	} else if (rc < len) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Short write during trunkdev write: %d < %d\n",
			rc, len);
	}

	return 0;
}


int
e1_dahdi_trunkdev_open(struct e1_intf *e1i)
{
	struct dahdi_trunkdev_create _cr;
	struct e1_trunkdev_intf_data *tid;
	struct e1_line *e1l;
	int rc, fd;

	/* various sanity checks */

	if (e1i->drv != E1_DRIVER_DAHDI_TRUNKDEV) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Cannot open non-trunkdev trunk as trunkdev\n");
		return -EINVAL;
	}

	if (!e1i->dahdi_trunkdev.name) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Cannot open trunkdev without name\n");
		return -EINVAL;
	}

	if (strlen(e1i->dahdi_trunkdev.name) > sizeof(_cr.name)-1) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Cannot open trunkdev with excessively long name\n");
		return -EINVAL;
	}

	if (e1i->drv_data) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_NOTICE, "Cannot open trunkdev that's already open\n");
		return -EBUSY;
	}

	/* open the trunkdev */
	fd = open("/dev/dahdi/trunkdev", O_RDWR);
	if (fd < 0) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Cannot open /dev/dahdi/trunkdev: %s\n",
			strerror(errno));
		return -errno;
	}

	/* try to select the trunk by name */
	rc = trunkdev_specify(fd, e1i->dahdi_trunkdev.name);
	if (rc < 0) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Unable to specify trunkdev '%s': %s\n",
			e1i->dahdi_trunkdev.name, strerror(errno));
		/* TODO: auto- create on demand? */
		close(fd);
		return -errno;
	}

	LOGPIF(e1i, DTRUNKDEV, LOGL_NOTICE, "Successfully opened trunkdev '%s'\n", e1i->dahdi_trunkdev.name);
	tid = talloc_zero(e1i->e1d->ctx, struct e1_trunkdev_intf_data);
	OSMO_ASSERT(tid);
	osmo_fd_setup(&tid->ofd, fd, OSMO_FD_READ, dahdi_trunkdev_fd_cb, e1i, e1i->id);
	osmo_fd_register(&tid->ofd);
	e1i->drv_data = tid;

	/* ensure line0 exists */
	if (!e1_intf_find_line(e1i, 0)) {
		e1l = e1_line_new(e1i, 0, NULL);
		e1l->mode = E1_LINE_MODE_E1OIP;
	}

	/* activate line */
	llist_for_each_entry(e1l, &e1i->lines, list)
		e1_line_active(e1l);

	return 0;
}

int
e1_dahdi_trunkdev_close(struct e1_intf *e1i)
{
	struct e1_trunkdev_intf_data *tid = e1i->drv_data;
	int rc;

	if (e1i->drv != E1_DRIVER_DAHDI_TRUNKDEV) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Cannot close non-trunkdev trunk as trunkdev\n");
		return -EINVAL;
	}

	if (!tid) {
		LOGPIF(e1i, DTRUNKDEV, LOGL_DEBUG, "No need to close trunkdev; was not open\n");
		return 0;
	}

	osmo_fd_unregister(&tid->ofd);

	/* we're not deleting the dahdi trunkdev as that might upset the applications using
	 * the channel-side of it */
	rc = close(tid->ofd.fd);
	if (rc < 0)
		LOGPIF(e1i, DTRUNKDEV, LOGL_ERROR, "Error closing trunkdev: %s\n", strerror(errno));

	talloc_free(tid);
	e1i->drv_data = tid = NULL;

	LOGPIF(e1i, DTRUNKDEV, LOGL_NOTICE, "Closed trunkdev '%s'\n", e1i->dahdi_trunkdev.name);

	return 0;
}
