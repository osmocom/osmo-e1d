/*
 * usb.c
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
 * (C) 2022 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <talloc.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/bit32gen.h>
#include <osmocom/usb/libusb.h>

#include <libusb.h>

#include "e1d.h"
#include "log.h"
#include "ice1usb_proto.h"


#define USB_VID		0x1d50
#define USB_PID		0x6145
#define USB_PID_TRACER	0x6151

libusb_context *g_usb = NULL;


struct e1_usb_flow;


/* Driver data */

struct e1_usb_line_data {
	/* Interface */
	uint8_t if_num;

	/* End Points */
	uint8_t ep_in;
	uint8_t ep_out;
	uint8_t ep_fb;
	uint8_t ep_int;

	/* Max packet size */
	int pkt_size;

	/* Flow */
	struct e1_usb_flow *flow_in;
	struct e1_usb_flow *flow_out;
	struct e1_usb_flow *flow_fb;

	/* Interrupt */
	struct {
		uint8_t buf[10];
		struct ice1usb_irq_err last_errcnt;
	} irq;

	/* Rate regulation */
	uint32_t r_acc;
	uint32_t r_sw;

	/* list of in-progress CTRL operations */
	struct llist_head ctrl_inprogress;
};

struct e1_usb_intf_data {
	libusb_device_handle *devh;

	struct {
		uint8_t if_num;
		struct osmo_timer_list poll_timer;
		struct e1usb_gpsdo_status last_status;
	} gpsdo;

	/* list of in-progress CTRL operations */
	struct llist_head ctrl_inprogress;
};


/* Flow */

struct e1_usb_flow_entry {
	uint8_t *buf;
	struct libusb_transfer *xfr;
};

typedef int (*xfer_cb_t)(struct e1_usb_flow *flow, uint8_t *buf, int len);

struct e1_usb_flow {
	struct e1_line *line;
	xfer_cb_t cb;

	uint8_t ep;

	int count;
	int size;
	int ppx;

	struct e1_usb_flow_entry *entries;
};

// ---------------------------------------------------------------------------
// USB data transfer
// ---------------------------------------------------------------------------

static int
e1_usb_xfer_in(struct e1_usb_flow *flow, uint8_t *buf, int len)
{
	if (len == 0)
		return 0;
	return e1_line_demux_in(flow->line, buf + 4, len - 4, buf[3] & 0xf);
}

static int
e1_usb_xfer_out(struct e1_usb_flow *flow, uint8_t *buf, int len)
{
	struct e1_line *line = flow->line;
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	int fm, fts;

	if (len <= 0) {
		LOGPLI(line, DXFR, LOGL_ERROR, "OUT ERROR: %d\n", len);
		return -1;
	}

	/* Flow regulation */
	ld->r_acc += ld->r_sw;

	fm = (ld->pkt_size - 4) / 32;
	fts = ld->r_acc >> 10;
	if      (fts <  4) fts = 4;
	else if (fts > fm) fts = fm;

	ld->r_acc -= fts << 10;
	if (ld->r_acc & 0x80000000)
		ld->r_acc = 0;

	memset(buf, 0xff, 4);

	return e1_line_mux_out(line, buf+4, fts) + 4;
}

static int
e1_usb_xfer_fb(struct e1_usb_flow *flow, uint8_t *buf, int len)
{
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) flow->line->drv_data;

	if (len < 0) {
		LOGPLI(flow->line, DE1D, LOGL_ERROR, "Feedback transfer error\n");
		return 0;
	} else if (len != 3) {
		LOGPLI(flow->line, DE1D, LOGL_ERROR, "Feedback packet invalid len (%d)\n", len);
		return 0;
	}

	ld->r_sw = (buf[2] << 16) | (buf[1] << 8) | buf[0];

	return 0;
}


// ---------------------------------------------------------------------------
// USB flow
// ---------------------------------------------------------------------------

/* strings for enum libusb_transfer_status */
static const struct value_string libusb_status_str[] = {
	{ LIBUSB_TRANSFER_COMPLETED,	"COMPLETED" },
	{ LIBUSB_TRANSFER_ERROR,	"ERROR" },
	{ LIBUSB_TRANSFER_TIMED_OUT,	"TIMED_OUT" },
	{ LIBUSB_TRANSFER_CANCELLED,	"CANCELLED" },
	{ LIBUSB_TRANSFER_STALL,	"STALL" },
	{ LIBUSB_TRANSFER_NO_DEVICE,	"NO_DEVICE" },
	{ LIBUSB_TRANSFER_OVERFLOW,	"OVERFLOW" },
	{ 0, NULL }
};

static void LIBUSB_CALL
_e1uf_xfr(struct libusb_transfer *xfr)
{
	struct e1_usb_flow *flow = (struct e1_usb_flow *) xfr->user_data;
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) flow->line->intf->drv_data;
	int j, rv, len;

	len = 0;

	/* FIXME: Check transfer status ? Error handling ? */


	if (flow->ep & 0x80) {
		for (j = 0; j < flow->ppx; j++) {
			struct libusb_iso_packet_descriptor *iso_pd = &xfr->iso_packet_desc[j];
			if (iso_pd->status != LIBUSB_TRANSFER_COMPLETED) {
				LOGPLI(flow->line, DE1D, LOGL_ERROR, "IN EP %02x ISO packet %d failed with status %s\n",
					flow->ep, j, get_value_string(libusb_status_str, iso_pd->status));
			}
			flow->cb(flow,
				libusb_get_iso_packet_buffer_simple(xfr, j),
				(iso_pd->status == LIBUSB_TRANSFER_COMPLETED) ?  (int)iso_pd->actual_length : -1
			);
			len += (iso_pd->length = flow->size);
		}
	} else {
		for (j = 0; j < flow->ppx; j++) {
			struct libusb_iso_packet_descriptor *iso_pd = &xfr->iso_packet_desc[j];
			if (iso_pd->status != LIBUSB_TRANSFER_COMPLETED) {
				LOGPLI(flow->line, DE1D, LOGL_ERROR, "OUT EP %02x ISO packet %d failed with status %s\n",
					flow->ep, j, get_value_string(libusb_status_str, iso_pd->status));
			}
			len += (iso_pd->length = flow->cb(flow, &xfr->buffer[len], flow->size));
		}
	}

	libusb_fill_iso_transfer(xfr, id->devh, flow->ep,
		xfr->buffer, len, flow->ppx,
		_e1uf_xfr, flow, 0
	);

	rv = libusb_submit_transfer(xfr);
	if (rv) {
		LOGPLI(flow->line, DE1D, LOGL_ERROR, "EP %02x Failed to resubmit buffer for transfer: %s\n",
		       flow->ep, libusb_strerror(rv));
	}
}

static struct e1_usb_flow *
e1uf_create(struct e1_line *line, xfer_cb_t cb,
            int ep, int count, int size, int ppx)
{
	void *ctx = line->intf->e1d->ctx;
	struct e1_usb_flow *flow;

	flow = talloc_zero(ctx, struct e1_usb_flow);
	OSMO_ASSERT(flow);

	flow->line  = line;
	flow->cb    = cb;
	flow->ep    = ep;
	flow->count = count;
	flow->size  = size;
	flow->ppx   = ppx;
	flow->entries = talloc_zero_size(ctx, count * sizeof(struct e1_usb_flow_entry));

	for (int i = 0; i < count; i++)
		flow->entries[i].buf = talloc_zero_size(ctx, size * ppx);

	return flow;
}

static void __attribute__((unused))
e1uf_destroy(struct e1_usb_flow *flow)
{
	if (!flow)
		return;

	/* FIXME: stop pending transfers */
	for (int i = 0; i < flow->count; i++)
		talloc_free(flow->entries[i].buf);

	talloc_free(flow->entries);
	talloc_free(flow);
}

static int
e1uf_start(struct e1_usb_flow *flow)
{
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) flow->line->intf->drv_data;
	struct libusb_transfer *xfr;
	int i, j, rv, len;

	for (i = 0; i < flow->count; i++) {
		xfr = libusb_alloc_transfer(flow->ppx);
		if (!xfr)
			return -ENOMEM;

		len = 0;

		if (flow->ep & 0x80) {
			for (j = 0; j < flow->ppx; j++)
				len += (xfr->iso_packet_desc[j].length = flow->size);
		} else {
			for (j = 0; j < flow->ppx; j++)
				len += (xfr->iso_packet_desc[j].length = flow->cb(flow, &flow->entries[i].buf[len], flow->size));
		}

		libusb_fill_iso_transfer(xfr, id->devh, flow->ep,
			flow->entries[i].buf, len, flow->ppx,
			_e1uf_xfr, flow, 0
		);

		rv = libusb_submit_transfer(xfr);
		if (rv) {
			LOGPLI(flow->line, DE1D, LOGL_ERROR, "EP %02x: Error submitting transfer %d: %s\n",
			       flow->ep, i, libusb_strerror(rv));
			return rv;
		}

		flow->entries[i].xfr = xfr;
	}

	return 0;
}

// ---------------------------------------------------------------------------
// USB interrupt
// ---------------------------------------------------------------------------

static int resubmit_irq(struct e1_line *line);

/* compute how much advanced 'cur' is copared to 'prev', in modulo-0xffff for wraps */
static uint32_t delta_mod_u16(uint32_t cur, uint32_t prev)
{
	return ((cur + 0xffff) - prev) % 0xffff;
}

static void rx_interrupt_errcnt(struct e1_line *line, const struct ice1usb_irq_err *errcnt)
{
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	struct ice1usb_irq_err *last = &ld->irq.last_errcnt;

	if (errcnt->crc != last->crc) {
		LOGPLI(line, DE1D, LOGL_ERROR, "CRC error count %d (was %d)\n",
			errcnt->crc, last->crc);
		line_ctr_add(line, LINE_CTR_CRC_ERR, delta_mod_u16(errcnt->crc, last->crc));
	}

	if (errcnt->align != last->align) {
		LOGPLI(line, DE1D, LOGL_ERROR, "ALIGNMENT error count %d (was %d)\n",
			errcnt->align, last->align);
		line_ctr_add(line, LINE_CTR_LOA, delta_mod_u16(errcnt->align, last->align));
	}

	if (errcnt->ovfl != last->ovfl) {
		LOGPLI(line, DE1D, LOGL_ERROR, "OVERFLOW error count %d (was %d)\n",
			errcnt->ovfl, last->ovfl);
		line_ctr_add(line, LINE_CTR_RX_OVFL, delta_mod_u16(errcnt->ovfl, last->ovfl));
	}

	if (errcnt->unfl != last->unfl) {
		LOGPLI(line, DE1D, LOGL_ERROR, "UNDERFLOW error count %d (was %d)\n",
			errcnt->unfl, last->unfl);
		line_ctr_add(line, LINE_CTR_TX_UNFL, delta_mod_u16(errcnt->unfl, last->unfl));
	}

	if ((errcnt->flags & ICE1USB_ERR_F_ALIGN_ERR) != (last->flags & ICE1USB_ERR_F_ALIGN_ERR)) {
		LOGPLI(line, DE1D, LOGL_ERROR, "ALIGNMENT %s\n",
			errcnt->flags & ICE1USB_ERR_F_ALIGN_ERR ? "LOST" : "REGAINED");
	}

	if ((errcnt->flags & ICE1USB_ERR_F_LOS) != (last->flags & ICE1USB_ERR_F_LOS)) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Rx Clock %s\n",
			errcnt->flags & ICE1USB_ERR_F_LOS ? "LOST" : "REGAINED");
		if (errcnt->flags & ICE1USB_ERR_F_LOS)
			line_ctr_add(line, LINE_CTR_LOS, 1);
	}

	if ((errcnt->flags & ICE1USB_ERR_F_RAI) != (last->flags & ICE1USB_ERR_F_RAI)) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Remote Alarm (YELLOW) %s\n",
			errcnt->flags & ICE1USB_ERR_F_RAI ? "PRESENT" : "ABSENT");
		/* don't increment counter here, our TS0 code in mux_demux.c does this */
	}

	ld->irq.last_errcnt = *errcnt;
}

static void interrupt_ep_cb(struct libusb_transfer *xfer)
{
	struct e1_line *line = (struct e1_line *) xfer->user_data;
	const struct ice1usb_irq *irq = (const struct ice1usb_irq *) xfer->buffer;

	if (xfer->status != LIBUSB_TRANSFER_COMPLETED) {
		LOGPLI(line, DE1D, LOGL_ERROR, "INT EP %02x transfer failed with status %s\n",
			xfer->endpoint, get_value_string(libusb_status_str, xfer->status));
		goto out;
	}

	if (!xfer->actual_length) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Zero-Length Interrupt transfer\n");
		goto out;
	}

	switch (irq->type) {
	case ICE1USB_IRQ_T_ERRCNT:
		if (xfer->actual_length < (int)sizeof(*irq)) {
			LOGPLI(line, DE1D, LOGL_ERROR, "Short ERRCNT interrupt: %u<%zu\n",
				xfer->actual_length, sizeof(*irq));
			break;
		}
		rx_interrupt_errcnt(line, &irq->u.errors);
		break;
	default:
		LOGPLI(line, DE1D, LOGL_INFO, "Unsupported interrupt 0x%02x\n", irq->type);
		break;
	}

out:
	resubmit_irq(line);
}

static int resubmit_irq(struct e1_line *line)
{
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) line->intf->drv_data;
	struct libusb_transfer *xfr = libusb_alloc_transfer(0);
	int rv;

	libusb_fill_interrupt_transfer(xfr, id->devh, ld->ep_int, ld->irq.buf, sizeof(ld->irq.buf),
					interrupt_ep_cb, line, 0);
	rv = libusb_submit_transfer(xfr);
	if (rv != LIBUSB_SUCCESS) {
		LOGPLI(line, DE1D, LOGL_ERROR, "EP %02x: Error submitting IRQ transfer: %s\n",
			ld->ep_int, libusb_strerror(rv));
	}

	return rv;
}

// ---------------------------------------------------------------------------
// Control transfers (USB interface == E1 line level)
// ---------------------------------------------------------------------------

struct e1_usb_ctrl_xfer {
	struct e1_line *line;
	struct llist_head list;
	/* 8 bytes control setup packet, remainder for data */
	uint8_t buffer[8 + 8];
};


static void
ctrl_xfer_compl_cb(struct libusb_transfer *xfr)
{
	struct e1_usb_ctrl_xfer *ucx = xfr->user_data;

	switch (xfr->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		LOGPLI(ucx->line, DE1D, LOGL_INFO, "CTRL transfer completed successfully\n");
		break;
	default:
		LOGPLI(ucx->line, DE1D, LOGL_ERROR, "CTRL transfer completed unsuccessfully %d\n",
			xfr->status);
		break;
	}
	llist_del(&ucx->list);
	talloc_free(ucx);
	libusb_free_transfer(xfr);
}

// ---------------------------------------------------------------------------
// Control transfers (USB device == E1 interface level)
// ---------------------------------------------------------------------------

/* generic helper for async transmission of control endpoint requests */
static int
_e1_usb_line_send_ctrl(struct e1_line *line, uint8_t bmReqType, uint8_t bReq, uint16_t wValue,
		       const uint8_t *data, size_t data_len)
{
	struct e1_usb_ctrl_xfer *ucx = talloc_zero(line, struct e1_usb_ctrl_xfer);
	struct e1_usb_line_data *ld = (struct e1_usb_line_data *) line->drv_data;
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) line->intf->drv_data;
	struct libusb_transfer *xfr;
	int rc;

	if (!ucx)
		return -ENOMEM;

	OSMO_ASSERT(sizeof(ucx->buffer) >= 8+data_len);
	ucx->line = line;
	libusb_fill_control_setup(ucx->buffer, bmReqType, bReq, wValue, ld->if_num, data_len);
	if (data && data_len)
		memcpy(ucx->buffer+8, data, data_len);

	xfr = libusb_alloc_transfer(0);
	if (!xfr) {
		rc = -ENOMEM;
		goto free_ucx;
	}

	libusb_fill_control_transfer(xfr, id->devh, ucx->buffer, ctrl_xfer_compl_cb, ucx, 3000);
	rc = libusb_submit_transfer(xfr);
	if (rc != 0) {
		LOGPLI(line, DE1D, LOGL_ERROR, "Error submitting control transfer: %s\n",
			libusb_strerror(rc));
		goto free_xfr;
	}

	llist_add_tail(&ucx->list, &ld->ctrl_inprogress);

	return 0;

free_xfr:
	libusb_free_transfer(xfr);
free_ucx:
	talloc_free(ucx);

	return rc;
}

int
e1_usb_ctrl_set_tx_cfg(struct e1_line *line, enum ice1usb_tx_mode mode, enum ice1usb_tx_timing timing,
			enum ice1usb_tx_ext_loopback ext_loop, uint8_t alarm)
{
	const uint16_t bmReqType = LIBUSB_RECIPIENT_INTERFACE | LIBUSB_REQUEST_TYPE_VENDOR |
				   LIBUSB_ENDPOINT_OUT;
	struct ice1usb_tx_config tx_cfg = {
		.mode = mode,
		.timing = timing,
		.ext_loopback = ext_loop,
		.alarm = alarm,
	};

	return _e1_usb_line_send_ctrl(line, bmReqType, ICE1USB_INTF_SET_TX_CFG, 0, (uint8_t *)&tx_cfg,
				      sizeof(tx_cfg));
}

int
e1_usb_ctrl_set_rx_cfg(struct e1_line *line, enum ice1usb_rx_mode mode)
{
	const uint16_t bmReqType = LIBUSB_RECIPIENT_INTERFACE | LIBUSB_REQUEST_TYPE_VENDOR |
				   LIBUSB_ENDPOINT_OUT;
	struct ice1usb_rx_config rx_cfg = {
		.mode = mode,
	};

	return _e1_usb_line_send_ctrl(line, bmReqType, ICE1USB_INTF_SET_RX_CFG, 0, (uint8_t *)&rx_cfg,
				      sizeof(rx_cfg));
}

struct e1_usb_ctrl_xfer_intf {
	struct e1_intf *intf;
	struct llist_head list;
	/* 8 bytes control setup packet, remainder for data */
	uint8_t buffer[8 + sizeof(struct e1usb_gpsdo_status)];
};

static void _e1_usb_intf_gpsdo_status_cb(struct e1_intf *intf, const uint8_t *data, size_t len);

static void
ctrl_xfer_intf_compl_cb(struct libusb_transfer *xfr)
{
	struct e1_usb_ctrl_xfer_intf *ucx = xfr->user_data;
	struct libusb_control_setup *setup;

	switch (xfr->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		setup = (struct libusb_control_setup *) ucx->buffer;
		LOGPIF(ucx->intf, DE1D, LOGL_DEBUG, "CTRL transfer completed successfully: %s\n",
			osmo_hexdump(ucx->buffer, 8+xfr->actual_length));
		switch (setup->bRequest) {
		case ICE1USB_INTF_GET_GPSDO_STATUS:
			_e1_usb_intf_gpsdo_status_cb(ucx->intf, ucx->buffer+8, xfr->actual_length);
			break;
		default:
			break;
		}
		break;
	default:
		LOGPIF(ucx->intf, DE1D, LOGL_ERROR, "CTRL transfer completed unsuccessfully %d\n",
			xfr->status);
		break;
	}
	llist_del(&ucx->list);
	talloc_free(ucx);
	libusb_free_transfer(xfr);
}


/* generic helper for async transmission of control endpoint requests */
static int
_e1_usb_intf_send_ctrl(struct e1_intf *intf, uint8_t bmReqType, uint8_t bReq, uint16_t wValue,
		       const uint8_t *data, size_t data_len)
{
	struct e1_usb_ctrl_xfer_intf *ucx = talloc_zero(intf, struct e1_usb_ctrl_xfer_intf);
	struct e1_usb_intf_data *id = (struct e1_usb_intf_data *) intf->drv_data;
	struct libusb_transfer *xfr;
	int rc;

	if (!ucx)
		return -ENOMEM;

	OSMO_ASSERT(sizeof(ucx->buffer) >= 8+data_len);
	ucx->intf = intf;
	libusb_fill_control_setup(ucx->buffer, bmReqType, bReq, wValue, id->gpsdo.if_num, data_len);
	if (data && data_len)
		memcpy(ucx->buffer+8, data, data_len);

	xfr = libusb_alloc_transfer(0);
	if (!xfr) {
		rc = -ENOMEM;
		goto free_ucx;
	}

	libusb_fill_control_transfer(xfr, id->devh, ucx->buffer, ctrl_xfer_intf_compl_cb, ucx, 3000);
	rc = libusb_submit_transfer(xfr);
	if (rc != 0) {
		LOGPIF(intf, DE1D, LOGL_ERROR, "Error submitting control transfer: %s\n",
			libusb_strerror(rc));
		goto free_xfr;
	}

	llist_add_tail(&ucx->list, &id->ctrl_inprogress);

	return 0;

free_xfr:
	libusb_free_transfer(xfr);
free_ucx:
	talloc_free(ucx);

	return rc;
}

int
e1_usb_ctrl_set_gpsdo_mode(struct e1_intf *intf, enum ice1usb_gpsdo_mode gpsdo_mode)
{
	const uint16_t bmReqType = LIBUSB_RECIPIENT_INTERFACE | LIBUSB_REQUEST_TYPE_VENDOR |
				   LIBUSB_ENDPOINT_OUT;
	return _e1_usb_intf_send_ctrl(intf, bmReqType, ICE1USB_INTF_SET_GPSDO_MODE, gpsdo_mode,
				      NULL, 0);
}

int
e1_usb_ctrl_set_gpsdo_tune(struct e1_intf *intf, const struct e1usb_gpsdo_tune *gpsdo_tune)
{
	const uint16_t bmReqType = LIBUSB_RECIPIENT_INTERFACE | LIBUSB_REQUEST_TYPE_VENDOR |
				   LIBUSB_ENDPOINT_OUT;
	return _e1_usb_intf_send_ctrl(intf, bmReqType, ICE1USB_INTF_SET_GPSDO_TUNE, 0,
				      (uint8_t *)gpsdo_tune, sizeof(*gpsdo_tune));
}

int
e1_usb_ctrl_get_gpsdo_status(struct e1_intf *intf)
{
	const uint16_t bmReqType = LIBUSB_RECIPIENT_INTERFACE | LIBUSB_REQUEST_TYPE_VENDOR |
				   LIBUSB_ENDPOINT_IN;
	return _e1_usb_intf_send_ctrl(intf, bmReqType, ICE1USB_INTF_GET_GPSDO_STATUS, 0,
				      NULL, sizeof(struct e1usb_gpsdo_status));
}

// ---------------------------------------------------------------------------
// GPS-DO
// ---------------------------------------------------------------------------

static const struct value_string ice1usb_gpsdo_mode_str[] = {
	{ ICE1USB_GPSDO_MODE_DISABLED,		"DISABLED" },
	{ ICE1USB_GPSDO_MODE_AUTO,		"AUTO" },
	{ 0, NULL }
};

static const struct value_string ice1usb_gpsdo_antenna_state_str[] = {
	{ ICE1USB_GPSDO_ANT_UNKNOWN,		"UNKNOWN" },
	{ ICE1USB_GPSDO_ANT_OK,			"OK" },
	{ ICE1USB_GPSDO_ANT_OPEN,		"OPEN" },
	{ ICE1USB_GPSDO_ANT_SHORT,		"SHORT" },
	{ 0, NULL }
};

static const struct value_string ice1usb_gpsdo_state_str[] = {
	{ ICE1USB_GPSDO_STATE_DISABLED,		"DISABLED" },
	{ ICE1USB_GPSDO_STATE_CALIBRATE,	"CALIBRATE" },
	{ ICE1USB_GPSDO_STATE_HOLD_OVER,	"HOLD_OVER" },
	{ ICE1USB_GPSDO_STATE_TUNE_COARSE,	"TUNE_COARSE" },
	{ ICE1USB_GPSDO_STATE_TUNE_FINE,	"TUNE_FINE" },
	{ 0, NULL }
};

int
e1_usb_intf_gpsdo_state_string(char *buf, size_t len, const struct e1_intf *intf)
{
	struct e1_usb_intf_data *id = intf->drv_data;
	struct e1usb_gpsdo_status *last_st = &id->gpsdo.last_status;

	OSMO_ASSERT(intf->drv == E1_DRIVER_USB);

	return snprintf(buf, len, "mode=%s, fix=%s, state=%s antenna=%s, tune=%u/%u, freq_est=%u",
			get_value_string(ice1usb_gpsdo_mode_str, last_st->mode),
			last_st->valid_fix ? "TRUE" : "FALSE",
			get_value_string(ice1usb_gpsdo_state_str, last_st->state),
			get_value_string(ice1usb_gpsdo_antenna_state_str, last_st->antenna_state),
			libusb_le16_to_cpu(last_st->tune.coarse), libusb_le16_to_cpu(last_st->tune.fine),
			osmo_load32le(&last_st->freq_est));
}

static void
_e1_usb_intf_gpsdo_status_cb(struct e1_intf *intf, const uint8_t *data, size_t len)
{
	struct e1_usb_intf_data *id = intf->drv_data;
	struct e1usb_gpsdo_status *last_st = &id->gpsdo.last_status;
	struct e1usb_gpsdo_status _st, *st = &_st;
	struct e1_line *line;

	if (len < sizeof(*st)) {
		/*
		 * Because some fields can be added to the structure by newer
		 * firmware revisions, this means we can potentially get a shorter
		 * struct than what we asked for. We simply set those fields to
		 * zero.
		 *
		 * The opposite case (newer firmware than e1d) means the structure
		 * could be larger, but because we limit the wLength to the struct
		 * we know, we can't receive a larger one and the new fields are
		 * just ignored by this e1d version
		 */
		LOGPIF(intf, DE1D, LOGL_DEBUG,
			"GPSDO status %zu < %zu ! Firmware probably outdated. "
			"Some values will be zeroed\n",
			len, sizeof(*st));
	}

	memset(st, 0x00, sizeof(*st));
	memcpy(st, data, len);

	if (st->state != last_st->state) {
		LOGPIF(intf, DE1D, LOGL_NOTICE, "GPSDO state change: %s -> %s\n",
			get_value_string(ice1usb_gpsdo_state_str, last_st->state),
			get_value_string(ice1usb_gpsdo_state_str, st->state));
	}

	if (st->antenna_state != last_st->antenna_state) {
		int level = LOGL_NOTICE;
		switch (st->antenna_state) {
		case ICE1USB_GPSDO_ANT_OPEN:
		case ICE1USB_GPSDO_ANT_SHORT:
			level = LOGL_ERROR;
			break;
		default:
			level = LOGL_NOTICE;
		}
		LOGPIF(intf, DE1D, level, "GPS antenna status change: %s -> %s\n",
			get_value_string(ice1usb_gpsdo_antenna_state_str, last_st->antenna_state),
			get_value_string(ice1usb_gpsdo_antenna_state_str, st->antenna_state));
	}

	if (st->valid_fix != last_st->valid_fix) {
		if (st->valid_fix)
			LOGPIF(intf, DE1D, LOGL_NOTICE, "GPS Fix achieved\n");
		else
			LOGPIF(intf, DE1D, LOGL_ERROR, "GPS Fix LOST\n");
	}

	/* update stat_items for statsd / monitoring */
	llist_for_each_entry(line, &intf->lines, list) {
		line_stat_set(line, LINE_GPSDO_STATE, st->state);
		line_stat_set(line, LINE_GPSDO_ANTENNA, st->antenna_state);
		line_stat_set(line, LINE_GPSDO_TUNE_COARSE, libusb_le16_to_cpu(st->tune.coarse));
		line_stat_set(line, LINE_GPSDO_TUNE_FINE, libusb_le16_to_cpu(st->tune.fine));
		line_stat_set(line, LINE_GPSDO_FREQ_EST, osmo_load32le(&st->freq_est));
		line_stat_set(line, LINE_GPSDO_ERR_ACC, (int16_t)libusb_le16_to_cpu(st->err_acc));
	}

	/* update our state */
	memcpy(last_st, st, sizeof(*last_st));
}

static void
_e1_usb_gpsdo_poll_cb(void *data)
{
	struct e1_intf *intf = (struct e1_intf *) data;
	struct e1_usb_intf_data *id = intf->drv_data;

	/* issue a control endpoint request, further processing is when it completes */
	e1_usb_ctrl_get_gpsdo_status(intf);

	osmo_timer_schedule(&id->gpsdo.poll_timer, 1, 0);
}

static void
_e1_usb_gpsdo_init(struct e1_intf *intf)
{
	struct e1_usb_intf_data *id = intf->drv_data;

	if (intf->usb.gpsdo.manual) {
		struct e1usb_gpsdo_tune tune = {
			.coarse = intf->usb.gpsdo.coarse,
			.fine   = intf->usb.gpsdo.fine,
		};
		e1_usb_ctrl_set_gpsdo_mode(intf, ICE1USB_GPSDO_MODE_DISABLED);
		e1_usb_ctrl_set_gpsdo_tune(intf, &tune);
	} else {
		e1_usb_ctrl_set_gpsdo_mode(intf, ICE1USB_GPSDO_MODE_AUTO);
	}

	osmo_timer_setup(&id->gpsdo.poll_timer, &_e1_usb_gpsdo_poll_cb, intf);
	osmo_timer_schedule(&id->gpsdo.poll_timer, 1, 0);
}

// ---------------------------------------------------------------------------
// Init / Probing
// ---------------------------------------------------------------------------

static int
_e1_usb_open_device(struct e1_daemon *e1d, struct libusb_device *dev, bool is_tracer)
{
	struct e1_intf *intf;
	struct e1_line *line;
	struct e1_usb_intf_data *intf_data;
	struct e1_usb_line_data *line_data;
	struct libusb_device_descriptor dd;
	struct libusb_config_descriptor *cd;
	const struct libusb_interface_descriptor *id;
	bool auto_create_lines;
	char serial_str[64];
	libusb_device_handle *devh;
	int line_nr = 0;
	int i, j, ret;

	ret = libusb_open(dev, &devh);
	if (ret) {
		LOGP(DE1D, LOGL_ERROR, "Failed to open usb device: %s\n", libusb_strerror(ret));
		return ret;
	}

	ret = libusb_get_device_descriptor(dev, &dd);
	if (ret) {
		LOGP(DE1D, LOGL_ERROR, "Failed to get device descriptor: %s\n", libusb_strerror(ret));
		libusb_close(devh);
		return ret;
	}

	/* this is actually a synchronous / blocking call, and if we detect a second icE1usb device while the
	 * first one is running, we might be delaying/blocking any important USB transfers.  However, as we
	 * still only call this probe function once at start-up and don't support hot-plugging yet, we can get
	 * away with it. */
	ret = libusb_get_string_descriptor_ascii(devh, dd.iSerialNumber, (uint8_t *)serial_str, sizeof(serial_str));
	if (ret < 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to get iSerialNumber string descriptor: %s\n", libusb_strerror(ret));
		libusb_close(devh);
		return ret;
	}

	/* try to find the matching interface config created by the vty */
	intf = e1d_find_intf_by_usb_serial(e1d, serial_str);
	if (intf) {
		LOGP(DE1D, LOGL_INFO, "Configuration for icE1usb serial '%s' found\n", serial_str);
		auto_create_lines = false;
		if (intf->drv_data) {
			LOGP(DE1D, LOGL_ERROR, "New device with serial '%s', but E1 interface %u busy\n",
			     serial_str, intf->id);
			libusb_close(devh);
			return -EBUSY;
		}
		intf_data = talloc_zero(e1d->ctx, struct e1_usb_intf_data);
		intf_data->devh = devh;
		intf->drv_data = intf_data;
	} else {
		LOGP(DE1D, LOGL_NOTICE, "No configuration for icE1usb serial '%s' found, "
		     "auto-generating it\n", serial_str);
		auto_create_lines = true;
		intf_data = talloc_zero(e1d->ctx, struct e1_usb_intf_data);
		intf_data->devh = devh;
		intf = e1_intf_new(e1d, -1, intf_data);
		intf->drv = E1_DRIVER_USB;
		osmo_talloc_replace_string(intf, &intf->usb.serial_str, serial_str);
	}

	/* we have prior knowledge that the e1-tracer firmware configuration 2 is the e1d compatible mode. */
	if (is_tracer) {
		if (libusb_set_configuration(devh, 2) != LIBUSB_SUCCESS) {
			LOGP(DE1D, LOGL_ERROR, "Cannot set configuration 2 of e1-tracer device. Maybe too old firmware?\n");
			libusb_close(devh);
			return -EIO;
		}
	}

	INIT_LLIST_HEAD(&intf_data->ctrl_inprogress);

	ret = libusb_get_active_config_descriptor(dev, &cd);
	if (ret) {
		LOGP(DE1D, LOGL_ERROR, "Failed to talk to usb device: %s\n", libusb_strerror(ret));
		intf_data->devh = NULL;
		talloc_free(intf_data);
		if (auto_create_lines)
			e1_intf_destroy(intf);
		libusb_close(devh);
		return ret;
	}

	for (i = 0; i < cd->bNumInterfaces; i++) {
		/* Expect 2 altsettings with proper class/subclass/eps */
		if (cd->interface[i].num_altsetting != 2)
			continue;

		id = &cd->interface[i].altsetting[1];
		if (is_tracer) {
			if ((id->bInterfaceClass != 0xff) || (id->bInterfaceSubClass != 0xe1) || (id->bNumEndpoints < 1))
				continue;
		} else {
			if ((id->bInterfaceClass != 0xff) || (id->bInterfaceSubClass != 0xe1) || (id->bNumEndpoints < 3))
				continue;
		}

		line = e1_intf_find_line(intf, line_nr);
		if (line) {
			OSMO_ASSERT(auto_create_lines == false);
			if (line->drv_data) {
				LOGPLI(line, DE1D, LOGL_ERROR, "line busy but we are trying to open it again?\n");
				goto next_interface;
			}
		}

		/* Setup driver data and find endpoints */
		line_data = talloc_zero(e1d->ctx, struct e1_usb_line_data);

		INIT_LLIST_HEAD(&line_data->ctrl_inprogress);
		line_data->if_num = id->bInterfaceNumber;
		line_data->r_acc  = 0;
		line_data->r_sw   = 8192;

		for (j = 0; j < id->bNumEndpoints; j++) {
			if (id->endpoint[j].bmAttributes == 0x11) {
				line_data->ep_fb = id->endpoint[j].bEndpointAddress;
			} else if (id->endpoint[j].bmAttributes == 0x05) {
				if (id->endpoint[j].bEndpointAddress & 0x80)
					line_data->ep_in = id->endpoint[j].bEndpointAddress;
				else
					line_data->ep_out = id->endpoint[j].bEndpointAddress;

				if (!line_data->pkt_size)
					line_data->pkt_size = id->endpoint[j].wMaxPacketSize;
				else if (line_data->pkt_size != id->endpoint[j].wMaxPacketSize)
					LOGP(DE1D, LOGL_ERROR, "Inconsistent max packet size %d vs %d\n",
						line_data->pkt_size, (int)id->endpoint[j].wMaxPacketSize);
			} else if (id->endpoint[j].bmAttributes == 0x03) {
				line_data->ep_int = id->endpoint[j].bEndpointAddress;
			} else {
				LOGP(DE1D, LOGL_ERROR, "Invalid EP %02x\n", id->endpoint[j].bEndpointAddress);
			}
		}

		if (is_tracer) {
			if (!line_data->ep_in || !line_data->pkt_size) {
				LOGP(DE1D, LOGL_ERROR, "Failed to use interface %d\n", id->bInterfaceNumber);
				goto next_interface;
			}
		} else {
			if (!line_data->ep_in || !line_data->ep_out || !line_data->ep_fb || !line_data->pkt_size) {
				LOGP(DE1D, LOGL_ERROR, "Failed to use interface %d\n", id->bInterfaceNumber);
				goto next_interface;
			}
		}

		if (!line) {
			if (!auto_create_lines) {
				LOGPIF(intf, DE1D, LOGL_ERROR, "No configuration for line %d "
					"iInterface=%d, skipping\n", line_nr, id->bInterfaceNumber);
				goto next_interface;
			}
			line = e1_line_new(intf, line_nr, line_data);
		} else {
			OSMO_ASSERT(auto_create_lines == false);
			line->drv_data = line_data;
		}

		/* Get interface and set it up */
		ret = libusb_claim_interface(devh, id->bInterfaceNumber);
		if (ret) {
			LOGP(DE1D, LOGL_ERROR, "Failed to claim interface %d:%s\n", id->bInterfaceNumber,
			     libusb_strerror(ret));
			goto next_interface;
		}

		ret = libusb_set_interface_alt_setting(devh, id->bInterfaceNumber, 1);
		if (ret) {
			LOGP(DE1D, LOGL_ERROR, "Failed to set interface %d altsetting:%s\n", id->bInterfaceNumber,
			     libusb_strerror(ret));
			goto next_interface;
		}

		/* Create data flows and start the line */

		/* all supported devices have an IN endpoint */
		line_data->flow_in  = e1uf_create(line, e1_usb_xfer_in,  line_data->ep_in,  4, line_data->pkt_size, 4);
		e1uf_start(line_data->flow_in);

		/* e1-tracer has no OUT or FEEDBACK endpoint */
		if (!is_tracer) {
			line_data->flow_out = e1uf_create(line, e1_usb_xfer_out, line_data->ep_out, 4, line_data->pkt_size, 4);
			e1uf_start(line_data->flow_out);
			line_data->flow_fb  = e1uf_create(line, e1_usb_xfer_fb,  line_data->ep_fb,  2, 3, 1);
			e1uf_start(line_data->flow_fb);
		}

		if (line_data->ep_int)
			resubmit_irq(line);

		e1_line_active(line);

next_interface:
		line_nr++;
	}

	/* find the GPS-DO interface (if any) */
	for (i = 0; i < cd->bNumInterfaces; i++) {
		if (cd->interface[i].num_altsetting != 1)
			continue;

		id = &cd->interface[i].altsetting[0];
		if ((id->bInterfaceClass == 0xff) && (id->bInterfaceSubClass == 0xe1) &&
		    (id->bInterfaceProtocol == 0xd0)) {
			intf_data->gpsdo.if_num = id->bInterfaceNumber;
			_e1_usb_gpsdo_init(intf);
			break;
		}
	}

	return 0;
}

int
e1_usb_probe(struct e1_daemon *e1d)
{
	struct libusb_device **dev_list;
	ssize_t n_dev;
	int i, ret;

	if (!g_usb) {
		ret = osmo_libusb_init(&g_usb);
		if (ret) {
			LOGP(DE1D, LOGL_ERROR, "Failed to initialize libusb\n");
			return -EIO;
		}
	}

	n_dev = libusb_get_device_list(g_usb, &dev_list);
	if (n_dev < 0) {
		LOGP(DE1D, LOGL_ERROR, "Failed to list devices\n");
		return -EIO;
	}

	for (i = 0; i < n_dev; i++) {
		struct libusb_device_descriptor desc;

		ret = libusb_get_device_descriptor(dev_list[i], &desc);
		if (ret)
			continue;

		if (desc.idVendor != USB_VID)
			continue;

		switch (desc.idProduct) {
		case USB_PID:
			_e1_usb_open_device(e1d, dev_list[i], false);
			break;
		case USB_PID_TRACER:
			_e1_usb_open_device(e1d, dev_list[i], true);
			break;
		default:
			continue;
		}
	}

	libusb_free_device_list(dev_list, 1);

	return 0;
}
