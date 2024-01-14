/*
 * mux_demux.c
 *
 * (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
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
#include <sys/types.h>
#include <sys/socket.h>

#include <talloc.h>

#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/e1d/proto.h>
#include <osmocom/e1d/proto_srv.h>

#include "e1d.h"
#include "log.h"

// ---------------------------------------------------------------------------
// data transfer
// ---------------------------------------------------------------------------

static int
_e1_tx_raw(struct e1_ts *ts, uint8_t *buf, int len)
{
		int l;

		l = read(ts->fd, buf, len);
		/* FIXME: handle underflow */

		/* If we're not started yet, we 'fake' data until the other side
		 * send something */
		if (l < 0 && errno == EAGAIN && !ts->raw.tx_started)
			return len;

		ts->raw.tx_started = true;

		return l;
}

static int
_e1_tx_hdlcfs(struct e1_ts *ts, uint8_t *buf, int len)
{
	int rv, oo, cl;

	oo = 0;

	while (oo < len) {
		/* Pending message ? */
		if (!ts->hdlc.tx_len) {
			rv = recv(ts->fd, ts->hdlc.tx_buf, sizeof(ts->hdlc.tx_buf), MSG_TRUNC);
			if (rv > 0) {
				if (rv > (int)sizeof(ts->hdlc.tx_buf)) {
					LOGPTS(ts, DXFR, LOGL_ERROR, "Truncated message: Client tried to "
						"send %d bytes but our buffer is limited to %zu\n",
						rv, sizeof(ts->hdlc.tx_buf));
					rv = sizeof(ts->hdlc.tx_buf);
				}
				LOGPTS(ts, DXFR, LOGL_DEBUG, "TX Message: %d [ %s]\n",
					rv, osmo_hexdump(ts->hdlc.tx_buf, rv));
				ts->hdlc.tx_len = rv;
				ts->hdlc.tx_ofs = 0;
			} else if ((rv < 0 && errno != EAGAIN) || rv == 0)
				return rv;
		}

		/* */
		rv = osmo_isdnhdlc_encode(&ts->hdlc.tx,
			&ts->hdlc.tx_buf[ts->hdlc.tx_ofs], ts->hdlc.tx_len - ts->hdlc.tx_ofs, &cl,
			&buf[oo], len - oo
		);

		if (rv < 0)
			LOGPTS(ts, DXFR, LOGL_ERROR, "ERR TX: %d\n", rv);

		if (ts->hdlc.tx_ofs < ts->hdlc.tx_len) {
			LOGPTS(ts, DXFR, LOGL_DEBUG, "TX chunk %d/%d %d [ %s]\n",
				ts->hdlc.tx_ofs, ts->hdlc.tx_len, cl, osmo_hexdump(&buf[ts->hdlc.tx_ofs], rv));
		}

		if (rv > 0)
			oo += rv;

		ts->hdlc.tx_ofs += cl;
		if (ts->hdlc.tx_ofs >= ts->hdlc.tx_len) {
			ts->hdlc.tx_len = 0;
			ts->hdlc.tx_ofs = 0;
		}
	}

	return len;
}

/* read from a timeslot-FD (direction application -> hardware) */
static int
_e1_ts_read(struct e1_ts *ts, uint8_t *buf, size_t len)
{
	int l;

	switch (ts->mode) {
	case E1_TS_MODE_RAW:
		l = _e1_tx_raw(ts, buf, len);
		break;
	case E1_TS_MODE_HDLCFCS:
		l = _e1_tx_hdlcfs(ts, buf, len);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}

	if ((l < 0 && errno != EAGAIN) || l == 0) {
		LOGPTS(ts, DE1D, LOGL_ERROR, "dead socket during read: %s\n",
			strerror(errno));
		e1_ts_stop(ts);
	} else if (l < (int)len) {
		LOGPTS(ts, DE1D, LOGL_NOTICE, "TS read underflow: We had %zu bytes to read, "
			"but socket returned only %d\n", len, l);
	}

	return l;
}

static void
_e1_line_mux_out_channelized(struct e1_line *line, uint8_t *buf, int fts)
{
	OSMO_ASSERT(line->mode == E1_LINE_MODE_CHANNELIZED);

	/* Scan timeslots */
	for (int tsn = 1; tsn < 32; tsn++) {
		struct e1_ts *ts = &line->ts[tsn];
		uint8_t buf_ts[fts];
		int l;

		if (ts->mode == E1_TS_MODE_OFF)
			continue;

		l = _e1_ts_read(ts, buf_ts, sizeof(buf_ts));
		if (l <= 0)
			continue;

		for (int i = 0; i < l; i++)
			buf[tsn+(i*32)] = buf_ts[i];
	}
}

static void
_e1_line_mux_out_superchan(struct e1_line *line, uint8_t *buf, int fts)
{
	struct e1_ts *ts = &line->superchan;
	uint8_t sc_buf[31*fts];
	int l;

	OSMO_ASSERT(line->mode == E1_LINE_MODE_SUPERCHANNEL);

	if (ts->mode == E1_TS_MODE_OFF)
		return;

	/* first pull all we need out of the source */
	l = _e1_ts_read(ts, sc_buf, sizeof(sc_buf));
	if (l <= 0)
		return;

	/* then form E1 frames from it, sprinkling in some gaps for TS0 */
	for (int i = 0; i < fts; i++)
		memcpy(buf + i*32 + 1, sc_buf + i*31, 31);
}

/*! generate (multiplex) output data for the specified e1_line
 *  \param[in] line E1 line for which to genrate output data
 *  \param[in] buf caller-allocated output buffer for multiplexed data
 *  \param[in] fts number of E1 frames (32 bytes each) to generate
 *  \return number of bytes written to buf */
int
e1_line_mux_out(struct e1_line *line, uint8_t *buf, int fts)
{
	int tsz;

	/* Prepare */
	tsz = 32 * fts;
	memset(buf, 0xff, tsz);

	switch (line->mode) {
	case E1_LINE_MODE_CHANNELIZED:
		_e1_line_mux_out_channelized(line, buf, fts);
		break;
	case E1_LINE_MODE_SUPERCHANNEL:
		_e1_line_mux_out_superchan(line, buf, fts);
		break;
	case E1_LINE_MODE_E1OIP:
		e1oip_line_mux_out(line, buf, fts);
		break;
	default:
		OSMO_ASSERT(0);
	}

	line_ctr_add(line, LINE_CTR_FRAMES_MUXED_E1T, fts);

	return tsz;
}

/* append data to the per-timeslot buffer; flush to socket every time buffer is full */
static int
_e1_rx_raw(struct e1_ts *ts, const uint8_t *buf, unsigned int len)
{
	unsigned int appended = 0;
	int rv;

	OSMO_ASSERT(ts->mode == E1_TS_MODE_RAW);

	/* we don't keep a larger set of buffers but simply assume that whenever
	 * we received one full chunk/buffer size, we are able to push the data
	 * into the underlying unix domain socket.  Kernel socket buffering should
	 * be far sufficient in terms of buffering capacity of voice data (which
	 * is typically consumed reasonably low latency and hence buffer size) */

	while (appended < len) {
		unsigned int ts_buf_tailroom = ts->raw.rx_buf_size - ts->raw.rx_buf_used;
		unsigned int chunk_len;

		/* determine size of chunk we can write at this point */
		chunk_len = len - appended;
		if (chunk_len > ts_buf_tailroom)
			chunk_len = ts_buf_tailroom;

		/* actually copy the chunk */
		memcpy(ts->raw.rx_buf + ts->raw.rx_buf_used, buf + appended, chunk_len);
		ts->raw.rx_buf_used += chunk_len;
		appended += chunk_len;

		/* if ts_buf is full: flush + rewind */
		if (ts->raw.rx_buf_used >= ts->raw.rx_buf_size) {
			rv = write(ts->fd, ts->raw.rx_buf, ts->raw.rx_buf_size);
			if (rv < 0)
				return rv;
			/* FIXME: count overflows */
			ts->raw.rx_buf_used = 0;
		}
	}

	return appended;
}

static int
_e1_rx_hdlcfs(struct e1_ts *ts, const uint8_t *buf, int len)
{
	int rv, cl, oi;

	oi = 0;

	while (oi < len) {
		rv = osmo_isdnhdlc_decode(&ts->hdlc.rx,
			&buf[oi], len-oi, &cl,
			ts->hdlc.rx_buf, sizeof(ts->hdlc.rx_buf)
		);

		if (rv > 0) {
			int bytes_to_write = rv;
			LOGPTS(ts, DXFR, LOGL_DEBUG, "RX Message: %d [ %s]\n",
				rv, osmo_hexdump(ts->hdlc.rx_buf, rv));
			rv = write(ts->fd, ts->hdlc.rx_buf, bytes_to_write);
			if (rv <= 0)
				return rv;
		} else  if (rv < 0 && ts->id == 4) {
			LOGPTS(ts, DXFR, LOGL_ERROR, "ERR RX: %d %d %d [ %s]\n",
				rv, oi, cl, osmo_hexdump(buf, len));
		}

		oi += cl;
	}

	return len;
}

/* write data to a timeslot (hardware -> application direction) */
static int
_e1_ts_write(struct e1_ts *ts, const uint8_t *buf, size_t len)
{
	int rv;

	switch (ts->mode) {
	case E1_TS_MODE_RAW:
		rv = _e1_rx_raw(ts, buf, len);
		break;
	case E1_TS_MODE_HDLCFCS:
		rv = _e1_rx_hdlcfs(ts, buf, len);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}

	if ((rv < 0 && errno != EAGAIN) || rv == 0) {
		LOGPTS(ts, DE1D, LOGL_ERROR, "dead socket during write: %s\n",
			strerror(errno));
		e1_ts_stop(ts);
	} else if (rv < (int)len) {
		LOGPTS(ts, DE1D, LOGL_NOTICE, "TS write overflow: We had %zu bytes to send, "
			"but write returned only %d\n", len, rv);
	}

	return rv;
}

static int
_e1_line_demux_in_channelized(struct e1_line *line, const uint8_t *buf, int ftr)
{
	OSMO_ASSERT(line->mode == E1_LINE_MODE_CHANNELIZED);

	for (int tsn = 1; tsn < 32; tsn++) {
		struct e1_ts *ts = &line->ts[tsn];
		uint8_t buf_ts[ftr];

		if (ts->mode == E1_TS_MODE_OFF)
			continue;

		for (int i = 0; i < ftr; i++)
			buf_ts[i] = buf[tsn+(i*32)];

		_e1_ts_write(ts, buf_ts, ftr);
	}

	return 0;
}

static int
_e1_line_demux_in_superchan(struct e1_line *line, const uint8_t *buf, int ftr)
{
	struct e1_ts *ts = &line->superchan;
	uint8_t sc_buf[ftr*31];

	OSMO_ASSERT(line->mode == E1_LINE_MODE_SUPERCHANNEL);

	if (ts->mode == E1_TS_MODE_OFF)
		return 0;

	/* first gather input data from multiple frames*/
	for (int i = 0; i < ftr; i++)
		memcpy(sc_buf + (i*31), buf + (i*32) + 1, 31);

	/* then dispatch to appropriate action */
	_e1_ts_write(ts, sc_buf, ftr*31);

	return 0;
}

static void
_e1_line_demux_in_ts0(struct e1_line *line, const uint8_t *buf, int ftr, uint8_t frame_base)
{
	int i;

	for (i = 0; i < ftr; i++) {
		const uint8_t *frame = buf + i*32;
		uint8_t frame_nr = (frame_base + i) & 0xf;

		if (frame_nr % 2) {
			/* A bit is present in each odd frame */
			if (frame[0] & 0x20) {
				if (!(line->ts0.cur_errmask & E1L_TS0_RX_ALARM)) {
					line->ts0.cur_errmask |= E1L_TS0_RX_ALARM;
					line_ctr_add(line, LINE_CTR_RX_REMOTE_A, 1);
					osmo_e1dp_server_event(line->intf->e1d->srv, E1DP_EVT_RAI_ON,
							       line->intf->id, line->id, 0, NULL, 0);
				}
			} else {
				if ((line->ts0.cur_errmask & E1L_TS0_RX_ALARM)) {
					line->ts0.cur_errmask &= ~E1L_TS0_RX_ALARM;
					osmo_e1dp_server_event(line->intf->e1d->srv, E1DP_EVT_RAI_OFF,
							       line->intf->id, line->id, 0, NULL, 0);
				}
			}
			/* SA bits changed */
			if (line->ts0.rx_frame != (frame[0] | 0xe0)) {
				uint8_t sa_bits = ((frame[0] & 0x01) << 7) | /* Sa8 -> Bit 7 */
						  ((frame[0] & 0x02) << 5) | /* Sa7 -> Bit 6 */
						  ((frame[0] & 0x04) >> 2) | /* Sa6 -> Bit 0 */
						  ((frame[0] & 0x08) << 2) | /* Sa5 -> Bit 5 */
						  (frame[0] & 0x10); /* Sa4 -> Bit 4 */
				line->ts0.rx_frame = frame[0] | 0xe0;
				osmo_e1dp_server_event(line->intf->e1d->srv, E1DP_EVT_SABITS,
						       line->intf->id, line->id, 0, &sa_bits, 1);
			}
		}

		/* E bits are present in frame 13 + 15 */
		if (frame_nr == 13)
			line->ts0.e_bits = frame[0] & 0x80 ? 2 : 0;
		if (frame_nr == 15) {
			line->ts0.e_bits |= frame[0] & 0x80 ? 1 : 0;
			if (line->ts0.e_bits != 3) {
				line->ts0.cur_errmask |= E1L_TS0_RX_CRC4_ERR;
				line_ctr_add(line, LINE_CTR_RX_REMOTE_E, 1);
			}
		}
		/* CRC error in cur_errmask is being cleared once per second via line->ts0.timer */
	}
}

/*! de-multiplex E1 line data to the individual timeslots.
 *  \param[in] line E1 line on which we operate.
 *  \param[in] buf buffer containing multiplexed frame-aligned E1 data.
 *  \param[in] size size of 'buf' in octets; assumed to be multiple of E1 frame size (32).
 *  \param[in] frame_base frame number (in multiframe) of first frame in 'buf'. -1 to disable TS0.
 *  \returns 0 on success; negative on error */
int
e1_line_demux_in(struct e1_line *line, const uint8_t *buf, int size, int frame_base)
{
	int ftr;

	if (size <= 0) {
		LOGPLI(line, DXFR, LOGL_ERROR, "IN ERROR: %d\n", size);
		return -1;
	}

	line->watchdog.rx_bytes += size;

	ftr = size / 32;
	OSMO_ASSERT(size % 32 == 0);

	if (frame_base >= 0)
		_e1_line_demux_in_ts0(line, buf, ftr, frame_base);

	line_ctr_add(line, LINE_CTR_FRAMES_DEMUXED_E1O, ftr);

	switch (line->mode) {
	case E1_LINE_MODE_CHANNELIZED:
		return _e1_line_demux_in_channelized(line, buf, ftr);
	case E1_LINE_MODE_SUPERCHANNEL:
		return _e1_line_demux_in_superchan(line, buf, ftr);
	case E1_LINE_MODE_E1OIP:
		return e1oip_line_demux_in(line, buf, ftr);
	default:
		OSMO_ASSERT(0);
	}
}
