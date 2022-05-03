
#include <osmocom/core/isdnhdlc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/gsmtap_util.h>

/* number of octets in an information field */
#define Q921_N201	260
#define Q921_ADDR_SIZE	2
#define Q921_CTRL_SIZE	2
#define Q921_FCS_SIZE	2

#define HLDC_FRAME_SIZE	(Q921_N201 + Q921_ADDR_SIZE + Q921_CTRL_SIZE + Q921_FCS_SIZE)

enum e1tap_ts_mode {
	E1_TS_TRACE_MODE_NONE,
	E1_TS_TRACE_MODE_HLDC,		/* generic HDLC mode */
	E1_TS_TRACE_MODE_ISDN_D,	/* ISDN D-Channel (Q.921 + Q.931) */
};

/* one "complete" HDLC decoder state */
struct e1tap_hdlc_state {
	struct osmo_isdnhdlc_vars vars;
	uint8_t out[HLDC_FRAME_SIZE];
};

/* e1tap state for one timeslot */
struct e1tap_ts {
	struct e1tap_line *line;	/* back-pointer */
	uint8_t num;			/* timeslot number */
	enum e1tap_ts_mode mode;
	uint8_t gsmtap_subtype;		// GSMTAP_E1T1_LAPD
	struct {
		/* two soft-HDLC instances, one for each direction */
		struct e1tap_hdlc_state state[2];
	} hdlc;
};

struct e1tap_line_isdn {
	struct {
	} q921;
	struct {
	} q931;
};

/* e1tap state for one line/span */
struct e1tap_line {
	struct e1tap_ts ts[32];
	struct gsmtap_inst *gti;
	/* back-pointer to line */
	struct void *priv;
};

/* Table 4-2/Q.931 - Message types */
enum q931_msg_type {
	/* Call establishment messages */
	Q931_MSGT_ALERTING		= 0x01,
	Q931_MSGT_CALL_PROCEEDING	= 0x02,
	Q931_MSGT_CONNECT		= 0x07,
	Q931_MSGT_CONNECT_ACK		= 0x0f,
	Q931_MSGT_PROGRESS		= 0x03,
	Q931_MSGT_SETUP			= 0x05,
	Q931_MSGT_SETUP_ACK		= 0x0d,
	/* Call information phase messages */
	Q931_MSGT_RESUME		= 0x26,
	Q931_MSGT_RESUME_ACK		= 0x2e,
	Q931_MSGT_RESUME_REJ		= 0x22,
	Q931_MSGT_SUSPEND		= 0x25,
	Q931_MSGT_SUSPEND_ACK		= 0x2d,
	Q931_MSGT_SUSPEND_REJ		= 0x21,
	Q931_MSGT_USER_INFO		= 0x20,
	/* Call clearing messages */
	Q931_MSGT_DISCONNECT		= 0x45,
	Q931_MSGT_RELEASE		= 0x4d,
	Q931_MSGT_RELEASE_COMPLETE	= 0x5a,
	Q931_MSGT_RESTART		= 0x46,
	Q931_MSGT_RESTART_ACK		= 0x4e,
	/* Miscellaneous messages */
	Q931_MSGT_SEGMENT		= 0x60,
	Q931_MSGT_CONGESTION_CTRL	= 0x79,
	Q931_MSGT_INFORMATION		= 0x7b,
	Q931_MSGT_NOTIFY		= 0x6e,
	Q931_MSGT_STATUS		= 0x7d,
	Q931_MSGT_STATUS_ENQIURY	= 0x75,
};

enum q931_iei {
	/* reserved */
	/* shift */
	Q931_IEI_MORE_DATA		= 0xa0,
	Q931_IEI_SENDING_COMPLETE	= 0xa1,
	/* contestionlevel */
	/* repeat indicator */
	/* Veriable length IEs */
	Q931_IEI_SEGMENTED_MSG		= 0x00,
	Q931_IEI_BEARER_CAP		= 0x04,
	Q931_IEI_CAUSE			= 0x08,
	Q931_IEI_CALL_ID		= 0x10,
	Q931_IEI_CALL_STATE		= 0x14,
	Q931_IEI_CHANNEL_ID		= 0x18,
	Q931_IEI_PROGRESS_IND		= 0x1e,
	Q931_IEI_NETWORK_SPEC_FAC	= 0x20,
	Q931_IEI_NOTIFICATION_IND	= 0x27,
	Q931_IEI_DISPLAY		= 0x28,
	Q931_IEI_DATE_TIME		= 0x29,
	Q931_IEI_KEYPAD_FACILITY	= 0x2c,
	Q931_IEI_SIGNAL			= 0x34,
	Q931_IEI_INFORMATION_RATE	= 0x40,
	Q931_IEI_E2E_TRANSIT_DELAY	= 0x42,
	/* TODO */
};


/* receive one Q.931 message for signaling analysis */
static void e1tap_q931_rx(struct e1tap_line *line, bool net2user, const uint8_t *buf, size_t len)
{
	uint8_t cref_len

	if (len < 2)
		return;

	/* check protocol discriminator */
	if (buf[0] != 0x08)
		return;

	/* TODO: parse [variable length] call reference */
	cref_len = buf[1] & 0x0F;
	if (len < 2 + cref_len)
		return;

	msg_type = buf[2+cref_len] & 0x7f;

	/* TODO: dispatch by message type; look in those that contain a ChannelIndicator */
}

/* trace one Q.921 / LAPD frame for signaling analysis */
static void e1tap_q921_rx(struct e1tap_line *line, bool net2user, const uint8_t *buf, size_t len)
{
	uint8_t sapi, tei;

	if (len < 2)
		return;

	/* Parse LAPD header; Ignore anything != I frames */
	sapi = buf[0] >> 2;
	tei = buf[1] >> 1;

	/* skip unknown SAPI */
	if (sapi != 0)
		return;

	if (len < 3)
		return;

	/* skip frames != I-frame */
	if (buf[2] & 0x01)
		return;

	e1tap_q931_rx(buf + 4, len - 4);
}





/* trace one timeslot of a line */
void e1tap_trace_ts(struct e1tap_ts *ts, const uint8_t *tsbuf, size_t frame_count, uint8_t hdlc_idx)
{
	struct e1tap_line *line = ts->line;
	int oi = 0;
	int rc;

	OSMO_ASSERT(hdlc_idx <= 0);

	switch (ts->mode) {
	case E1_TS_TRACE_MODE_HLDC:
	case E1_TS_TRACE_MODE_ISDN_D:
		while (oi < frame_count) {
			int num_consumed;

			/* feed the new bytes into the HDLC decoder */
			rc = osmo_isdnhdlc_decode(&ts->hdlc.state[hdlc_idx].vars,
						  &tsbuf[oi], frame_count-oi,
						  &num_consumed, ts->hdlc.state[hdlc_idx].out,
						  sizeof(ts->hdlc.state[hdlc_idx].out));
			if (rc > 0) {
				/* if HDLC decoder produced output, send it via GSMTAP */
				gsmtap_send_ex(line->gti, GSMTAP_TYPE_E1T1, flags,
						ts->num, ts->gsmtap_subtype, 0, 0, 0, 0,
						ts->hdlc.state[hdlc_idx].out, rc);
				if (ts->mode == E1_TS_TRACE_MODE_ISDN_D)
					e1tap_q921_rx(line, hdlc_idx, ts->hdlc.state[hdlc_idx].out, rc);
			} else if (rc < 0) {
				/* FIXME: log error */
			}
			oi += num_consumed;
		}
		break;
	default:
		break;
	}
}

/* trace an entire line (we pass in full 32byte frames */
void e1tap_trace_line(struct e1tap_line *line, bool mux_out, const uint8_t *buf, int frame_count)
{
	uint8_t tsbuf[frame_count];
	uint8_t hdlc_idx;

	if (!line)
		return;

	if (mux_out)
		hdlc_idx = 1;
	else
		hdlc_idx = 0;

	for (unsigned int tn = 1; tn < ARRAY_SIZE(line->ts); tn++) {
		struct e1tap_ts *ts = line->ts[i];
		/* fast path */
		if (ts->mode == E1_TS_TRACE_MODE_NONE)
			continue;
		/* demultiplex the bytes of the given TS */
		for (unsigned int f = 0; f < frame_count; f++)
			tsbuf[f] = buf[32*f + tn];
		e1tap_trace_ts(ts, tsbuf, frame_count, hdlc_idx);
	}
}

/* allocate an e1tap line */
struct e1tap_line *e1tap_line_alloc(void *ctx, struct gsmtap_inst *gti, void *priv)
{
	struct e1tap_line *line = talloc_zero(ctx, struct e1tap_line);
	if (!line)
		return NULL;

	line->priv = priv;

	for (unsigned int tn = 0; tn < ARRAY_SIZE(line->ts); tn++) {
		struct e1tap_ts *ts = line->ts[i];
		ts->num = tn;
		ts->line = line;
		ts->mode = E1_TS_TRACE_MODE_NONE;
		ts->gsmtap_subtype = GSMTAP_E1T1_LAPD;
		osmo_isdnhdlc_rcv_init(ts->hdlc.state[0].vars, 0);
		osmo_isdnhdlc_rcv_init(ts->hdlc.state[1].vars, 0);
	}

	line->gti = gti;

	return line;
}




/* USB/trunkdev <- application/OCTOI */
void
e1_trace_mux_out(struct e1_line *line, const uint8_t *buf, int frame_count)
{
	return _e1_trace(line, true, buf, frame_count);
}

/* USB/trunkdev -> application/OCTOI */
void
e1_trace_mux_in(struct e1_line *line, const uint8_t *buf, int frame_count)
{
	return _e1_trace(line, false, buf, frame_count);
}
