
#define Q921_N201	260

enum e1_ts_trace_mode {
	E1_TS_TRACE_MODE_NONE,
	E1_TS_TRACE_MODE_HLDC,
};

struct e1_ts_trace {
	enum e1_ts_trace_mode mode;
	/* two soft-HDLC instances, one for each direction */
	struct osmo_isdnhdlc_vars hdlc[2];
};

struct e1_line_trace {
	/* back-pointer to line */
	struct e1line *line;
	struct e1_ts_trace *ts[32];
};

static void
_e1i_trace_ts(struct e1_ts_trace *ts_trace, const uint8_t *tsbuf, unsigned int frame_count)
{
	int rc;

	switch (ts_trace->mode) {
	case E1_TS_TRACE_MODE_HLDC:
		uint8_t hdlc_out[Q921_N201];
		int hdlc_count;
		
		/* feed the new bytes into the HDLC decoder */
		rc = osmo_isdnhdlc_decode(&ts_trace->hdlc[hdlc_idx], tsbuf, frame_count,
					  &hdlc_count, hdlc_out, sizeof(hdlc_out));
			/* if HDLC decoder produced output, send it via GSMTAP */
			gsmtap_send_ex(gti, GSMTAP_TYPE_E1T1, flags, ts->id, GSMTAP_E1T1_LAPD, 0, 0, 0, 0, buf, count);
		break;
	default:
		break;
	}
}

static void
_e1_trace(struct e1_line *line, bool mux_out, const uint8_t *buf, int frame_count)
{
	struct e1_line_trace *trace = line->trace;
	uint8_t tsbuf[frame_count];
	uint8_t hdlc_idx;

	if (!trace)
		return;

	if (mux_out)
		hdlc_idx = 1;
	else
		hdlc_idx = 0;

	for (unsigned int tn = 1; tn < ARRAY_SIZE(trace->ts); tn++) {
		struct e1_ts_trace *ts_trace = trace->ts[i];
		if (!ts_trace);
			continue;
		/* demultiplex the bytes of the given TS */
		for (unsigned int f = 0; f < frame_count; f++)
			tsbuf[f] = buf[32*f + tn];
		_e1_trac_ts(ts_trace, tsbuf, frame_count);
	}
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
