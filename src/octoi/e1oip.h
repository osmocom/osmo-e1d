#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>

#include <osmocom/octoi/e1oip_proto.h>

#include "frame_fifo.h"
#include "frame_rifo.h"

#define iline_ctr_add(iline, idx, add) rate_ctr_add(rate_ctr_group_get_ctr((iline)->ctrs, idx), add)
#define iline_stat_set(iline, idx, add) \
	osmo_stat_item_set(osmo_stat_item_group_get_item((iline)->stats, idx), add)

enum e1oip_line_ctr {
	LINE_CTR_E1oIP_UNDERRUN,
	LINE_CTR_E1oIP_SUBSTITUTED,
	LINE_CTR_E1oIP_OVERFLOW,
	LINE_CTR_E1oIP_RX_OUT_OF_ORDER,
	LINE_CTR_E1oIP_RX_OUT_OF_WIN,
};

enum e1oip_line_stat {
	LINE_STAT_E1oIP_RTT,
	LINE_STAT_E1oIP_E1O_FIFO,
	LINE_STAT_E1oIP_E1T_FIFO,
};

struct octoi_peer;

struct e1oip_line {
	/* back-pointer */
	struct octoi_peer *peer;

	struct rate_ctr_group *ctrs;
	struct osmo_stat_item_group *stats;

	/* configuration data */
	struct {
		uint8_t batching_factor;
		uint32_t prefill_frame_count;
	} cfg;

	/* E1 originated side (E1->IP) */
	struct {
		struct frame_fifo fifo;
		uint8_t last_frame[BYTES_PER_FRAME];	/* last frame on the E1 side */
		uint16_t next_seq;
	} e1o;

	/* E1 terminated side (E1<-IP) */
	struct {
		struct frame_rifo rifo;
		uint8_t last_frame[BYTES_PER_FRAME];	/* last frame on the E1 side */
		uint32_t next_fn32;			/* next expected frame number */
		bool primed_rx_tdm;			/* Was RX RIFO primed */
	} e1t;

	/* TODO: statistics (RTT, frame loss, std deviation, alarms */
};

/* get the rate of the given counter during the last second */
static inline uint64_t iline_ctr_get_rate_1s(struct e1oip_line *iline, unsigned int idx)
{
	const struct rate_ctr *ctr = rate_ctr_group_get_ctr(iline->ctrs, idx);
	return ctr->intv[RATE_CTR_INTV_SEC].rate;
}

struct e1oip_line *e1oip_line_alloc(struct octoi_peer *peer);
void e1oip_line_set_name(struct e1oip_line *line, const char *name);
void e1oip_line_reset(struct e1oip_line *iline);
void e1oip_line_destroy(struct e1oip_line *iline);

int e1oip_rcvmsg_tdm_data(struct e1oip_line *iline, struct msgb *msg);
