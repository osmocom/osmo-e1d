#pragma once

#include <stdint.h>
#include <osmocom/core/prbs.h>
#include <osmocom/core/select.h>

#define MAX_NR_TS	31
#define PRBS_LEN	2048

/* prbs.c */

struct timeslot_state;
struct prbs_precomp {
	uint8_t bytes[PRBS_LEN/8];
};

void prbs_for_ts_nr(struct osmo_prbs *prbs, uint8_t ts_nr);

void prbs_precomp(struct prbs_precomp *out, const struct osmo_prbs *prbs);
void ts_init_prbs_tx(struct timeslot_state *ts, unsigned int prbs_offs_tx);
void ts_init_prbs_rx(struct timeslot_state *ts, unsigned int prbs_offs_rx);

/* utils.c */
uint8_t bits_set_in_byte(uint8_t byte);
void cfg_dahdi_buffer(int fd);
void set_realtime(int rt_prio);


struct timeslot_state_tx {
	struct osmo_prbs prbs;			/* PRBS definition */
	struct prbs_precomp prbs_pc;		/* pre-computed PRBS bytes */
	unsigned int prbs_pc_idx;		/* next to-be-transmitted byte offset in prbs_pc */
};

struct timeslot_state_rx {
	struct osmo_prbs prbs;			/* PRBS definition */
	struct prbs_precomp prbs_pc[8];		/* bit-shifted pre-computed PRBS sequences */
	struct {
		bool has_sync;			/* do we have a PRBS sync? */
		struct timespec ts_sync;	/* time at which sync was established */
		unsigned int prbs_pc_num;	/* index to prbs_pc[] array */
		unsigned int prbs_pc_offset;	/* offset of next byte into prbs_pc[pc_num].bytes[] */

		unsigned int num_bit_err;	/* bit errors since last sync */
		unsigned int num_sync_loss;	/* number of sync losses since start */
	} sync_state;
};


struct timeslot_state {
	struct osmo_fd ofd;
	struct timeslot_state_tx tx;
	struct timeslot_state_rx rx;
};

struct test_state {
	struct timeslot_state ts[MAX_NR_TS];
	unsigned int next_unused_ts;
};

/* rx.c */
void process_rx(struct timeslot_state_rx *tsr, unsigned int ts_nr, const uint8_t *data, unsigned int len);

/* tx.c */
void process_tx(struct timeslot_state *ts, int len);
