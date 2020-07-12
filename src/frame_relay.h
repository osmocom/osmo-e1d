#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/timer.h>

struct fr_network {
	struct llist_head links;

	unsigned int n391; 		/* full status polling counter */
	unsigned int n392;		/* error threshold */
	unsigned int n393;		/* monitored events count */
	struct osmo_tdef *T_defs;	/* T391, T392 */
};

struct fr_dlc;

/* Frame Relay Link */
struct fr_link {
	/* list in fr_network.links */
	struct llist_head list;
	struct fr_network *net;

	/* value of the last received send sequence number field in the
	 * link integrity verification information element */
	uint8_t last_rx_seq;

	/* value of the send sequence number field of the last link
	 * integrity verification information element sent */
	uint8_t last_tx_seq;

	struct osmo_timer_list t391;
	struct osmo_timer_list t392;
	unsigned int polling_count;
	unsigned int err_count;

	/* list of data link connections at this link */
	struct llist_head dlc_list;

	int (*unknown_dlc_rx_cb)(struct fr_dlc *dlc, struct msgb *msg);
};

/* Frame Relay Data Link Connection */
struct fr_dlc {
	/* entry in fr_link.dlc_list */
	struct llist_head list;
	struct fr_link *link;

	uint16_t dlci;

	/* is this DLC marked active for traffic? */
	bool active;
	/* was this DLC newly added? */
	bool new;
	/* is this DLC about to be destroyed */
	bool del;

	int (*rx_cb)(struct fr_dlc *dlc, struct msgb *msg);
};


/* allocate a frame relay network */
struct fr_network *fr_network_alloc(void *ctx);

/* allocate a frame relay link in a given network */
struct fr_link *fr_link_alloc(struct fr_network *net);

/* allocate a data link connectoin on a given framerelay link */
struct fr_dlc *fr_dlc_alloc(struct fr_link *link, uint16_t dlci);

int fr_rx(struct fr_link *link, struct msgb *msg);

extern int fr_tx(struct msgb *msg);
