#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/vty/vty.h>

struct octoi_peer;

enum octoi_account_mode {
	ACCOUNT_MODE_NONE,
	ACCOUNT_MODE_ICE1USB,
	ACCOUNT_MODE_REDIRECT,
	ACCOUNT_MODE_DAHDI_TRUNKDEV,
};

extern const struct value_string octoi_account_mode_name[];

/* a single user account connecting via OCTOI protocol */
struct octoi_account {
	struct llist_head list;				/* member in octoi_server.cfg.accounts */
	char *user_id;					/* user ID (IMSI) */
	enum octoi_account_mode mode;
	uint8_t batching_factor;			/* E1 frames per UDP packet (Tx) */
	bool force_send_all_ts;				/* force transmission of all timeslots */
	uint32_t prefill_frame_count;			/* FIFO prefill/preseed count (Rx) */
	uint8_t buffer_reset_percent;			/* When to reset Rx RIFO in percent */
	union {
		struct {
			char *usb_serial;		/* USB serial string (ASCII) of icE1usb */
			uint8_t line_nr;		/* line nubmer inside icE1usb */
		} ice1usb;
		struct {
			struct osmo_sockaddr_str to;	/* remote IP/port to which to redirect */
		} redirect;
		struct {
			char *name;			/* DAHDI trunkdev name */
			uint8_t line_nr;		/* line number inside icE1usb */
		} dahdi_trunkdev;
	} u;
};

struct octoi_sock;

struct octoi_server {
	struct octoi_sock *sock;			/* OCTOI UDP server sock representation */
	struct {
		struct llist_head accounts;		/* list of octoi_account */
		struct osmo_sockaddr_str local;		/* local socket bind address/port */
		uint8_t dscp;				/* IP DSCP value */
		uint8_t priority;			/* Socket Priority value */
	} cfg;

};

struct octoi_client {
	struct llist_head list;				/* member in e1_daemon.octoi.clients */
	struct octoi_sock *sock;			/* OCTOI UDP server sock representation */
	struct {
		struct osmo_sockaddr_str remote;	/* remote socket address/port */
		struct osmo_sockaddr_str local;		/* local socket bind address/port */

		struct octoi_account *account;

		uint8_t dscp;				/* IP DSCP value */
		uint8_t priority;			/* Socket Priority value */
	} cfg;
};

/* call-backs from OCTOI library to application */
struct octoi_ops {
	/* server notifies the application that a new client connection has just been accepted */
	void * (*client_connected)(struct octoi_server *srv, struct octoi_peer *peer,
				   struct octoi_account *acc);
	/* OCTOI library notifies the application that a given peer has disconnected */
	void (*peer_disconnected)(struct octoi_peer *peer);
	/* OCTOI library notifies the application that a given client has been updated */
	void (*client_updated)(struct octoi_client *client);
};

struct octoi_daemon {
	void *priv;
	const struct octoi_ops *ops;
	struct octoi_server *server;
	struct llist_head clients;
};

extern struct octoi_daemon *g_octoi;

void octoi_init(void *ctx, void *priv, const struct octoi_ops *ops);

int octoi_vty_go_parent(struct vty *vty);

struct octoi_peer *octoi_client_get_peer(struct octoi_client *client);
void octoi_clnt_start_for_peer(struct octoi_peer *peer, struct octoi_account *acc);

void octoi_peer_e1o_in(struct octoi_peer *peer, const uint8_t *buf, int ftr);
void octoi_peer_e1t_out(struct octoi_peer *peer, uint8_t *buf, int fts);

