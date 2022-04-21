#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <sys/socket.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

/* Server side:
 *  - one socket, bound to configured port but not connected
 *  - multiple peers
 *
 * Client side:
 *  - one socket, [optionally locally bound] + connected to configured remote IP+port
 *  - single peer
 */

#define LOGPEER(peer, lvl, fmt, args ...) \
	LOGP(DLINP, lvl, "%s: " fmt, (peer)->name, ## args)

struct e1oip_line;
struct octoi_peer;

struct octoi_sock {
	struct llist_head list;		/* member in global list */
	struct osmo_fd ofd;		/* file descriptor */
	struct llist_head peers;	/* list of peers */
	void *priv;

	int (*rx_cb)(struct octoi_peer *peer, struct msgb *msg);

	struct {
		bool server_mode;
		struct osmo_sockaddr_str local;	/* local address */
	} cfg;
};

struct octoi_peer {
	struct llist_head list;		/* member in octoi_sock.peers */
	struct octoi_sock *sock;	/* back-pointer to sock */
	struct sockaddr_storage remote;	/* remote socket address */
	time_t last_rx_tdm;		/* last time we received TDM from peer */
	struct e1oip_line *iline;
	bool tdm_permitted;		/* TDM messages are permitted (now) */
	char *name;			/* human-readable name (just for logging) */
	void *priv;			/* private data, e.g. fsm instance */

	struct {
		struct osmo_sockaddr_str remote; /* remote address */
	} cfg;
};

struct octoi_sock *octoi_sock_create_server(void *ctx, void *priv,
					    const struct osmo_sockaddr_str *local);

struct octoi_sock *octoi_sock_create_client(void *ctx, void *priv,
					    const struct osmo_sockaddr_str *local,
					    const struct osmo_sockaddr_str *remote);

void octoi_sock_destroy(struct octoi_sock *sock);

struct octoi_peer *octoi_sock_client_get_peer(struct octoi_sock *sock);

int octoi_sock_set_dscp(struct octoi_sock *sock, uint8_t dscp);
int octoi_sock_set_priority(struct octoi_sock *sock, uint8_t priority);

void octoi_peer_destroy(struct octoi_peer *peer);

int octoi_tx(struct octoi_peer *peer, uint8_t msg_type, uint8_t flags,
	     const void *data, size_t len);

int octoi_tx_echo_req(struct octoi_peer *peer, uint16_t seq_nr, const uint8_t *data, size_t data_len);

int octoi_tx_echo_resp(struct octoi_peer *peer, uint16_t seq_nr, const uint8_t *data, size_t data_len);

int octoi_tx_service_req(struct octoi_peer *peer, uint32_t service, const char *subscr_id,
			 const char *software_id, const char *software_version,
			 uint32_t capability_flags);

int octoi_tx_redir_cmd(struct octoi_peer *peer, const char *server_ip, uint16_t server_port);

int octoi_tx_auth_req(struct octoi_peer *peer, uint8_t rand_len, const uint8_t *rand,
		      uint8_t autn_len, const uint8_t *autn);

int octoi_tx_auth_resp(struct octoi_peer *peer, uint8_t res_len, const uint8_t *res,
		      uint8_t auts_len, const uint8_t *auts);

int octoi_tx_service_ack(struct octoi_peer *peer, uint32_t assigned_service,
			 const char *server_id, const char *software_id,
			 const char *software_version, uint32_t capability_flags);

int octoi_tx_service_rej(struct octoi_peer *peer, uint32_t rejected_service, const char *message);

int octoi_tx_error_ind(struct octoi_peer *peer, uint32_t cause, const char *message,
		       const uint8_t *orig, size_t orig_len);
