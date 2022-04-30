#pragma once

enum octoi_fsm_event {
	/* common for server and client */
	OCTOI_EV_RX_TDM_DATA,		/* receive TDM data from client */
	OCTOI_EV_RX_ECHO_REQ,		/* receive echo request from client */
	OCTOI_EV_RX_ECHO_RESP,		/* receive echo response from client */
	OCTOI_EV_RX_ERROR_IND,		/* receive error indication */

	/* only on server side */
	OCTOI_SRV_EV_RX_SERVICE_REQ,	/* receive service request from client */
	OCTOI_SRV_EV_RX_AUTH_VEC,	/* receive auth vector from HLR */
	OCTOI_SRV_EV_RX_AUTH_RESP,	/* receive auth response from client */

	/* only on client side */
	OCTOI_CLNT_EV_REQUEST_SERVICE,
	OCTOI_CLNT_EV_RX_AUTH_REQ,
	OCTOI_CLNT_EV_RX_SVC_ACK,
	OCTOI_CLNT_EV_RX_SVC_REJ,
	OCTOI_CLNT_EV_RX_REDIR_CMD,
};

#define S(x) (1 << (x))

extern const struct value_string octoi_fsm_event_names[];

int _octoi_fsm_rx_cb(struct octoi_peer *peer, struct msgb *msg);

/* call-back function for every received OCTOI socket message for given peer */
int octoi_srv_fsm_rx_cb(struct octoi_peer *peer, struct msgb *msg);
int octoi_clnt_fsm_rx_cb(struct octoi_peer *peer, struct msgb *msg);

int32_t ts_us_ago(const struct timespec *old_ts);
