#pragma once

/***********************************************************************
 * OCTOI related data structures
 ***********************************************************************/

#include <osmocom/vty/command.h>

#include <osmocom/octoi/octoi.h>

/* FIXME: migrate to libosmocore/vty/command.h */
enum octoi_vty_node {
	OCTOI_SRV_NODE = RESERVED1_NODE,
	OCTOI_ACCOUNT_NODE,
	OCTOI_CLNT_NODE,
	OCTOI_CLNT_ACCOUNT_NODE,
};


extern struct osmo_fsm octoi_server_fsm;
extern struct osmo_fsm octoi_client_fsm;

void octoi_server_vty_init(void);
void octoi_client_vty_init(void);

struct octoi_account *octoi_account_find(struct octoi_server *srv, const char *user_id);
