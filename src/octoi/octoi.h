#pragma once

/***********************************************************************
 * OCTOI related data structures
 ***********************************************************************/

#include <osmocom/vty/command.h>

#include <osmocom/octoi/octoi.h>

extern struct osmo_fsm octoi_server_fsm;
extern struct osmo_fsm octoi_client_fsm;

void octoi_server_vty_init(void);
void octoi_client_vty_init(void);

struct octoi_account *octoi_account_find(struct octoi_server *srv, const char *user_id);
