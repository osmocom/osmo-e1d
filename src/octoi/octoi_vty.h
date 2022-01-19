#pragma once

#include <osmocom/vty/command.h>

#include "octoi.h"

extern struct cmd_element cfg_account_mode_cmd;
extern struct cmd_element cfg_account_ice1_serno_cmd;
extern struct cmd_element cfg_account_ice1_line_cmd;

struct octoi_account *octoi_client_account_create(struct octoi_client *clnt, const char *user_id);

void octoi_vty_write_one_account(struct vty *vty, const struct octoi_account *acc);

void vty_show_octoi_sock(struct vty *vty, struct octoi_sock *sock);
