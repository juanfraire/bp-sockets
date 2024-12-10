#ifndef GENL_BP_H
#define GENL_BP_H

#define GENL_BP_NAME "genl_bp"
#define GENL_BP_VERSION 1
#define GENL_BP_MC_GRP_NAME "genl_bp_mcgrp"

/* Attributes */
enum genl_bp_attrs
{
    GENL_BP_A_UNSPEC,
    GENL_BP_A_SOCKID,
    GENL_BP_A_EID,
    GENL_BP_A_PAYLOAD,
    GENL_BP_A_RETURN,
    __GENL_BP_A_MAX,
};

#define GENL_BP_A_MAX (__GENL_BP_A_MAX - 1)

/* Commands */
enum genl_bp_cmds
{
    GENL_BP_CMD_UNSPEC,
    GENL_BP_CMD_BUNDLE_NOTIFY,
    GENL_BP_CMD_RETURN,
    __GENL_BP_CMD_MAX,
};

#define GENL_BP_CMD_MAX (__GENL_BP_CMD_MAX - 1)

static const struct nla_policy nla_policy[GENL_BP_A_MAX + 1] = {
    [GENL_BP_A_UNSPEC] = {.type = NLA_UNSPEC},
    [GENL_BP_A_SOCKID] = {.type = NLA_U64},
    [GENL_BP_A_EID] = {.type = NLA_NUL_STRING},
    [GENL_BP_A_PAYLOAD] = {.type = NLA_NUL_STRING},
};

#endif