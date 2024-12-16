#include <net/genetlink.h>
#include "../common.h"
#include "bp_nl_gen.h"

static struct genl_ops genl_ops[] = {
	// {
	// 	.cmd = GENL_BP_CMD_FORWARD_BUNDLE,
	// 	.flags = GENL_ADMIN_PERM,
	// 	.policy = nla_policy,
	// 	.doit = fail_doit,
	// 	.dumpit = NULL,
	// },
	{
		.cmd = GENL_BP_CMD_REPLY_BUNDLE,
		.flags = GENL_ADMIN_PERM,
		.policy = nla_policy,
		.doit = recv_reply_bundle_doit,
		.dumpit = NULL,
	}};

/* Multicast groups for our family */
static const struct genl_multicast_group genl_mcgrps[] = {
	{.name = GENL_BP_MC_GRP_NAME},
};

/* Generic Netlink family */
struct genl_family genl_fam = {
	.module = THIS_MODULE,
	.name = GENL_BP_NAME,
	.version = GENL_BP_VERSION,
	.maxattr = GENL_BP_A_MAX,
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
	.mcgrps = genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(genl_mcgrps),
	// .hdrsize = 0,
};

int fail_doit(struct sk_buff *skb, struct genl_info *info)
{
	pr_alert("Kernel receieved an SSA netlink notification. This should never happen.\n");
	return -1;
}

int send_bundle_doit(u64 sockid, char *payload, int payload_size, char *eid, int eid_size, int port_id)
{
	int ret = 0;
	void *hdr;
	struct sk_buff *msg;
	int msg_size;

	/* Allocate a new buffer for the reply */
	msg_size = nla_total_size(sizeof(u64)) +
			   nla_total_size(eid_size) +
			   nla_total_size(payload_size);
	msg = genlmsg_new(msg_size + GENL_HDRLEN, GFP_KERNEL);
	if (!msg)
	{
		pr_err("failed to allocate message buffer\n");
		return -ENOMEM;
	}

	/* Put the Generic Netlink header */
	hdr = genlmsg_put(msg, 0, 0, &genl_fam, 0, GENL_BP_CMD_FORWARD_BUNDLE);
	if (!hdr)
	{
		pr_err("failed to create genetlink header\n");
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* And the message */
	if ((ret = nla_put_string(msg, GENL_BP_A_PAYLOAD, payload)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}
	if ((ret = nla_put_string(msg, GENL_BP_A_EID, eid)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}
	if ((ret = nla_put_u64_64bit(msg, GENL_BP_A_SOCKID, sockid, 0)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}

	/* Finalize the message and send it */
	genlmsg_end(msg, hdr);
	ret = genlmsg_unicast(&init_net, msg, port_id);
	if (ret != 0)
	{
		pr_alert("Failed in gemlmsg_unicast [setsockopt notify]\n (%d)", ret);
	}

out:
	return 0;
}

int notify_deamon_doit(u32 agent_id, int port_id)
{
	int ret = 0;
	void *hdr;
	struct sk_buff *msg;
	int msg_size;

	/* Allocate a new buffer for the reply */
	msg_size = nla_total_size(sizeof(u32));
	msg = genlmsg_new(msg_size + GENL_HDRLEN, GFP_KERNEL);
	if (!msg)
	{
		pr_err("failed to allocate message buffer\n");
		return -ENOMEM;
	}

	/* Put the Generic Netlink header */
	hdr = genlmsg_put(msg, 0, 0, &genl_fam, 0, GENL_BP_CMD_REQUEST_BUNDLE);
	if (!hdr)
	{
		pr_err("failed to create genetlink header\n");
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	/* And the message */
	if ((ret = nla_put_u32(msg, GENL_BP_A_AGENT_ID, agent_id)))
	{
		pr_err("failed to create message string\n");
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		goto out;
	}

	/* Finalize the message and send it */
	genlmsg_end(msg, hdr);
	ret = genlmsg_unicast(&init_net, msg, port_id);
	if (ret != 0)
	{
		pr_alert("Failed in gemlmsg_unicast [setsockopt notify]\n (%d)", ret);
	}

out:
	return 0;
}

int recv_reply_bundle_doit(struct sk_buff *skb, struct genl_info *info)
{
	/* Check if the attribute is present and print it */
	if (info->attrs[GENL_BP_A_PAYLOAD])
	{
		char *str = nla_data(info->attrs[GENL_BP_A_PAYLOAD]);
		pr_info("message received: %s\n", str);
	}
	else
	{
		pr_info("empty message received\n");
	}

	return 0;
}
