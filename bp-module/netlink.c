#include <net/genetlink.h>
#include "../genl_bp.h"
#include "netlink.h"

static struct genl_ops genl_ops[] = {
	{
		.cmd = GENL_BP_CMD_BUNDLE_NOTIFY,
		.flags = GENL_ADMIN_PERM,
		.policy = nla_policy,
		.doit = fail_doit,
		.dumpit = NULL,
	},
	{
		.cmd = GENL_BP_CMD_RETURN,
		.flags = GENL_ADMIN_PERM,
		.policy = nla_policy,
		.doit = recv_bundle_doit,
		.dumpit = NULL,
	},
};

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

int send_bundle_doit(unsigned long id, void *optval, int optlen, int port_id)
{
	struct sk_buff *skb;
	int ret;
	void *msg_head;
	int msg_size = nla_total_size(sizeof(unsigned long)) +
				   2 * nla_total_size(sizeof(int)) +
				   nla_total_size(optlen);

	skb = genlmsg_new(msg_size, GFP_KERNEL);
	printk(KERN_INFO "in netlink : %s", (char *)optval);
	if (skb == NULL)
	{
		printk(KERN_ALERT "Failed in genlmsg_new [setsockopt notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &genl_fam, 0, GENL_BP_CMD_BUNDLE_NOTIFY);
	if (msg_head == NULL)
	{
		printk(KERN_ALERT "Failed in genlmsg_put [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, GENL_BP_A_ID, sizeof(id), &id);
	if (ret != 0)
	{
		printk(KERN_ALERT "Failed in nla_put (id) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}

	ret = nla_put(skb, GENL_BP_A_OPTVAL, optlen, optval);
	if (ret != 0)
	{
		printk(KERN_ALERT "Failed in nla_put (optval) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	/*ret = genlmsg_multicast(&genl_fam, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [setsockopt notify] (%d)\n", ret);
	}*/
	ret = genlmsg_unicast(&init_net, skb, port_id);
	if (ret != 0)
	{
		printk(KERN_ALERT "Failed in gemlmsg_unicast [setsockopt notify]\n (%d)", ret);
	}
	return 0;
}

int recv_bundle_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	unsigned long id = 0;
	void *optval = NULL;

	printk(KERN_INFO "Trigger nl_receive\n");

	if (!info)
		return -EINVAL;

	// Parse attributes from the Netlink message
	na = info->attrs[GENL_BP_A_ID];
	if (na)
	{
		id = *(unsigned long *)nla_data(na);
		printk(KERN_INFO "Received ID: %lu\n", id);
	}
	else
	{
		printk(KERN_ALERT "Missing ID attribute.\n");
		return -EINVAL;
	}

	na = info->attrs[GENL_BP_A_OPTVAL];
	if (na)
	{
		optval = nla_data(na);
		printk(KERN_INFO "Received Optval: %s\n", (char *)optval);
	}
	else
	{
		printk(KERN_ALERT "Missing Optval attribute.\n");
		return -EINVAL;
	}

	// Perform further processing as needed...
	return 0;
}
