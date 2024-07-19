#include <net/netlink.h>
#include <net/genetlink.h>


#include "netlink.h"

int nl_fail(struct sk_buff* skb, struct genl_info* info);

static const struct nla_policy ssa_nl_policy[SSA_NL_A_MAX + 1] = {
        [SSA_NL_A_UNSPEC] = { .type = NLA_UNSPEC },
	[SSA_NL_A_ID] = { .type = NLA_UNSPEC },
	[SSA_NL_A_OPTVAL] = { .type = NLA_UNSPEC },

};

static struct genl_ops ssa_nl_ops[] = {
        {
                .cmd = SSA_NL_C_BUNDLE_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
};


static const struct genl_multicast_group ssa_nl_grps[] = {
        [SSA_NL_NOTIFY] = { .name = "notify", },
};

static struct genl_family ssa_nl_family = {
        .module = THIS_MODULE,
        .ops = ssa_nl_ops,
        .n_ops = ARRAY_SIZE(ssa_nl_ops),
        .mcgrps = ssa_nl_grps,
        .n_mcgrps = ARRAY_SIZE(ssa_nl_grps),
        .hdrsize = 0,
        .name = "SSA",
        .version = 1,
        .maxattr = SSA_NL_A_MAX,
};

int nl_fail(struct sk_buff* skb, struct genl_info* info) {
        printk(KERN_ALERT "Kernel receieved an SSA netlink notification. This should never happen.\n");
        return -1;
}

int register_netlink() {
	return genl_register_family(&ssa_nl_family);
}

void unregister_netlink() {
	genl_unregister_family(&ssa_nl_family);
	return;
}

int send_bundle_notification(unsigned long id, void* optval, int optlen, int port_id) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;
	int msg_size = nla_total_size(sizeof(unsigned long)) +
			2 * nla_total_size(sizeof(int)) +
			nla_total_size(optlen);

	skb = genlmsg_new(msg_size, GFP_KERNEL);
	printk(KERN_INFO "in netlink : %s", (char *) optval);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [setsockopt notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_BUNDLE_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}

	ret = nla_put(skb, SSA_NL_A_OPTVAL, optlen, optval);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (optval) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	/*ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [setsockopt notify] (%d)\n", ret);
	}*/
	ret = genlmsg_unicast(&init_net, skb, port_id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_unicast [setsockopt notify]\n (%d)", ret);
	}
	return 0;
}
