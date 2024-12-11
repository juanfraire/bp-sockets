#ifndef NETLINK_H
#define NETLINK_H

extern struct genl_family genl_fam;

int fail_doit(struct sk_buff *skb, struct genl_info *info);
int send_bundle_doit(unsigned long id, char *payload, int payload_size, char *eid, int eid_size, int port_id);
int recv_bundle_doit(unsigned long sockid, char *payload, int payload_size, char *eid, int eid_size, int port_id);

#endif