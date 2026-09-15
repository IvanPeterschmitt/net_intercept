#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/net_namespace.h>

static struct nf_hook_ops nfho;

static const char *get_proto_name (u8 proto) {
	switch (proto) {
		case IPPROTO_ICMP: return "ICMP";
		case IPPROTO_TCP: return "TCP";
		case IPPROTO_UDP: return "UDP";
		default: return "OTHER";
	}
}

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *iph;
	
	if (!skb) 
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph)
		return NF_ACCEPT;

	printk(KERN_INFO "[NET_INTERCEPT] Proto: %s (%u) | Packet: %pI4 -> %pI4\n", get_proto_name(iph->protocol), iph->protocol, &iph->saddr, &iph->daddr);
	
	return NF_ACCEPT;
}


static int __init intercept_init(void) {
	int ret;

	nfho.hook = hook_func;
	nfho.pf = NFPROTO_IPV4;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = NF_IP_PRI_FIRST;

	ret = nf_register_net_hook(&init_net, &nfho);
	if (ret) {
		printk(KERN_ERR "[NET_INTERCEPT] Netfilter hook registration Failure (code %d)\n", ret);
		return ret;
	}

	printk(KERN_INFO "[NET_INTERCEPT] Module charged and hook successfully activated !\n");
	return 0;
}

static void __exit intercept_exit(void) {
	nf_unregister_net_hook(&init_net, &nfho);
	printk(KERN_INFO "[NET_INTERCEPT] Hook withdrawn and module properly discharged\n");
}

module_init(intercept_init);
module_exit(intercept_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan");
MODULE_DESCRIPTION("Netfilter Interception");
