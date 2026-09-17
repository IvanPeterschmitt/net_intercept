#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/net_namespace.h>

#include "packet_parser.h"


static struct nf_hook_ops nfho;

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

	if (!skb) {
		pr_debug("[NET_INTERCEPT] Invalid skb\n");
		return NF_ACCEPT;
	}
	
	return parse_packet(skb);
}


static int __init intercept_init(void) {
	int ret;

	nfho.hook = hook_func;
	nfho.pf = NFPROTO_IPV4;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = NF_IP_PRI_FIRST;

	ret = nf_register_net_hook(&init_net, &nfho);
	if (ret) {
		pr_err("[NET_INTERCEPT] Netfilter hook registration Failure (code %d)\n", ret);
		return ret;
	}

	pr_info("[NET_INTERCEPT] Module charged and hook successfully activated !\n");
	return 0;
}

static void __exit intercept_exit(void) {
	nf_unregister_net_hook(&init_net, &nfho);
	pr_info("[NET_INTERCEPT] Hook withdrawn and module properly discharged\n");
}

module_init(intercept_init);
module_exit(intercept_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan");
MODULE_DESCRIPTION("Netfilter Interception");
