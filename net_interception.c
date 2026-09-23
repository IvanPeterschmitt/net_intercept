#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/net_namespace.h>

#include "packet_parser.h"
#include "param_parser.h"
#include "packet_filter.h"


static char *mode = "";
module_param(mode, charp, 0644);
MODULE_PARM_DESC(mode, "Mode of operation: log(default), drop");

static char *target_ip_dest = "";
module_param(target_ip_dest, charp, 0644);
MODULE_PARM_DESC(target_ip_dest, "Target destination IP address range (ex: \"192.168.1.0/24\")");

static char *target_ip_src = "";
module_param(target_ip_src, charp, 0644);
MODULE_PARM_DESC(target_ip_src, "Target source IP address range (ex: \"192.168.1.0/24\")");

static char *target_proto = "";
module_param(target_proto, charp, 0644);
MODULE_PARM_DESC(target_proto, "Target protocol: all(default), icmp, tcp, udp");

static int target_port_src = -1;
module_param(target_port_src, int, 0644);
MODULE_PARM_DESC(target_port_src, "Target source port number (1-65535)");

static int target_port_dest = -1;
module_param(target_port_dest, int, 0644);
MODULE_PARM_DESC(target_port_dest, "Target destination port number (1-65535)");

static struct nf_hook_ops nfho;
static struct params params;

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct packet_data packet;
	int err;
	int action;
	char *sport = "";
	char *dport = "";

	if (!skb) {
		pr_debug("[NET_INTERCEPT] Invalid skb\n");
		return NF_ACCEPT;
	}

	err = parse_packet(skb, &packet);
	if (err) {
		pr_debug("[NET_INTERCEPT] Failed to parse packet\n");
		return NF_ACCEPT;
	}

	if (packet.protocol == IPPROTO_TCP || packet.protocol == IPPROTO_UDP) {
		sport = kasprintf(GFP_KERNEL, ":%u", ntohs(packet.src_port));
		dport = kasprintf(GFP_KERNEL, ":%u", ntohs(packet.dest_port));
	}

	action = filter_packet(&packet, &params);
	if (action == NF_DROP) {
		pr_info("[NET_INTERCEPT] Dropped packet: protocol=%u, %pI4%s -> %pI4%s\n",
			packet.protocol, &packet.src_ip, sport, &packet.dest_ip, dport);
		return NF_DROP;
	}
	if (action == NF_ACCEPT) {
		pr_info("[NET_INTERCEPT] Intercepted packet: protocol=%u, %pI4%s -> %pI4%s\n",
			packet.protocol, &packet.src_ip, sport, &packet.dest_ip, dport);
	}

	return NF_ACCEPT;
}


static int __init intercept_init(void) {
	int ret;

	ret = parse_params(&params, mode, target_ip_src, target_ip_dest, target_proto, target_port_src, target_port_dest);
	if (ret) {
		pr_err("[NET_INTERCEPT] Failed to parse parameters\n");
		return ret;
	}

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
