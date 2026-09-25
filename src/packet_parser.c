#include "packet_parser.h"

#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>


static struct iphdr *ip_hdr_check(struct sk_buff *skb) {
	struct iphdr *iph;
	unsigned int ip_header_len;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))        //checks if the a minimal-sized IP header is available
		return NULL;

	iph = ip_hdr(skb);                             //ip_hdr() gives a pointer to the beginning of the IP header
	if (!iph)
		return NULL;

	ip_header_len = iph->ihl * 4;         //retrieves the real size of IP header

	if (ip_header_len < sizeof(struct iphdr))
		return NULL;

	if (!pskb_may_pull(skb, ip_header_len))        //checks if all data from IP header is available inline
		return NULL;

	iph = ip_hdr(skb);                             //in case the pskb_may_pull() function has reallocated the skb
	if (!iph)
		return NULL;

	return iph;
}

static struct tcphdr *tcp_hdr_check(struct sk_buff *skb) {
	struct tcphdr *tcph;
	unsigned int tcp_header_len;
	unsigned int ip_header_len;

	ip_header_len = ip_hdr(skb)->ihl * 4;

	if (!pskb_may_pull(skb, ip_header_len + sizeof(struct tcphdr)))
		return NULL;

	tcph = tcp_hdr(skb);
	if (!tcph)
		return NULL;

	tcp_header_len = tcph->doff * 4;

	if (tcp_header_len < sizeof(struct tcphdr))
		return NULL;

	if (!pskb_may_pull(skb, ip_header_len + tcp_header_len))
		return NULL;

	tcph = tcp_hdr(skb);
	if (!tcph)
		return NULL;

	return tcph;
}

static struct udphdr *udp_hdr_check(struct sk_buff *skb) {
	struct udphdr *udph;
	unsigned int ip_header_len;

	ip_header_len = ip_hdr(skb)->ihl * 4;

	if (!pskb_may_pull(skb, ip_header_len + sizeof(struct udphdr)))
		return NULL;

	udph = udp_hdr(skb);   //no need to recalculate the UDP header length, since it is always 8 bytes long
	if (!udph)
		return NULL;

	return udph;
}

int parse_packet(struct sk_buff *skb, struct packet_data *packet) {
	struct iphdr *iph;

	iph = ip_hdr_check(skb);
	if (!iph) {
		pr_debug("[NET_INTERCEPT] Failed to parse IP header\n");
		return 1;
	}

	packet->src_ip = iph->saddr;
	packet->dest_ip = iph->daddr;
	packet->protocol = iph->protocol;

	switch (iph->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph;

			tcph = tcp_hdr_check(skb);
			if (!tcph) {
				pr_debug("[NET_INTERCEPT] Failed to parse TCP header\n");
				return 1;
			}

			packet->src_port = tcph->source;
			packet->dest_port = tcph->dest;

			break;
		}

		case IPPROTO_UDP: {
			struct udphdr *udph;

			udph = udp_hdr_check(skb);
			if (!udph) {
				pr_debug("[NET_INTERCEPT] Failed to parse UDP header\n");
				return 1;
			}

			packet->src_port = udph->source;
			packet->dest_port = udph->dest;

			break;
		}
	}

	return 0;
}
