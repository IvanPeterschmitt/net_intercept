#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <linux/skbuff.h>

unsigned int parse_packet(struct sk_buff *skb);

#endif
