#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <linux/skbuff.h>
#include <linux/errno.h>

struct packet_data {
    __be32 src_ip;
    __be32 dest_ip;
    __u8 protocol;
    __be16 src_port;
    __be16 dest_port;
    int error;
};

int parse_packet(struct sk_buff *skb, struct packet_data *packet);

#endif
