#include "packet_filter.h"

#include <linux/netfilter.h>

#define FORBIDDEN_SRC_IP 0x7f000001 // 127.0.0.1

unsigned int filter_packet(struct packet_data *packet, struct params *params) {
    
    if ((packet->src_ip & params->src_mask) != (params->src_ip & params->src_mask)) {
        return 2;   //source IP does not match
    }
    if ((packet->dest_ip & params->dest_mask) != (params->dest_ip & params->dest_mask)) {
        return 2;   //destination IP does not match
    }

    if (params->protocol != 0 && packet->protocol != params->protocol) {
        return 2;   //protocol does not match
    }

    if (params->src_port != 0 && packet->src_port != params->src_port) {
        return 2;   //source port does not match
    }
    if (params->dest_port != 0 && packet->dest_port != params->dest_port) {
        return 2;   //destination port does not match
    }

    return params->mode;   //return the mode (NF_ACCEPT or NF_DROP) if all conditions are met
}