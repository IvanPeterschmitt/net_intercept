#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include "packet_parser.h"
#include "param_parser.h"

unsigned int filter_packet(struct packet_data *packet, struct params *params);

#endif