#ifndef PARAM_PARSER_H
#define PARAM_PARSER_H

#include <linux/types.h>
#include <linux/errno.h>

struct params {
    __u8 mode;
    __be32 src_ip;
    __be32 src_mask;
    __be32 dest_ip;
    __be32 dest_mask;
    __u8 protocol;
    __be16 src_port;
    __be16 dest_port;
    int error;   //error code if parsing goes wrong
};

int parse_params(struct params *params, char *mode, char *src_ip, char *dest_ip, char *protocol, int src_port, int dest_port);

#endif