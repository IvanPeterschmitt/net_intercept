#include "param_parser.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/inet.h>


static struct ip_mask {
    __be32 ip;
    __be32 mask;
};

static __u8 check_mode(char *mode_str) {
    
    if (strcmp(mode_str, "") == 0) {
        return 1;   //default mode is log (NF_ACCEPT = 1)
    } else if (strcmp(mode_str, "log") == 0) {
        return 1;
    } else if (strcmp(mode_str, "drop") == 0) {
        return 0;
    } else {
        pr_err("[NET_INTERCEPT] Unknown mode: %s\n", mode_str);
        return 255;     //return error for unknown mode
    }
}

static int check_ip(char *ip_str, struct ip_mask *result) {
    __be32 res = in_aton(ip_str);
    char *orig_ptr = ip_str;
    
    for (int i = 0; i < 5; i++) {
        char *byte_str = strsep(&ip_str, ".");
        
        if (i < 4) {
            if (!byte_str) {
                pr_err("[NET_INTERCEPT] Invalid IP address (missing octets): %s\n", orig_ptr);
                return 1;
            }

            unsigned long byte;
            if (kstrtoul(byte_str, 10, &byte) != 0 || byte > 255) {
                pr_err("[NET_INTERCEPT] Invalid IP address (wrong format): %s\n", orig_ptr);
                return 1;
            }
        } else {
            if (byte_str) {
                pr_err("[NET_INTERCEPT] Invalid IP address (too many octets): %s\n", orig_ptr);
                return 1;
            }
        }
    }

    result->ip = res;

    return 0;
}

static int check_ip_mask(const char *ip_str, struct ip_mask *result) {
    char ip_str_copy[32];
    
    if (!ip_str || !result || strscpy(ip_str_copy, ip_str, sizeof(ip_str_copy)) < 0)
        return 1;

    char *slash = strchr(ip_str_copy, '/');
    if (slash) {
        *slash = '\0';
        if (check_ip(ip_str_copy, result)) {
            return 1;
        }
        
        unsigned long prefix_len;
        if (kstrtoul(slash + 1, 10, &prefix_len) != 0 || prefix_len > 32) {
            pr_err("[NET_INTERCEPT] Invalid IP prefix length: %lu\n", prefix_len);
            return 1;
        }
        if (prefix_len == 0) {
            result->mask = 0;
        } else {
            result->mask = htonl(~((1U << (32 - prefix_len)) - 1));
        }
    } else {
        if (check_ip(ip_str_copy, result)) {
            return 1;
        }
        result->mask = htonl(0xFFFFFFFF); // default mask for single IP
    }

    return 0;
}

static __u8 check_proto (char *proto_name) {

    if (strcmp(proto_name, "") == 0) {
        return 0;
    } else if (strcmp(proto_name, "icmp") == 0) {
        return IPPROTO_ICMP;
    } else if (strcmp(proto_name, "tcp") == 0) {
        return IPPROTO_TCP;
    } else if (strcmp(proto_name, "udp") == 0) {
        return IPPROTO_UDP;
    } else {
        pr_err("[NET_INTERCEPT] Unknown protocol: %s\n", proto_name);
        return 255;   //handle error case, return error for unknown protocol
    }
}

static __be16 check_port(int port) {
    
    if (port < 1 || port > 65535) {
        pr_err("[NET_INTERCEPT] Invalid port number: %d. Must be between 1 and 65535.\n", port);
        return 0;
    }
    return htons(port);
}

int parse_params(struct params *params, char *mode, char *src_ip, char *dest_ip, char *protocol, int src_port, int dest_port) {
    struct ip_mask src_ip_mask, dest_ip_mask;

    // interception mode parameter parsing

    if (!mode) {
        params->mode = 0;   //default mode is log
    } else {
        params->mode = check_mode(mode);
    }
    if (params->mode == 255) {
        pr_err("[NET_INTERCEPT] Invalid mode: %s\n", mode);
        return -EINVAL;   //return error for invalid mode
    }

    // source and destination IP address parameter parsing

    if (src_ip[0] == '\0') {
        src_ip = "0.0.0.0/0";               //default: target all traffic
    }
    if (check_ip_mask(src_ip, &src_ip_mask)) {
        pr_err("[NET_INTERCEPT] Invalid source IP address: %s\n", src_ip);
        return -EINVAL;                     //return error for invalid source IP
    }
    params->src_ip = src_ip_mask.ip;
    params->src_mask = src_ip_mask.mask;

    if (dest_ip[0] == '\0') {
        dest_ip = "0.0.0.0/0";              //default: target all traffic
    }
    if (check_ip_mask(dest_ip, &dest_ip_mask)) {
        pr_err("[NET_INTERCEPT] Invalid destination IP address: %s\n", dest_ip);
        return -EINVAL;                     //return error for invalid destination IP
    }
    params->dest_ip = dest_ip_mask.ip;
    params->dest_mask = dest_ip_mask.mask;

    // protocol parameter parsing

    params->protocol = check_proto(protocol);
    if (params->protocol == 255) {
        pr_err("[NET_INTERCEPT] Invalid protocol: %s\n", protocol);
        return -EINVAL;                     //return error for invalid protocol
    }

    // source and destination port parameter parsing
    
    if (src_port != -1) {
        params->src_port = check_port(src_port);
        if (params->src_port == 0) {
            pr_err("[NET_INTERCEPT] Invalid source port: %d\n", src_port);
            return -EINVAL;                  //return error for invalid source port
        }
    } else {
        params->src_port = 0;   //default: target all source ports
    }

    if (dest_port != -1) {
        params->dest_port = check_port(dest_port);
        if (params->dest_port == 0) {
            pr_err("[NET_INTERCEPT] Invalid destination port: %d\n", dest_port);
            return -EINVAL;   //return error for invalid destination port
        }
    } else {
        params->dest_port = 0;   //default: target all destination ports
    }

    if (params->mode == 0 && params->src_ip == 0 && params->dest_ip == 0 && params->protocol == 0 && params->src_port == 0 && params->dest_port == 0) {
        pr_err("[NET_INTERCEPT] Invalid configuration: drop mode with no filtering criteria leads to dropping all incoming traffic.\n");
        return -EINVAL;   //return error for invalid configuration
    }

    return 0;
}