//
// Created by ghost on 19-5-5.
//

#include <linux/tcp.h>
#include <linux/udp.h>


#ifndef FIREWALL_DETECTION_H
#define FIREWALL_DETECTION_H

bool check_tcp(struct tcphdr * hdr);
bool check_udp(struct udphdr * hdr);

#endif //FIREWALL_DETECTION_H
