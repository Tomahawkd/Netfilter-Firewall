#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include "constants.h"

//========================Filter Declaration==START==Author: @wzs82868996==================
bool check_tcp(struct iphdr *ip, struct tcphdr *tcp, unsigned char *data, int length);

bool check_udp(struct iphdr *ip, struct udphdr *udp, unsigned char *data, int length);
//=========================Filter Declaration==END=========================================



//========================Logger Declaration==START==Author: @Dracula1998==================


//========================Logger Declaration==END==========================================




//========================Messager Declaration==START==Author: @Vshows=====================


//========================Messager Declaration==END========================================



//========================Kernel Module Implementation==START==Author: @Tomahawkd==========
static struct nf_hook_ops nfho;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    if (!skb) return NF_ACCEPT;

    struct iphdr *ip = ip_hdr(skb);
    if (!ip) return NF_ACCEPT;
    unsigned int saddr = ip->saddr;
    unsigned int daddr = ip->daddr;
    printk(NAME"IP[%u.%u.%u.%u]--->[%u.%u.%u.%u]", saddr&255u, saddr>>8u&255u, saddr>>16u&255u, saddr>>24u&255u, daddr&255u, daddr>>8u&255u, daddr>>16u&255u, daddr>>24u&255u);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = tcp_hdr(skb);
        printk(NAME"TCP[%u.%u.%u.%u:%hu]-->[%u.%u.%u.%u:%hu]", saddr&255u, saddr>>8u&255u, saddr>>16u&255u, saddr>>24u&255u, tcp->source, daddr&255u, daddr>>8u&255u, daddr>>16u&255u, daddr>>24u&255u, tcp->dest);

        unsigned char *user_data = (unsigned char *) ((unsigned char *) tcp + (tcp->doff * 4));
        unsigned char *tail = skb_tail_pointer(skb);
        if (user_data && tail) {
            int datasize = (int) ((long) tail - (long) user_data);

            if (datasize > 0 && check_tcp(ip, tcp, user_data, datasize)) {
                return NF_ACCEPT;
            } else {
                return NF_ACCEPT;
            }
        }

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = udp_hdr(skb);
        printk(NAME"UDP[%u.%u.%u.%u:%hu]-->[%u.%u.%u.%u:%hu]", saddr&255u, saddr>>8u&255u, saddr>>16u&255u, saddr>>24u&255u, udp->source, daddr&255u, daddr>>8u&255u, daddr>>16u&255u, daddr>>24u&255u, udp->dest);

        unsigned char *user_data = (unsigned char *) ((unsigned char *) udp + 32);
        if (user_data) {
            int datasize = udp->len;

            if (datasize > 0 && check_udp(ip, udp, user_data, datasize)) {
                return NF_ACCEPT;
            } else {
                return NF_ACCEPT;
            }
        }
    } else {
        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

static int __init hook_init(void) {
    int ret = 0;
    struct net *n;

    nfho.hook = hook_funcion;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_MANGLE;
    for_each_net(n)ret += nf_register_net_hook(n, &nfho);

    printk(NAME"nf_register_hook returnd %d\n", ret);

    return 0;
}

static void __exit hook_exit(void) {
    struct net *n;

    for_each_net(n)nf_unregister_net_hook(n, &nfho);
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Tomahawkd");
//========================Kernel Module Implementation==END================================



//========================Filter Implementation==START==Author: @wzs82868996===============
bool check_tcp(struct iphdr *ip, struct tcphdr *tcp, unsigned char *data, int length) {
    return true;
}

bool check_udp(struct iphdr *ip, struct udphdr *udp, unsigned char *data, int length) {
    return true;
}
//========================Filter Implementation==END==Author: @wzs82868996=================




//========================Logger Implementation==START==Author: @Dracula1998===============


//========================Logger Implementation==END=======================================




//========================Messager Implementation==START==Author: @Vshows==================


//========================Messager Implementation==END=====================================
