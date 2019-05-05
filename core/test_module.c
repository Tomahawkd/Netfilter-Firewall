#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "filter/detection.h"

static struct nf_hook_ops nfho;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    register struct tcphdr *tcph;
    register struct iphdr *iph;

    // check if it is TCP package here
    if (skb == 0)
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
    tcph = tcp_hdr(skb);

    // debug here
    printk("tcph->dest = %d", tcph->dest);

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

    printk("nf_register_hook returnd %d\n", ret);

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