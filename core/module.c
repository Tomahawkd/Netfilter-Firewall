#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include "constants.h"
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/string.h>
#include <linux/types.h>

//========================Filter Declaration==START==Author: @wzs82868996==================
bool check_tcp(struct iphdr *ip, struct tcphdr *tcp, unsigned char *data, int length);

bool check_udp(struct iphdr *ip, struct udphdr *udp, unsigned char *data, int length);
//=========================Filter Declaration==END=========================================



//========================Logger Declaration==START==Author: @Dracula1998==================

/*
struct {
    char *time;
    char *source;
    char *message;
    int level;
    char *level_str;
} logger_record;
*/
char *log_str = NULL;

void init_writer(void);
void log_message(char *source, int level, char *message);
void close_writer(void);

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

struct file *fp;
//char time_str_space[50];
//char log_space[400];

void init_writer(void)
{
    fp = filp_open("/var/log/NetFilter.log",O_RDWR | O_CREAT,0644);
    if (IS_ERR(fp)){
        printk("create file error/n");
	return;
    }
}

void write_log(char *log_str)
{
    mm_segment_t fs;
    loff_t pos;

    printk("hello enter/n");

    fs = get_fs();
    set_fs(KERNEL_DS);
    vfs_write(fp, log_str, strlen(log_str)*8, &pos);
    set_fs(fs);
}

void close_writer(void)
{
    filp_close(fp,NULL);
}

char *get_current_time(void)
{
/*
    tt = time(NULL);
	t = localtime(&tt);
	char *log_time = time_str_space;
	log_time = "";
	log_time = strcat(log_time, t->tm_year + 1900);
	log_time = strcat(log_time, "-");
	log_time = strcat(log_time, t->tm_mon + 1);
	log_time = strcat(log_time, "-");
	log_time = strcat(log_time, t->tm_mday);
	log_time = strcat(log_time, " ");
	log_time = strcat(log_time, t->tm_hour);
	log_time = strcat(log_time, ":");
	log_time = strcat(log_time, t->tm_min);
	log_time = strcat(log_time, ":");
	log_time = strcat(log_time, t->tm_sec);

    return log_time;
*/
	struct timex txc;
	struct rtc_time tm;

	do_gettimeofday(&(txc.time));

	txc.time.tv_sec -= sys_tz.tz_minuteswest*60;
	rtc_time_to_tm(txc.time.tv_sec, &tm);
	sprintf(time, "\n%d-%02d-%02d %02d:%02d:%02d\n",
		tm.tm_year + 1900,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec);
    return time;
}

void log_message(char *source, int level,char *message) {
    char *time = NULL;
    char *level_str = NULL;

    printk("%s\n", source);
    printk("%s\n", message);
    printk("%d\n", level);

    switch(level)
    {
    case LOGGER_DEBUG:
        level_str = "DEBUG";
        break;
    case LOGGER_OK:
        level_str = "OK";
        break;
    case LOGGER_LOW:
        level_str = "LOW";
        break;
    case LOGGER_WARN:
        level_str = "WARN";
        break;
    case LOGGER_FATAL:
        level_str = "FATAL";
        break;
    default:
        level_str = "UNKNOWN";
        break;
    }
    //char *log_str = = log_space;
    time = get_current_time();
/*
    log_str = logger_record.time;
    log_str = strcat(log_str, " [");
    log_str = strcat(log_str, logger_record.level_str);
    log_str = strcat(log_str, "][");
    log_str = strcat(log_str, logger_record.source);
    log_str = strcat(log_str, "] ");
    log_str = strcat(log_str, logger_record.message);
    log_str = strcat(log_str, "\n");
*/
    sprintf(log_str, "%s [%s][%s] %s\n", time, level_str, source, message);
    write_log(log_str);
}

//========================Logger Implementation==END=======================================




//========================Messager Implementation==START==Author: @Vshows==================


//========================Messager Implementation==END=====================================
