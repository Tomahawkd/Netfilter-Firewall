#include "constants.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/processor.h>

//========================Filter Declaration==START==Author: @wzs82868996==================
FILTER_BOOL check_tcp(struct iphdr *ip, struct tcphdr *tcp, unsigned char *data, int length);

FILTER_BOOL check_udp(struct iphdr *ip, struct udphdr *udp, unsigned char *data, int length);
//=========================Filter Declaration==END=========================================



//========================Logger Declaration==START==Author: @Dracula1998==================

#define LOG_LEVEL LOGGER_OK

void init_writer(void);

/**
 * Be aware that the message has max length. The concat message length should be less than
 * 512 bytes.
 *
 * @param source
 * @param level
 * @param message
 */
void log_message(char *source, int level, char *message);

void close_writer(void);

//========================Logger Declaration==END==========================================




//========================Messager Declaration==START==Author: @Vshows=====================


//========================Messager Declaration==END========================================



//========================Kernel Module Implementation==START==Author: @Tomahawkd==========
static struct nf_hook_ops nfho;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    if (!skb) return NF_ACCEPT;

    char info[256];

    struct iphdr *ip = ip_hdr(skb);
    if (!ip) return NF_ACCEPT;
    unsigned int saddr = ip->saddr;
    unsigned int daddr = ip->daddr;

    sprintf(info, "IP[%u.%u.%u.%u]--->[%u.%u.%u.%u]", saddr & 255u, saddr >> 8u & 255u, saddr >> 16u & 255u,
           saddr >> 24u & 255u, daddr & 255u, daddr >> 8u & 255u, daddr >> 16u & 255u, daddr >> 24u & 255u);
    log_message("Hook Function IP", LOGGER_OK, info);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = tcp_hdr(skb);

        sprintf(info, "TCP[%u.%u.%u.%u:%hu]-->[%u.%u.%u.%u:%hu]", saddr & 255u, saddr >> 8u & 255u,
                saddr >> 16u & 255u, saddr >> 24u & 255u, tcp->source, daddr & 255u, daddr >> 8u & 255u,
               daddr >> 16u & 255u, daddr >> 24u & 255u, tcp->dest);
        log_message("Hook Function TCP", LOGGER_OK, info);

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

        sprintf(info, "UDP[%u.%u.%u.%u:%hu]-->[%u.%u.%u.%u:%hu]", saddr & 255u, saddr >> 8u & 255u,
                saddr >> 16u & 255u, saddr >> 24u & 255u, udp->source, daddr & 255u, daddr >> 8u & 255u,
               daddr >> 16u & 255u, daddr >> 24u & 255u, udp->dest);
        log_message("Hook Function UDP", LOGGER_OK, info);

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

    init_writer();

    nfho.hook = hook_funcion;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_MANGLE;
    for_each_net(n)ret += nf_register_net_hook(n, &nfho);

    char message[128];
    sprintf(message, "nf_register_hook returnd %d", ret);
    log_message("Hook init", LOGGER_OK, message);

    return 0;
}

static void __exit hook_exit(void) {
    struct net *n;

    log_message("Hook exit", LOGGER_OK, "Hook deinit");

    for_each_net(n)nf_unregister_net_hook(n, &nfho);

    close_writer();
}

module_init(hook_init)
module_exit(hook_exit)

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Tomahawkd");
//========================Kernel Module Implementation==END================================



//========================Filter Implementation==START==Author: @wzs82868996===============
FILTER_BOOL check_tcp(struct iphdr *ip, struct tcphdr *tcp, unsigned char *data, int length) {
    return FILTER_TRUE;
}

FILTER_BOOL check_udp(struct iphdr *ip, struct udphdr *udp, unsigned char *data, int length) {
    return FILTER_TRUE;
}
//========================Filter Implementation==END==Author: @wzs82868996=================




//========================Logger Implementation==START==Author: @Dracula1998===============

struct file *file;

void init_writer(void) {
    file = filp_open("/var/log/NetFilter.log", O_RDWR | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file)) {
        printk(NAME"Create log file error\n");
        file = NULL;
        return;
    }
}

void print_console(int level, char *log_str) {

    if (log_str == NULL) return;

    char *console_color = NULL;

    switch (level) {
        case LOGGER_DEBUG:
            console_color = COLOR_PURPLE;
            break;
        case LOGGER_INFO:
            console_color = COLOR_BLACK;
            break;
        case LOGGER_OK:
            console_color = COLOR_BLUE;
            break;
        case LOGGER_LOW:
            console_color = COLOR_CYAN;
            break;
        case LOGGER_WARN:
            console_color = COLOR_YELLOW;
            break;
        case LOGGER_FATAL:
            console_color = COLOR_RED;
            break;
        default:
            console_color = COLOR_WHITE;
            break;
    }

    printk("%s"NAME"%s"COLOR_RESET, console_color, log_str);

}

void write_log(char *log_str, int length) {

    if (log_str == NULL) return;

    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());
    vfs_write(file, log_str, length, &file->f_pos);
    set_fs(old_fs);
}

void close_writer(void) {
    filp_close(file, NULL);
}

void get_current_time(char* time) {

    struct timex txc;
    struct rtc_time tm;

    do_gettimeofday(&(txc.time));

    txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;
    rtc_time_to_tm(txc.time.tv_sec, &tm);
    sprintf(time, "%d-%02d-%02d %02d:%02d:%02d",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec);
}

void log_message(char *source, int level, char *message) {

    if (file == NULL) return;
    if (message == NULL || source == NULL) return;

    if (level < LOG_LEVEL) return;

    char time[32];
    char log_str[512];
    char *level_str = NULL;

    switch (level) {
        case LOGGER_DEBUG:
            level_str = "DEBUG";
            break;
        case LOGGER_INFO:
            level_str = "INFO";
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

    get_current_time(time);

    sprintf(log_str, "%s [%s] %s %s", time, source, level_str, message);
    print_console(level, log_str);
    strncat(log_str, "\n", 1);
    write_log(log_str, strlen(log_str));
}

//========================Logger Implementation==END=======================================




//========================Messager Implementation==START==Author: @Vshows==================


//========================Messager Implementation==END=====================================
