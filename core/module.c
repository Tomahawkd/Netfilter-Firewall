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
typedef struct Node {
    unsigned int sip;
    unsigned short port;
    unsigned short protocol;
    unsigned int mask;
    bool isPermit;
    struct Node *next; 
} Node, *NodePointer;

static int major_number;
static NodePointer head, tail;
static struct cdev netfilter_cdev;

void addRule(struct Node *node);

void deleteRule(struct Node *node);

void clearRule(void);

long cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

struct file_operations cdev_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = cdev_ioctl
};

unsigned int times_contains(unsigned char *s, unsigned char *c, unsigned int lens, unsigned int lenc);

bool check_ip(struct iphdr *ip, unsigned short sport);

bool check_sc(unsigned char *data, unsigned int length);

FILTER_BOOL check_tcp(struct iphdr *ip, struct tcphdr *tcp, unsigned char *data, unsigned int length);

FILTER_BOOL check_udp(struct iphdr *ip, struct udphdr *udp, unsigned char *data, unsigned int length);
//=========================Filter Declaration==END=========================================



//========================Logger Declaration==START==Author: @Dracula1998==================

#define LOG_LEVEL LOGGER_OK

void init_writer(void);

/**
 * Be aware that the message has max length. The message length should be less than
 * 512 bytes and the source length should be less than 64.
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


//========================Messager Implementation==START==Author: @Vshows==================


//========================Messager Implementation==END=====================================


//========================Filter Implementation==START==Author: @wzs82868996===============
void addRule(struct Node *node) {
    Node *p;
    p = (Node *)kmalloc(sizeof(Node), 0);
    memcpy(p, node, sizeof(struct Node));
    p->next = NULL;
    if (head->next == NULL && tail->next == NULL) {
        head->next = p;
        tail->next = p;
    }
    else {
        tail->next->next = p;
        tail->next = p;
    }
    log_message("Add Rule", LOGGER_OK, "A new rule added.");
}

void deleteRule(struct Node *node) {
    if (head->next != NULL || tail->next != NULL) {
        Node *p = head;
        Node *pp = p;
        while (p && p->next != NULL) {
            pp = p;
            p = p->next;

            if(p->sip != node->sip)
                continue;
            if(p->port != node->port)
                continue;
            if(p->protocol != node->protocol)
                continue;
            if(p->mask != node->mask)
                continue;
            if(p->isPermit != node->isPermit)
                continue;

            if(pp->next == head->next) {
                head->next = NULL;
                tail->next = NULL;
            }
            else if(tail->next == pp->next) {
                tail->next = pp;
                pp->next = NULL;
            }
            else
                pp->next = p->next;
            break;
        }
        kfree(p);
    }
    log_message("Delete Rule", LOGGER_OK, "Rules deleted.");
}

void clearRule(void) {
    Node *p = head;
    Node *t = NULL;
    while (p && p->next != NULL) {
        p = p->next;
        t = p->next;
        kfree(p);
        p = t;
    }
    head->next = NULL;
    tail->next = NULL;
    log_message("Clear Rule", LOGGER_OK, "Rules cleared.");
}

long cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    Node node;
    copy_from_user(&node,(struct Node *)arg, sizeof(struct Node));
    switch (cmd) {
        case 0:
            addRule(&node);
            break;
        case 1:
            deleteRule(&node);
            break;
        case 2:
            clearRule();
            break;
    }
    return 0;
}

unsigned int times_contains(unsigned char *s, unsigned char *c, unsigned int lens, unsigned int lenc) {
    unsigned int i = 0, j = 0, count = 0;
    while (i < lens && j < lenc){
        if (s[i] == c[j]) {
            i++;
            j++;
        } else {
            i -= j - 1;
            j = 0;
        }
        if (j == lenc) {
            count++;
            j = 0;
        }
    }
    return count;
}

bool check_ip(struct iphdr *ip, unsigned short sport) {
    Node *p = head;
    unsigned int sip;
    unsigned short port;
    unsigned short mask;

    while(p->next != NULL) {
        p = p->next;
        if (p->isPermit)
            continue;
        sip = p->sip;
        port = p->port;
        mask = p->mask;

        if ((ip->saddr & mask) != (sip & mask))
            continue;

        if (ip->protocol != p->protocol && p->protocol != 0)
            continue;

        if (sport != port && port != 0)
           continue;

        char info[256];
        sprintf(info, "IP[%u.%u.%u.%u] port %u blocked!", ip->saddr & 255u, ip->saddr >> 8u & 255u, ip->saddr >> 16u & 255u, ip->saddr >> 24u & 255u, port);
        log_message("Check IP", LOGGER_WARN, info);
        return false;
    }
    return true;
}

bool check_sc(unsigned char *data, unsigned int length) {
    unsigned char pushl_vsh[] = "\x68\x2f\x2f\x73\x68";
    unsigned char pushl_sh[] = "\x68\x2f\x73\x68";
    unsigned char pushl_bin[] = "\x68\x2f\x74\x6d\x70";
    unsigned char nop[] = "\x90";
    unsigned char intrpt[] = "\x80";
    unsigned char intrpt_win10[] = "\xcc";
    unsigned int nop_threshold = 10;
    unsigned int int_threshold = 3;
    bool nop_sled = false, instuct_int = false;
    if (times_contains(data, nop, length, 1) > nop_threshold)
        nop_sled = true;

    if (times_contains(data, intrpt, length, 1) > int_threshold)
        instuct_int = true;

    if (times_contains(data, intrpt_win10, length, 1) > int_threshold)
        instuct_int = true;

    if (times_contains(data, pushl_vsh, length, 5) != 0) {
        if (nop_sled)
            log_message("Check SC", LOGGER_WARN, "NOP sled detected!");
        if (instuct_int)
            log_message("Check SC", LOGGER_WARN, "Instruction INT detected!");
        log_message("Check SC", LOGGER_WARN, "Suspicious \"//sh\" detected. Is there an \"execve\"?");
        return false;
    }

    if (times_contains(data, pushl_sh, length, 4) != 0) {
        if (nop_sled)
            log_message("Check SC", LOGGER_WARN, "NOP sled detected!");
        if (instuct_int)
            log_message("Check SC", LOGGER_WARN, "Instruction INT detected!");
        log_message("Check SC", LOGGER_WARN, "Suspicious \"/sh\" detected. Is there an \"execve\"?");
        return false;
    }

    if (times_contains(data, pushl_bin, length, 5) != 0) {
        if (nop_sled)
            log_message("Check SC", LOGGER_WARN, "NOP sled detected!");
        if (instuct_int)
            log_message("Check SC", LOGGER_WARN, "Instruction INT detected!");
        log_message("Check SC", LOGGER_WARN, "Suspicious \"/bin\" detected. Is there an \"execve\"?");
        return false;
    }

    return true;
}

FILTER_BOOL check_tcp(struct iphdr *ip, struct tcphdr *tcp, unsigned char *data, unsigned int length) {
    if(!check_ip(ip, tcp->source))
        return FILTER_FALSE;

    if(!check_sc(data, length))
        return FILTER_FALSE;

    return FILTER_TRUE;
}

FILTER_BOOL check_udp(struct iphdr *ip, struct udphdr *udp, unsigned char *data, unsigned int length) {
    if(!check_ip(ip, udp->source))
        return FILTER_FALSE;

    if(!check_sc(data, length))
        return FILTER_FALSE;

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

    int message_len, source_len;
    char time[32];
    char *level_str = NULL;
    char *log_str;
    
    if (file == NULL) return;
    if (message == NULL || source == NULL) return;

    message_len = strnlen(message, 512);
    source_len = strnlen(source, 64);

    // length too long
    if (message_len >= 512) {
        print_console(LOGGER_WARN, NAME"Message length exceeded 512");
        return;
    }
    if (source_len >= 64) {
        print_console(LOGGER_WARN, NAME"Source length exceeded 64");
        return;
    }

    if (level < LOG_LEVEL) return;

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

    log_str = kmalloc(32 + 2 + source_len + 2 + strlen(level_str) + 1 + message_len + 2);

    sprintf(log_str, "%s [%s] %s %s", time, source, level_str, message);
    print_console(level, log_str);
    strncat(log_str, "\n", 1);
    write_log(log_str, strlen(log_str));
    kfree(log_str);
}

//========================Logger Implementation==END=======================================


//========================Kernel Module Implementation==START==Author: @Tomahawkd==========
static struct nf_hook_ops nfho;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    unsigned int saddr, daddr;
    unsigned char *user_data, *tail;
    int datasize;
    char info[256];
    
    if (!skb) return NF_ACCEPT;

    ip = ip_hdr(skb);
    if (!ip) return NF_ACCEPT;
    saddr = ip->saddr;
    daddr = ip->daddr;

    sprintf(info, "IP[%u.%u.%u.%u]--->[%u.%u.%u.%u]", saddr & 255u, saddr >> 8u & 255u, saddr >> 16u & 255u,
            saddr >> 24u & 255u, daddr & 255u, daddr >> 8u & 255u, daddr >> 16u & 255u, daddr >> 24u & 255u);
    log_message("Hook Function IP", LOGGER_OK, info);

    if (ip->protocol == IPPROTO_TCP) {
        tcp = tcp_hdr(skb);

        sprintf(info, "TCP[%u.%u.%u.%u:%hu]-->[%u.%u.%u.%u:%hu]", saddr & 255u, saddr >> 8u & 255u,
                saddr >> 16u & 255u, saddr >> 24u & 255u, tcp->source, daddr & 255u, daddr >> 8u & 255u,
                daddr >> 16u & 255u, daddr >> 24u & 255u, tcp->dest);
        log_message("Hook Function TCP", LOGGER_OK, info);

        user_data = (unsigned char *) ((unsigned char *) tcp + (tcp->doff * 4));
        tail = skb_tail_pointer(skb);
        if (user_data && tail) {
            datasize = (int) ((long) tail - (long) user_data);

            if (datasize > 0 && check_tcp(ip, tcp, user_data, datasize)) {
                return NF_ACCEPT;
            } else {
                return NF_ACCEPT;
            }
        }

    } else if (ip->protocol == IPPROTO_UDP) {
        udp = udp_hdr(skb);

        sprintf(info, "UDP[%u.%u.%u.%u:%hu]-->[%u.%u.%u.%u:%hu]", saddr & 255u, saddr >> 8u & 255u,
                saddr >> 16u & 255u, saddr >> 24u & 255u, udp->source, daddr & 255u, daddr >> 8u & 255u,
                daddr >> 16u & 255u, daddr >> 24u & 255u, udp->dest);
        log_message("Hook Function UDP", LOGGER_OK, info);

        user_data = (unsigned char *) ((unsigned char *) udp + 32);
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
    char message[128];
    dev_t devno,devno_m;

    init_writer();

    nfho.hook = hook_funcion;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_MANGLE;
    for_each_net(n)ret += nf_register_net_hook(n, &nfho);

    sprintf(message, "nf_register_hook returnd %d", ret);
    log_message("Hook init", LOGGER_OK, message);

    ret = alloc_chrdev_region(&devno, 0, 1, "NetfilterFirewall");
    if (ret < 0)
        return ret;

    major_number = MAJOR(devno);
    devno_m = MKDEV(major_number, 0);
    cdev_init(&netfilter_cdev, &cdev_fops);
    cdev_add(&netfilter_cdev, devno_m, 1);
    
    head = (Node *)kmalloc(sizeof(Node), 0);
    head->next = NULL;
    tail = head;

    return ret;
}

static void __exit hook_exit(void) {
    struct net *n;

    log_message("Hook exit", LOGGER_OK, "Hook deinit");

    clearRule();
    for_each_net(n)nf_unregister_net_hook(n, &nfho);

    close_writer();

    cdev_del(&netfilter_cdev);
    unregister_chrdev_region(MKDEV(major_number, 0), 1);
}

module_init(hook_init)
module_exit(hook_exit)

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Tomahawkd");
//========================Kernel Module Implementation==END================================
