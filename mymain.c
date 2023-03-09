#define WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include "pcap.h"
#ifndef WIN32
#include <sys/socket.h>
#include <WinSock2.h>
#include <netinet/in.h>
#else
#include <WinSock2.h>
#endif
#pragma comment(lib,"wpcap")

using namespace std;

/*下边是以太网的协议格式 */
struct ethernet_header
{
    u_int8_t ether_dhost[6];  /*目的以太地址*/
    u_int8_t ether_shost[6];  /*源以太网地址*/
    u_int16_t ether_type;      /*以太网类型*/
};

/*ip地址格式*/
typedef u_int32_t in_addr_t;

struct ipv4_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IP协议首部长度Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*服务类型Differentiated Services  Field*/
    u_int16_t ip_length;  /*总长度Total Length*/
    u_int16_t ip_id;         /*标识identification*/
    u_int16_t ip_off;        /*片偏移*/
    u_int8_t ip_ttl;            /*生存时间Time To Live*/
    u_int8_t ip_protocol;        /*协议类型（TCP或者UDP协议）*/
    u_int16_t ip_checksum;  /*首部检验和*/
    struct in_addr  ip_source_address; /*源IP*/
    struct in_addr  ip_destination_address; /*目的IP*/
};


struct ipv6_header
{
#ifdef WORKS_BIGENDIAN
    u_int32_t version : 4,
        u_int32_t traffic_class : 8, 
        u_int32_t flow_label : 20;
#else
    u_int32_t flow_label : 20,
         traffic_class : 8, //流量分类（Traffic Class）
         version : 4;
#endif

    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
};

/*关于udp头部的定义*/
struct udp_header
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

// L2TP头部结构
struct l2tp_header {
#ifdef WORKS_BIGENDIAN
    u_int8_t type : 1,
        lengthin : 1,
        x2 : 2,
        sequence : 1,
        x1 : 1,
        offset : 1,
        priority : 1;
    u_int8_t  x3 : 4,
       ver : 4;
#else
    u_int8_t priority : 1,
         offset : 1,
        x1 : 1,
        sequence :1,
        x2: 2,
        lengthin:1,
        type:1;
    u_int8_t ver : 4,
        x3: 4;
#endif
    uint16_t length;    // L2TP数据包长度
    uint16_t tunnel_id; // 隧道ID
    uint16_t session_id;// 会话ID
    uint16_t ns;        // 下一个发送序列号
    uint16_t nr;        // 下一个期望接收序列号
    uint16_t offset_size;    // 偏移量
};

// ppp头部结构
struct ppp_header {

    u_int8_t flag; //标志，默认0x7e
    u_int8_t address; //默认0xff
    u_int8_t control; //默认0x03
    u_int16_t procotol;

};

// message_type_avp头部结构
struct avp_header{

    u_int32_t length : 10, //avp长度
        rsvd : 4,  //保留位
        H : 1, //hidden位
        M : 1; //Mandatory位
    uint16_t vendor_ID;    // SMI 网络管理专用”企业代码“[RFC1700] 值 一般为0
    uint16_t Attribute_Type; // avp属性类型
};
/* packet handler 函数原型 */
void my_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);




int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char packet_filter[] = "ether proto 0x0800 or ether proto 0x86DD";
    struct bpf_program fcode;
    u_int netmask = 0;
    

    /* 获取本机设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* 打印列表 */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 跳转到选中的适配器 */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* 打开设备 */
    if ((adhandle = pcap_open(d->name,          // 设备名
        65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
        1000,             // 读取超时时间
        NULL,             // 远程机器验证
        errbuf            // 错误缓冲池
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* complie the filter */
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "/nUnable to compile the packet filter. Check the syntax./n");
        /* Free the devices list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* set the filter */
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "/nError setting the filter./n");
        /* Free the devices list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    printf("\nlistening on %s...\n", d->description);

    /* 释放设备列表 */
    pcap_freealldevs(alldevs);

    /* 开始捕获 */
    pcap_loop(adhandle, 0, my_protocol_packet_callback, NULL);

    return 0;
}



void my_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{


    //解析以太网协议头

    u_short ethernet_type;                                     /*以太网协议类型*/
    struct ethernet_header* ethernet_protocol;  /*以太网协议变量*/
    u_char* mac_string;
    static int packet_number = 1;
    const int ether_header_length = 14;
    printf("\n*** ****** ******* *********   ********* ******* ****** ***\n");
    printf("\t!!!!!#    第【 %d 】个IP数据包被捕获    #!!!!!\n", packet_number);
    printf("\n==========    链路层(以太网协议)    ==========\n");
    ethernet_protocol = (struct ethernet_header*)packet_content;  /*获得一太网协议数据内容*/
    printf("以太网类型为 :\t");
    ethernet_type = ntohs(ethernet_protocol->ether_type); /*获得以太网类型*/
    printf("%04x\n", ethernet_type);
    packet_number++;
    if (ethernet_type != 0x0800 && ethernet_type != 0x86DD) {
        printf("上层不是IPV4或者IPV6协议，停止解析\n");
        return ;
    }
   
    
    /*获得Mac源地址*/
    printf("Mac源地址:\t");
    mac_string = ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    /*获得Mac目的地址*/
    printf("Mac目的地址:\t");
    mac_string = ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

 
    u_int  ip_header_length;    /*长度*/

    //解析IPv4协议头
    if (ethernet_type == 0x0800) {
        printf("上层是IPV4协议，继续解析\n");
        struct ipv4_header* ip_protocol;   /*ip协议变量*/
       
        u_int  offset;                   /*片偏移*/
        u_char  tos;                     /*服务类型*/
        u_int16_t checksum;    /*首部检验和*/
        ip_protocol = (struct ipv4_header*)(packet_content + ether_header_length); /*获得ip数据包的内容去掉以太头部*/
        checksum = ntohs(ip_protocol->ip_checksum);      /*获得校验和*/
        ip_header_length = ip_protocol->ip_header_length * 4; /*获得长度*/
        tos = ip_protocol->ip_tos;    /*获得tos*/
        offset = ntohs(ip_protocol->ip_off);   /*获得偏移量*/
        printf("\n##########    网络层（IP协议）    ########### \n");
        printf("IP版本:\t\tIPv%d\n", ip_protocol->ip_version);
        printf("IP协议首部长度:\t%d\n", ip_header_length);
        printf("服务类型:\t%d\n", tos);
        printf("总长度:\t\t%d\n", ntohs(ip_protocol->ip_length));/*获得总长度*/
        printf("标识:\t\t%d\n", ntohs(ip_protocol->ip_id));  /*获得标识*/
        printf("片偏移:\t\t%d\n", (offset & 0x1fff) * 8);    /**/
        printf("生存时间:\t%d\n", ip_protocol->ip_ttl);     /*获得ttl*/
        printf("首部检验和:\t%d\n", checksum);
        printf("源IP:\t%s\n", inet_ntoa(ip_protocol->ip_source_address));          /*获得源ip地址*/
        printf("目的IP:\t%s\n", inet_ntoa(ip_protocol->ip_destination_address));/*获得目的ip地址*/
        printf("协议号:\t%d\n", ip_protocol->ip_protocol);         /*获得协议类型*/
        

        if (ip_protocol->ip_protocol != 17) {
            printf("上层不是UDP停止解析\n");
            return;
        }
        printf("上层是UDP继续解析\n");
    }

    //解析IPv6协议头
    else if (ethernet_type == 0x86DD) {
        printf("上层是IPV6协议，继续解析\n");
        struct ipv6_header* ipv6_hdr;   /*ip协议变量*/
        char src_addr[40], dst_addr[40];
        ipv6_hdr = (struct ipv6_header*)(packet_content + ether_header_length);

        inet_ntop(AF_INET6, &(ipv6_hdr->src_addr), src_addr, 40);
        inet_ntop(AF_INET6, &(ipv6_hdr->dst_addr), dst_addr, 40);
        printf("Source Address: %s\n", src_addr);
        printf("Destination Address: %s\n", dst_addr);
        printf("Next Header: %u\n", ipv6_hdr->next_header);
        printf("Hop Limit: %u\n", ipv6_hdr->hop_limit);
        printf("Payload Length: %u\n", ntohs(ipv6_hdr->payload_len));

        if (ipv6_hdr->next_header != 17) {
            printf("上层不是UDP停止解析\n");
            return;
        };
        ip_header_length=40;
        
       
    }
    
    //解析UDP协议头

    struct udp_header* udp_protocol;
    u_short source_port;
    u_short destination_port;
    u_short length;
    const int udp_header_length = 8;
    udp_protocol = (struct udp_header*)(packet_content+ether_header_length+ ip_header_length);
    /* 获取UPD协议数据 */

    source_port = ntohs(udp_protocol->uh_sport);
    /* 获取源端口 */

    destination_port = ntohs(udp_protocol->uh_dport);
    /* 获取目的端口 */

    length = ntohs(udp_protocol->uh_ulen);
    /* 获取长度 */

    printf("----------  UDP协议首部    ----------\n");
    printf("源端口:%d\n", source_port);
    printf("目的端口:%d\n", destination_port);
    if (destination_port != 1701) {
        printf("目的端口号不是1701，停止解析\n");
        return;
    }
    
    printf("长度:%d\n", length);
    printf("校验和:%d\n", ntohs(udp_protocol->uh_sum));
    /* 获取校验和 */


    //解析l2tp协议头
    printf("目的端口号是1701，继续解析\n");


    l2tp_header* l2tp;
    int headerlength = 6;
    u_int16_t l2tp_length;
    u_int16_t tunnel_id;
    u_int16_t session_id;
    u_int16_t Ns;
    u_int16_t Nr;
    u_int16_t offset_size;

    // 指向L2TP头部
    l2tp = (l2tp_header*)(packet_content+ether_header_length+ip_header_length+udp_header_length); // 以太网头部长度为14字节，IP头部长度为20字节，UDP头部长度为8字节

    printf("L2TP packet received:\n");
    printf("  版本号: %d\n", l2tp->ver);
    bool type = l2tp->type;
    string stype = l2tp->type ? "控制信息" : "数据信息";
    printf("类型: %s\n", stype);

    bool lengthin = l2tp->lengthin; //长度域是否存在 
    bool sequence = l2tp->sequence; //序列域是否存在
    bool l2tp_offset = l2tp->offset; //偏移域是否存在
    if (lengthin) {
        l2tp_length = ntohs(l2tp->length);
        printf("  Length: %d\n", length);
        headerlength += 2;
        tunnel_id = ntohs(l2tp->tunnel_id);
        session_id = ntohs(l2tp->session_id);
        printf("  Tunnel ID: %d\n", tunnel_id);
        printf("  Session ID: %d\n", session_id);
        if (sequence) {
            headerlength += 4;
            Ns = ntohs(l2tp->ns);
            Nr = ntohs(l2tp->nr);
            printf("  NS: %d\n", Ns);
            printf("  NR: %d\n", Nr);
            if (l2tp_offset) {
                offset_size = ntohs(l2tp->offset_size);
                printf("Offset size: %d\n", offset_size);
                headerlength += 2;
                headerlength += offset_size;
            }
        }
        else {
            if (l2tp_offset) {
                offset_size = ntohs(l2tp->ns);
                printf("Offset size: %d\n", offset_size);
                headerlength += 2;
                headerlength += offset_size;
            }
        }
    }
    else {
        tunnel_id = ntohs(l2tp->length);
        session_id = ntohs(l2tp->tunnel_id);
        printf("  Tunnel ID: %d\n", tunnel_id);
        printf("  Session ID: %d\n", session_id);
        if (sequence) {
            headerlength += 4;
            Ns = ntohs(l2tp->session_id);
            Nr = ntohs(l2tp->ns);
            printf("  NS: %d\n", Ns);
            printf("  NR: %d\n", Nr);
            if (l2tp_offset) {
                offset_size = ntohs(l2tp->nr);
                printf("Offset size: %d\n", offset_size);
                headerlength += 2;
                headerlength += offset_size;
            }
        }
        else {
            if (l2tp_offset) {
                offset_size = ntohs(l2tp->session_id);
                printf("Offset size: %d\n", offset_size);
                headerlength += 2;
                headerlength += offset_size;
            }
        }
    }
    printf("l2tp头总长度: %d\n", headerlength);

    if (l2tp->type) {
        //如果是控制信息，紧随在l2tp头之后的就应该是message type 的avp
        //avp_protocol_packet_callback(packet_content + headerlength);
        printf("这是一个控制包/n");
    }

    else {
        //如果是数据信息则应该检查剩余信息是否以ppp协议开头
        printf("这是一个数据包/n");
    }
}








/*void ppp_protocol_packet_callback(const u_char* packet_content) {
    ppp_header* ppp;

    ppp = (ppp_header*)(packet_content);

    if (ppp->flag == 0x7e && ppp->address == 0xff && ppp->control == 0x3c) {
        printf("确实是ppp协议,继续解析");
        u_int16_t procotol = ntohs(ppp->procotol);
        if (procotol == 0x0021) {
            printf("ppp协议包装了ip协议,继续解析");
            ip_protocol_packet_callback(packet_content + 5);
        }
        else {
            printf("ppp协议中不是ip协议，停止解析");
        }
    }
    else {
        printf("不是ppp协议，停止解析");
        return;
    }
}

void avp_protocol_packet_callback(const u_char* packet_content) {
    

    avp_header*  avp = (avp_header*)(packet_content);

    
}*/

