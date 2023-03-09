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

/*�±�����̫����Э���ʽ */
struct ethernet_header
{
    u_int8_t ether_dhost[6];  /*Ŀ����̫��ַ*/
    u_int8_t ether_shost[6];  /*Դ��̫����ַ*/
    u_int16_t ether_type;      /*��̫������*/
};

/*ip��ַ��ʽ*/
typedef u_int32_t in_addr_t;

struct ipv4_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IPЭ���ײ�����Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*��������Differentiated Services  Field*/
    u_int16_t ip_length;  /*�ܳ���Total Length*/
    u_int16_t ip_id;         /*��ʶidentification*/
    u_int16_t ip_off;        /*Ƭƫ��*/
    u_int8_t ip_ttl;            /*����ʱ��Time To Live*/
    u_int8_t ip_protocol;        /*Э�����ͣ�TCP����UDPЭ�飩*/
    u_int16_t ip_checksum;  /*�ײ������*/
    struct in_addr  ip_source_address; /*ԴIP*/
    struct in_addr  ip_destination_address; /*Ŀ��IP*/
};


struct ipv6_header
{
#ifdef WORKS_BIGENDIAN
    u_int32_t version : 4,
        u_int32_t traffic_class : 8, 
        u_int32_t flow_label : 20;
#else
    u_int32_t flow_label : 20,
         traffic_class : 8, //�������ࣨTraffic Class��
         version : 4;
#endif

    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
};

/*����udpͷ���Ķ���*/
struct udp_header
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

// L2TPͷ���ṹ
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
    uint16_t length;    // L2TP���ݰ�����
    uint16_t tunnel_id; // ���ID
    uint16_t session_id;// �ỰID
    uint16_t ns;        // ��һ���������к�
    uint16_t nr;        // ��һ�������������к�
    uint16_t offset_size;    // ƫ����
};

// pppͷ���ṹ
struct ppp_header {

    u_int8_t flag; //��־��Ĭ��0x7e
    u_int8_t address; //Ĭ��0xff
    u_int8_t control; //Ĭ��0x03
    u_int16_t procotol;

};

// message_type_avpͷ���ṹ
struct avp_header{

    u_int32_t length : 10, //avp����
        rsvd : 4,  //����λ
        H : 1, //hiddenλ
        M : 1; //Mandatoryλ
    uint16_t vendor_ID;    // SMI �������ר�á���ҵ���롰[RFC1700] ֵ һ��Ϊ0
    uint16_t Attribute_Type; // avp��������
};
/* packet handler ����ԭ�� */
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
    

    /* ��ȡ�����豸�б� */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* ��ӡ�б� */
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
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* ��ת��ѡ�е������� */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* ���豸 */
    if ((adhandle = pcap_open(d->name,          // �豸��
        65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
        PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
        1000,             // ��ȡ��ʱʱ��
        NULL,             // Զ�̻�����֤
        errbuf            // ���󻺳��
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* �ͷ��豸�б� */
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

    /* �ͷ��豸�б� */
    pcap_freealldevs(alldevs);

    /* ��ʼ���� */
    pcap_loop(adhandle, 0, my_protocol_packet_callback, NULL);

    return 0;
}



void my_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{


    //������̫��Э��ͷ

    u_short ethernet_type;                                     /*��̫��Э������*/
    struct ethernet_header* ethernet_protocol;  /*��̫��Э�����*/
    u_char* mac_string;
    static int packet_number = 1;
    const int ether_header_length = 14;
    printf("\n*** ****** ******* *********   ********* ******* ****** ***\n");
    printf("\t!!!!!#    �ڡ� %d ����IP���ݰ�������    #!!!!!\n", packet_number);
    printf("\n==========    ��·��(��̫��Э��)    ==========\n");
    ethernet_protocol = (struct ethernet_header*)packet_content;  /*���һ̫��Э����������*/
    printf("��̫������Ϊ :\t");
    ethernet_type = ntohs(ethernet_protocol->ether_type); /*�����̫������*/
    printf("%04x\n", ethernet_type);
    packet_number++;
    if (ethernet_type != 0x0800 && ethernet_type != 0x86DD) {
        printf("�ϲ㲻��IPV4����IPV6Э�飬ֹͣ����\n");
        return ;
    }
   
    
    /*���MacԴ��ַ*/
    printf("MacԴ��ַ:\t");
    mac_string = ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    /*���MacĿ�ĵ�ַ*/
    printf("MacĿ�ĵ�ַ:\t");
    mac_string = ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

 
    u_int  ip_header_length;    /*����*/

    //����IPv4Э��ͷ
    if (ethernet_type == 0x0800) {
        printf("�ϲ���IPV4Э�飬��������\n");
        struct ipv4_header* ip_protocol;   /*ipЭ�����*/
       
        u_int  offset;                   /*Ƭƫ��*/
        u_char  tos;                     /*��������*/
        u_int16_t checksum;    /*�ײ������*/
        ip_protocol = (struct ipv4_header*)(packet_content + ether_header_length); /*���ip���ݰ�������ȥ����̫ͷ��*/
        checksum = ntohs(ip_protocol->ip_checksum);      /*���У���*/
        ip_header_length = ip_protocol->ip_header_length * 4; /*��ó���*/
        tos = ip_protocol->ip_tos;    /*���tos*/
        offset = ntohs(ip_protocol->ip_off);   /*���ƫ����*/
        printf("\n##########    ����㣨IPЭ�飩    ########### \n");
        printf("IP�汾:\t\tIPv%d\n", ip_protocol->ip_version);
        printf("IPЭ���ײ�����:\t%d\n", ip_header_length);
        printf("��������:\t%d\n", tos);
        printf("�ܳ���:\t\t%d\n", ntohs(ip_protocol->ip_length));/*����ܳ���*/
        printf("��ʶ:\t\t%d\n", ntohs(ip_protocol->ip_id));  /*��ñ�ʶ*/
        printf("Ƭƫ��:\t\t%d\n", (offset & 0x1fff) * 8);    /**/
        printf("����ʱ��:\t%d\n", ip_protocol->ip_ttl);     /*���ttl*/
        printf("�ײ������:\t%d\n", checksum);
        printf("ԴIP:\t%s\n", inet_ntoa(ip_protocol->ip_source_address));          /*���Դip��ַ*/
        printf("Ŀ��IP:\t%s\n", inet_ntoa(ip_protocol->ip_destination_address));/*���Ŀ��ip��ַ*/
        printf("Э���:\t%d\n", ip_protocol->ip_protocol);         /*���Э������*/
        

        if (ip_protocol->ip_protocol != 17) {
            printf("�ϲ㲻��UDPֹͣ����\n");
            return;
        }
        printf("�ϲ���UDP��������\n");
    }

    //����IPv6Э��ͷ
    else if (ethernet_type == 0x86DD) {
        printf("�ϲ���IPV6Э�飬��������\n");
        struct ipv6_header* ipv6_hdr;   /*ipЭ�����*/
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
            printf("�ϲ㲻��UDPֹͣ����\n");
            return;
        };
        ip_header_length=40;
        
       
    }
    
    //����UDPЭ��ͷ

    struct udp_header* udp_protocol;
    u_short source_port;
    u_short destination_port;
    u_short length;
    const int udp_header_length = 8;
    udp_protocol = (struct udp_header*)(packet_content+ether_header_length+ ip_header_length);
    /* ��ȡUPDЭ������ */

    source_port = ntohs(udp_protocol->uh_sport);
    /* ��ȡԴ�˿� */

    destination_port = ntohs(udp_protocol->uh_dport);
    /* ��ȡĿ�Ķ˿� */

    length = ntohs(udp_protocol->uh_ulen);
    /* ��ȡ���� */

    printf("----------  UDPЭ���ײ�    ----------\n");
    printf("Դ�˿�:%d\n", source_port);
    printf("Ŀ�Ķ˿�:%d\n", destination_port);
    if (destination_port != 1701) {
        printf("Ŀ�Ķ˿ںŲ���1701��ֹͣ����\n");
        return;
    }
    
    printf("����:%d\n", length);
    printf("У���:%d\n", ntohs(udp_protocol->uh_sum));
    /* ��ȡУ��� */


    //����l2tpЭ��ͷ
    printf("Ŀ�Ķ˿ں���1701����������\n");


    l2tp_header* l2tp;
    int headerlength = 6;
    u_int16_t l2tp_length;
    u_int16_t tunnel_id;
    u_int16_t session_id;
    u_int16_t Ns;
    u_int16_t Nr;
    u_int16_t offset_size;

    // ָ��L2TPͷ��
    l2tp = (l2tp_header*)(packet_content+ether_header_length+ip_header_length+udp_header_length); // ��̫��ͷ������Ϊ14�ֽڣ�IPͷ������Ϊ20�ֽڣ�UDPͷ������Ϊ8�ֽ�

    printf("L2TP packet received:\n");
    printf("  �汾��: %d\n", l2tp->ver);
    bool type = l2tp->type;
    string stype = l2tp->type ? "������Ϣ" : "������Ϣ";
    printf("����: %s\n", stype);

    bool lengthin = l2tp->lengthin; //�������Ƿ���� 
    bool sequence = l2tp->sequence; //�������Ƿ����
    bool l2tp_offset = l2tp->offset; //ƫ�����Ƿ����
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
    printf("l2tpͷ�ܳ���: %d\n", headerlength);

    if (l2tp->type) {
        //����ǿ�����Ϣ��������l2tpͷ֮��ľ�Ӧ����message type ��avp
        //avp_protocol_packet_callback(packet_content + headerlength);
        printf("����һ�����ư�/n");
    }

    else {
        //�����������Ϣ��Ӧ�ü��ʣ����Ϣ�Ƿ���pppЭ�鿪ͷ
        printf("����һ�����ݰ�/n");
    }
}








/*void ppp_protocol_packet_callback(const u_char* packet_content) {
    ppp_header* ppp;

    ppp = (ppp_header*)(packet_content);

    if (ppp->flag == 0x7e && ppp->address == 0xff && ppp->control == 0x3c) {
        printf("ȷʵ��pppЭ��,��������");
        u_int16_t procotol = ntohs(ppp->procotol);
        if (procotol == 0x0021) {
            printf("pppЭ���װ��ipЭ��,��������");
            ip_protocol_packet_callback(packet_content + 5);
        }
        else {
            printf("pppЭ���в���ipЭ�飬ֹͣ����");
        }
    }
    else {
        printf("����pppЭ�飬ֹͣ����");
        return;
    }
}

void avp_protocol_packet_callback(const u_char* packet_content) {
    

    avp_header*  avp = (avp_header*)(packet_content);

    
}*/

