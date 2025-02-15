#ifndef FORMAT_H
#define FORMAT_H
// 创建数据包格式，定义每种格式的结构体

// 54、一共有三种类型的长度，1字节，2字节，4字节，这里为了便于区分，用typedef
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

#define ARP  "ARP"
#define TCP  "TCP"
#define UDP  "UDP"
#define ICMP "ICMP"
#define DNS  "DNS"
#define TLS  "TLS"
#define SSL  "SSL"

// 55、Mac帧14个字节，分别为源地址（6）、目的地址（6）、类型（2）
typedef struct ether_header{
    u_char ether_des_host[6];
    u_char ether_src_host[6];
    u_short ether_type;
}ETHER_HEADER;


// 56、IP头部20个字节，分别为版本号（1）、头部长度（1）、TOS（1）、数据包长度（2）、标识（2）、标志位（2）、跳数（1）、协议(1)、头部校验和（2）、源IP地址（4）、目的IP地址（4）
typedef struct ip_header{
    u_char versiosn_head_length;
    u_char TOS;
    u_short total_length;
    u_short identification;
    u_short flag_offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int src_addr;
    u_int des_addr;
}IP_HEADER;


// 太多了，后面的就不写了


typedef struct tcp_header{
    u_short src_port;
    u_short des_port;
    u_int sequence;
    u_int ack;
    u_char header_length;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urgent;
}TCP_HEADER;


typedef struct udp_header{
    u_short src_port;
    u_short des_port;
    u_short data_length;
    u_short checksum;

}UDP_HEADER;


typedef struct icmp_header{
    u_char type;
    u_char code;
    u_short checksum;
    u_short identification;
    u_short sequence;
}ICMP_HEADER;


typedef struct arp_header{
    u_short hardware_type;
    u_short protocol_type;
    u_char mac_length;
    u_char ip_length;
    u_short op_code;

    u_char src_eth_addr[6];
    u_char src_ip_addr[4];
    u_char des_eth_addr[6];
    u_char des_ip_addr[4];

}ARP_HEADER;

typedef struct dns_header{
    u_short identification;
    u_short flags;
    u_short question;
    u_short answer;
    u_short authority;
    u_short additional;
}DNS_HEADER;

typedef struct dns_question{
    u_short query_type;
    u_short query_class;
}DNS_QUESITON;

typedef struct dns_answer{
    u_short answer_type;
    u_short answer_class;
    u_int TTL;
    u_short dataLength;
}DNS_ANSWER;

#endif


