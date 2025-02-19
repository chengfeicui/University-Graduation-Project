// 子线程

#include "capture.h"
#include <QDebug>
#include <QString>


Capture::Capture(){
    // 38、初始化多线程开关以及各类指针
    this->isDone = false;
    this->pointer = nullptr;
    this->header = nullptr;
    this->pkt_data = nullptr;
}

// 39、构造函数给设备描述符赋值，并判断设备描述符是否为空
bool Capture::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer)
        return true;
    else return false;
}

// 40、 控制run函数开启(也就是isDone不成立)
void Capture::setFlag(){
    this->isDone = true;
}

// 41、控制run函数关闭
void Capture::resetFlag(){
    this->isDone = false;
}

// 116、这里用到Mac地址，把之前datapackage里的转换函数拿来用一下
QString Capture::byteToHex(u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

// 42、重写开启多线程的run函数，本质是个死循环，一直处理数据包
void Capture::run(){
    unsigned int number_package = 0;
    // 43、通过setFlag和resetFlag控制死循环
    while(true){
        if(isDone)
            break;
        // 44、从已打开的网络设备中读取下一个数据包，此为主要抓包函数
        int res = pcap_next_ex(pointer,&header,&pkt_data);
        if(res == 0)
            continue;
        /*open pcap write output file*/
        pcap_dumper_t* out_pcap;
        // qDebug() << "1";
        out_pcap = pcap_dump_open(pointer, "/home/ccf/test.pcap");
        // qDebug() << "2";
        // 第一个参数是pcap_loop的最后一个参数，第二个参数是收到的数据包的pcap_pkthdr结构，第三个参数是数据包数据
        pcap_dump((u_char *)out_pcap, header, pkt_data);
        // qDebug() << "3";

        /*flush buff*/
        pcap_dump_flush(out_pcap);

        pcap_dump_close(out_pcap);
        // 45、获得时间信息
        local_time_version_sec = header->ts.tv_sec;
        localtime_r(&local_time_version_sec, &local_time);
        // 46、把时间信息转换为时分秒的格式
        strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);

        QString info = "";
        // 81、获取Mac帧的类型
        int type = ethernetPackageHandle(pkt_data,info);
        if(type){
            DataPackage data;
            int len = header->len;
            data.setPackageType(type);
            data.setTimeStamp(QString(timeString));
            data.setDataLength(len);
            data.setPackagePointer(pkt_data,len);
            data.setPackageInfo(info);
            // 87、用自定义信号发送者send把获取的Mac帧发送给槽函数
            if(data.pkt_content != nullptr){
                emit send(data);
                number_package++;
            }else continue;
        }
        else continue;
    }
    return;
}



//77、从mac层开始解析数据
int Capture::ethernetPackageHandle(const u_char *pkt_content,QString& info){
    // 78、通过自定义的结构体定义指向当前数据包的指针
    ETHER_HEADER* ethernet;
    u_short ethernet_type;
    ethernet = (ETHER_HEADER*)pkt_content;
    // 79、以主机字节顺序返回值，而不是网络字节顺序
    ethernet_type = ntohs(ethernet->ether_type);

    // 80、从捕获的Mac帧的type字段来分析，0x0800上层封装是ip数据包，0x0806上层封装是arp数据包
    switch(ethernet_type){
    case 0x0800:{
        int dataPackage = 0;
        // 119、取出协议字段的值，来看一看上层封装那些协议
        int res = ipPackageHandle(pkt_content,dataPackage);
        // 120、值为1，则封装了ICMP协议，值为6，则封装了tcp协议，值为17，则封装了udp协议，最终都返回在datapackage定义的不同类型的值
        switch (res) {
        case 1:{// icmp package
            info = icmpPackageHandle(pkt_content);
            return 2;
        }
        case 6:{// tcp package
            return tcpPackageHandle(pkt_content,info,dataPackage);

        }
        case 17:{ // udp package
            int type = udpPackageHandle(pkt_content,info);
            return type;
        }
        default:break;
        }
        break;
    }
    case 0x0806:{
        info = arpPackageHandle(pkt_content);
        return 1;
    }
    default:{
        break;
    }
    }
    return 0;
}

//90、解析IP数据
int Capture::ipPackageHandle(const u_char *pkt_content,int& ipPackage){
    IP_HEADER* ip;
    // 91、跳过Mac层头部的14字节去强转类型
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    // 92、计算除了IP以外的数据包长度，以主机字节顺序返回值，而不是网络字节顺序
    ipPackage = (htons(ip->total_length) - (ip->versiosn_head_length & 0x0F) * 4);
    return protocol;
}

QString Capture::icmpPackageHandle(const u_char *pkt_content){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 20 + 14);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString result = "";
    switch (type) {
    case 0:{
        if(!code)
            result = "Echo response (ping)";
        break;
    }
    case 3:{
        switch (code) {
        case 0:{
            result = "Network unreachable";
            break;
        }
        case 1:{
            result = "Host unreachable";
            break;
        }
        case 2:{
            result = "Protocol unreachable";
            break;
        }
        case 3:{
            result = "Port unreachable";
            break;
        }
        case 4:{
            result = "Fragmentation is required, but DF is set";
            break;
        }
        case 5:{
            result = "Source route selection failed";
            break;
        }
        case 6:{
            result = "Unknown target network";
            break;
        }
        default:break;
        }
        break;
    }
    case 4:{
        result = "Source station suppression [congestion control]";
        break;
    }
    case 5:{
        result = "Relocation";
        break;
    }
    case 8:{
        if(!code)
            result = "Echo request (ping)";
        break;
    }
    default:break;
    }
    return result;
}

// 94、解析TCP数据
int Capture::tcpPackageHandle(const u_char *pkt_content,QString &info,int ipPackage){
    TCP_HEADER*tcp;
    // 95、跳过Mac层头部的14字节和IP层头部的20字节去强转类型
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);

    // 96、定义几个信息，用于最终界面的显示

    // 97、源地址、目的地址
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);
    QString proSend = "";
    QString proRecv = "";

    // 98、在datapackage中定义的tcp的类型是3
    int type = 3;

    // 99、TCP的头部不总为20字节，包含可选项
    int delta = (tcp->header_length >> 4) * 4;

    // 100、tcp的包内容为IP的包内容减去tcp头部的内容
    int tcpPayLoad = ipPackage - delta;

    // 101、如果源端口或目的端口为443，那么就是https协议
    if((src == 443 || des == 443) && (tcpPayLoad > 0)){
        if(src == 443)
            proSend = "(https)";
        else proRecv = "(https)";
        u_char *ssl;
        ssl = (u_char*)(pkt_content + 14 + 20 + delta);
        u_char isTls = *(ssl);
        ssl++;
        u_short*pointer = (u_short*)(ssl);
        u_short version = ntohs(*pointer);
        if(isTls >= 20 && isTls <= 23 && version >= 0x0301 && version <= 0x0304){
            type = 6;
            switch(isTls){
            case 20:{
                info = "Change Cipher Spec";
                break;
            }
            case 21:{
                info = "Alert";
                break;
            }
            case 22:{
                info = "Handshake";
                ssl += 4;
                u_char type = (*ssl);
                switch (type) {
                case 1: {
                    info += " Client Hello";
                    break;
                }
                case 2: {
                    info += " Server hello";
                    break;
                }
                case 4: {
                    info += " New Session Ticket";
                    break;
                }
                case 11:{
                    info += " Certificate";
                    break;
                }
                case 16:{
                    info += " Client Key Exchange";
                    break;
                }
                case 12:{
                    info += " Server Key Exchange";
                    break;
                }
                case 14:{
                    info += " Server Hello Done";
                    break;
                }
                default:break;
                }
                break;
            }
            case 23:{
                info = "Application Data";
                break;
            }
            default:{
                break;
            }
            }
            return type;
        }else type = 7;
    }

    if((src == 80 || des == 80 || src == 8080 || des == 8080 || src == 3128 || des == 3128 || src == 8081 || des == 8081 || src == 9098 || des == 9098) && (tcpPayLoad > 0)){
        if(src == 80 || src == 8080 || src == 3128 || src == 8081 || src == 9098)
            proSend = "(http)";
        else proRecv = "(http)";

    }

    if(type == 7){
        info = "Continuation Data";
    }



    // 102、如果不是上述协议，就是源端口发送给目的端口
    else{
        info += QString::number(src) + proSend+ "->" + QString::number(des) + proRecv;
        QString flag = "";
        // 103、通过位运算判断标志位是否置位
        if(tcp->flags & 0x08) flag += "PSH,";
        if(tcp->flags & 0x10) flag += "ACK,";
        if(tcp->flags & 0x02) flag += "SYN,";
        if(tcp->flags & 0x20) flag += "URG,";
        if(tcp->flags & 0x01) flag += "FIN,";
        if(tcp->flags & 0x04) flag += "RST,";
        // 104、如果位运算都不是，那么就去掉额外添加的逗号
        if(flag != ""){
            flag = flag.left(flag.length()-1);
            info += " [" + flag + "]";
        }

        // 105、面板显示窗口大小，序列号之类的字段
        u_int sequeue = ntohl(tcp->sequence);
        u_int ack = ntohl(tcp->ack);
        u_short window = ntohs(tcp->window_size);
        info += " Seq=" + QString::number(sequeue) + " Ack=" + QString::number(ack) + " win=" + QString::number(window) + " Len=" + QString::number(tcpPayLoad);
    }
    return type;
}

// 107、解析UDP
int Capture::udpPackageHandle(const u_char *pkt_content,QString&info){
    UDP_HEADER * udp;

    // 108、跳过Mac层头部的14字节和IP层头部的20字节去强转类型
    udp = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short desPort = ntohs(udp->des_port);
    u_short srcPort = ntohs(udp->src_port);

    // 109、如果端口为53，则返回在datapackage定义的UDP的位置5
    if(desPort == 53){
        info =  dnsPackageHandle(pkt_content);
        return 5;
    }
    else if(srcPort == 53){
        info =  dnsPackageHandle(pkt_content);
        return 5;
    }
    else{
        // 110、源端口发送给目的端口
        QString res = QString::number(srcPort) + "->" + QString::number(desPort);
        res += " len=" + QString::number(ntohs(udp->data_length));
        info = res;
        return 4;
    }
}

// 112、解析arp协议
QString Capture::arpPackageHandle(const u_char *pkt_content){
    ARP_HEADER*arp;

    // 113、arp封在Mac帧，所以和IP是一个层级，只+14强转
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_short op = ntohs(arp->op_code);
    QString res = "";
    u_char*addr = arp->des_ip_addr;

    // 114、把目的IP转为字符串
    QString desIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    // 115、把源IP转为字符串
    addr = arp->src_ip_addr;
    QString srcIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    // 117、把Mac地址转为字符串
    u_char* srcEthTemp = arp->src_eth_addr;
    QString srcEth = byteToHex(srcEthTemp,1) + ":"
            + byteToHex((srcEthTemp+1),1) + ":"
            + byteToHex((srcEthTemp+2),1) + ":"
            + byteToHex((srcEthTemp+3),1) + ":"
            + byteToHex((srcEthTemp+4),1) + ":"
            + byteToHex((srcEthTemp+5),1);

    // 118、操作码判断，操作码1为询问字段，操作码2为应答字段
    switch (op){
    case 1:{
        res  = "Who has " + desIp + "? Tell " + srcIp;
        break;
    }
    case 2:{
        res = srcIp + " is at " + srcEth;
        break;
    }
    default:break;
    }
    return res;
}

QString Capture::dnsPackageHandle(const u_char *pkt_content){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    u_short identification = ntohs(dns->identification);
    u_short type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "Standard query ";
    }
    else if((type & 0xf800) == 0x8000){
        info = "Standard query response ";
    }
    QString name = "";
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    name = name.left(name.length()-1);
    return info + "0x" + QString::number(identification,16) + " " + name;
}
