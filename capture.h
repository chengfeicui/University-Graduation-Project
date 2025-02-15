#ifndef CAPTURE_H
#define CAPTURE_H

#include <QThread>
#include <Format.h>
#include <QQueue>
#include "pcap.h"
#include <QString>
#include "datapackage.h"

class Capture : public QThread
{
     Q_OBJECT
public:
    Capture();
    // 35、传具体的网卡的pointer参数
    bool setPointer(pcap_t *pointer);
    // 36、控制run函数开启(也就是isDone不成立)
    void setFlag();
    // 37、控制run函数关闭
    void resetFlag();
    // 76、从mac层开始解析数据
    int ethernetPackageHandle(const u_char *pkt_content,QString& info);
    // 89、解析IP数据
    int ipPackageHandle(const u_char *pkt_content,int&ipPackage);

    // 111、解析arp协议
    QString arpPackageHandle(const u_char *pkt_content);
    QString icmpPackageHandle(const u_char *pkt_content);
    // 93、解析TCP数据
    int tcpPackageHandle(const u_char *pkt_content,QString &info,int ipPackage);
    // 106、解析UDP
    int udpPackageHandle(const u_char *pkt_content,QString&info);
    QString dnsPackageHandle(const u_char *pkt_content);
protected:
    static QString byteToHex(u_char *str, int size);
    //34、开启多线程的run函数
    void run();

// 82、把datapackage类与主线程连接的是信号和槽，自定义信号发送者send
signals:
    void send(DataPackage data);

private:
    pcap_t *pointer; // 27、网卡设备描述符
    struct pcap_pkthdr*header; // 28、数据包头部结构
    const u_char *pkt_data; // 29、数据包内容
    time_t local_time_version_sec; // 30、原始时间
    struct tm local_time; // 31、转换后的时间戳格式
    char timeString[16]; // 32、时间戳字符串
    volatile bool isDone; // 33、定义开关判断线程是否结束（volatile防止线程数据被编译器优化）
};

#endif // CAPTURE_H
