#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "Format.h"


// 单独创建此类来管理选定数据包


class DataPackage
{
private:
    u_int data_length; // 57、数据包长度
    QString timeStamp; // 58、数据包时间戳
    QString info;      // 59、数据包基础信息
    int packageType;   // 60、数据包类型

public:
    const u_char *pkt_content; // 61、定义指向内容的指针,，在鼠标点击对应一行后，会显示此行数据包内容

protected:
    // 62、将一个字节的数据转换为16进制
    static QString byteToHex(u_char*str,int size);
public:
    DataPackage();
    ~DataPackage() = default;

    // 63、设置对数据包内容进行操作的set成员函数
    void setDataLength(unsigned int length);
    void setTimeStamp(QString timeStamp);
    void setPackageType(int type);
    void setPackagePointer(const u_char *pkt_content,int size);
    void setPackageInfo(QString info);

    // 64、设置对数据包内容进行操作的get成员函数，设置为字符串类型是为了便于输出
    QString getDataLength();
    QString getTimeStamp();
    QString getPackageType();
    QString getInfo();

    // 134、定义source和destination
    QString getSource();
    QString getDestination();

    // 135、定义得到源ip源Mac和目的ip目的Mac的逻辑
    QString getDesMacAddr();
    QString getSrcMacAddr();

    // 139、上层封装协议
    QString getMacType();

    QString getDesIpAddr();
    QString getSrcIpAddr();
    QString getIpVersion();
    QString getIpHeaderLength();
    QString getIpTos();
    QString getIpTotalLength();
    QString getIpIdentification();
    QString getIpFlag();
    QString getIpReservedBit();
    QString getIpDF();
    QString getIpMF();
    QString getIpFragmentOffset();
    QString getIpTTL();
    QString getIpProtocol();
    QString getIpCheckSum();

    QString getIcmpType();
    QString getIcmpCode();
    QString getIcmpCheckSum();
    QString getIcmpIdentification();
    QString getIcmpSequeue();
    QString getIcmpData(int size);

    QString getArpHardwareType();
    QString getArpProtocolType();
    QString getArpHardwareLength();
    QString getArpProtocolLength();
    QString getArpOperationCode();
    QString getArpSourceEtherAddr();
    QString getArpSourceIpAddr();
    QString getArpDestinationEtherAddr();
    QString getArpDestinationIpAddr();

    QString getTcpSourcePort();
    QString getTcpDestinationPort();
    QString getTcpSequence();
    QString getTcpAcknowledgment();
    QString getTcpHeaderLength();
    QString getTcpRawHeaderLength();
    QString getTcpFlags();
    QString getTcpPSH();
    QString getTcpACK();
    QString getTcpSYN();
    QString getTcpURG();
    QString getTcpFIN();
    QString getTcpRST();
    QString getTcpWindowSize();
    QString getTcpCheckSum();
    QString getTcpUrgentPointer();
    QString getTcpOperationKind(int kind);
    int getTcpOperationRawKind(int offset);


    bool getTcpOperationMSS(int offset,u_short& mss);
    bool getTcpOperationWSOPT(int offset,u_char&shit);
    bool getTcpOperationSACKP(int offset);
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);

    QString getUdpSourcePort();
    QString getUdpDestinationPort();
    QString getUdpDataLength();
    QString getUdpCheckSum();

    QString getDnsTransactionId();
    QString getDnsFlags();
    QString getDnsFlagsQR();
    QString getDnsFlagsOpcode();
    QString getDnsFlagsAA();
    QString getDnsFlagsTC();
    QString getDnsFlagsRD();
    QString getDnsFlagsRA();
    QString getDnsFlagsZ();
    QString getDnsFlagsRcode();
    QString getDnsQuestionNumber();
    QString getDnsAnswerNumber();
    QString getDnsAuthorityNumber();
    QString getDnsAdditionalNumber();
    void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    QString getDnsDomainType(int type);
    QString getDnsDomainName(int offset);
    int getDnsAnswersDomain(int offset,QString&name1,u_short&Type,u_short& Class,u_int&ttl,u_short&dataLength,QString& name2);

    bool getisTlsProtocol(int offset);
    void getTlsBasicInfo(int offset,u_char&contentType,u_short&version,u_short&length);
    void getTlsClientHelloInfo(int offset,u_char&handShakeType,int& length,u_short&version,QString&random,u_char&sessionIdLength,QString&sessionId,u_short&cipherLength,QVector<u_short>&cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength);
    void getTlsServerHelloInfo(int offset,u_char&handShakeType,int&length,u_short&version,QString& random,u_char&sessionIdLength,QString&sessionId,u_short&cipherSuit,u_char&compressionMethod,u_short&extensionLength);
    void getTlsServerKeyExchange(int offset,u_char&handShakeType,int&length,u_char&curveType,u_short&curveName,u_char&pubLength,QString&pubKey,u_short&sigAlgorithm,u_short&sigLength,QString&sig);
    u_short getTlsExtensionType(int offset);
    void getTlsHandshakeType(int offset,u_char&type);





    void getTlsExtensionServerName(int offset,u_short&type,u_short&length,u_short&listLength,u_char&nameType,u_short&nameLength,QString& name);
    void getTlsExtensionSignatureAlgorithms(int offset,u_short&type,u_short&length,u_short&algorithmLength,QVector<u_short>&signatureAlgorithm);
    void getTlsExtensionSupportGroups(int offset,u_short&type,u_short&length,u_short&groupListLength,QVector<u_short>&group);
    void getTlsExtensionEcPointFormats(int offset,u_short&type,u_short&length,u_char& ecLength,QVector<u_char>&EC);
    void getTlsExtensionSessionTicket(int offset,u_short&type,u_short&length);
    void getTlsExtensionEncryptThenMac(int offset,u_short&type,u_short&length);
    void getTlsExtensionSupportVersions(int offset,u_short&type,u_short&length,u_char&supportLength,QVector<u_short>&supportVersion);
    void getTlsExtensionPskKeyExchangeModes(int offset,u_short&type,u_short&length,u_char&modeLength,QVector<u_char>&mode);
    void getTlsExtensionKeyShare(int offset,u_short&type,u_short&length,u_short&shareLength,u_short&group,u_short&exchangeLength,QString& exchange);
    void getTlsExtensionOther(int offset,u_short&type,u_short&length,QString& data);
    void getTlsExtensionExtendMasterSecret(int offset,u_short&type,u_short&length);
    void getTlsExtensionPadding(int offset,u_short&type,u_short&length,QString&data);


    static QString getTlsHandshakeType(int type);
    static QString getTlsContentType(int type);
    static QString getTlsVersion(int version);
    static QString getTlsHandshakeCipherSuites(u_short code);
    static QString getTlsHandshakeCompression(u_char code);
    static QString getTlsHandshakeExtension(u_short type);
    static QString getTlsHandshakeExtensionECPointFormat(u_char type);
    static QString getTlsHandshakeExtensionSupportGroup(u_short type);
    static QString getTlsHadshakeExtensionSignature(u_char type);
    static QString getTlsHadshakeExtensionHash(u_char type);

};

#endif
