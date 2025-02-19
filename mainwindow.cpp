// 主线程

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"
#include <QDebug>
#include "capture.h"
#include <QStringList>
#include <QColor>
#include <QMessageBox>
#include <QTreeWidgetItem>
#include <QStringList>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // 121、初始化GUI界面
    statusBar()->showMessage("welcome to shark!");
    // 122、把菜单栏显示到工具栏
    ui->toolBar->addAction(ui->actionstart_capture);
    ui->toolBar->addAction(ui->actionclear_all);
    ui->toolBar->addAction(ui->actionup);
    ui->toolBar->addAction(ui->actiondown);
    ui->toolBar->addAction(ui->actionTop);
    ui->toolBar->addAction(ui->actionEnd);
    // 13、使用函数测试输出网卡设备
    showNetworkCard();
    // 47、创建multhread类的实例化变量，不在对象树上，和主线程分离
    Capture *thread = new Capture;
    ui->comboBox->setEnabled(true);
    isStart = false;
    // 23、点击"开始"按钮，使左下角输出当前选中的网卡，但不是"开始"按钮的全部功能

    // 24、设置一个开关来区分"开始"和"暂停"
    static bool index = false;
    countNumber = 0;
    rowNumber = -1;
    data.clear();
    device = nullptr;
    pointer = nullptr;

    // 25、获取由QAction::triggered传递的"点击"信号后，根据index开关设置不同回应的自定义槽函数，这里槽函数使用的是拉姆达表达式
    connect(ui->actionstart_capture,&QAction::triggered,this,[=]{
        // 26、开始设置的false，后来用了"!"，所以现在是true，这时候就是开，使用capture()
        index = !index;
        if(index){
            if(ui->tableWidget->rowCount()){
                int type = QMessageBox::information(NULL,"information","Before restarting do you want to save result?","Save","Continue","Cancel");
                if(type == 0)
                {
                    // wuxiao_save

                }else if(type == 1){
                    qDebug()<<"not save";
                }else{
                    index = !index;
                    isStart = false;
                    return;
                }
            }

            // 131、清空内容，不会影响下一次新的捕获
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            ui->treeWidget->clear();
            countNumber = 0;
            rowNumber = -1;

            // 132、设置一个循环，逐次释放掉在datapackage中，通过memorycopy申请的指针定义一个空的vector，和准备释放的空间进行交换
            int dataSize = this->data.size();
            for(int i = 0;i < dataSize;i++){
                free((char*)(this->data[i].pkt_content));
                this->data[i].pkt_content = nullptr;
            }

            // 133、和空的容器进行交换是真的释放内存，clear函数不是
            QVector<DataPackage>().swap(data);
            int res = capture();
            // 48、抓包函数有效，则点击开始启动子线程
            if(pointer && res != -1){

                thread->resetFlag();
                thread->setPointer(pointer);
                // 49、在没有暂停之前，不可随意更改网卡
                ui->comboBox->setEnabled(false);
                thread->start();
                // 50、点击开始之后，会由开始图片变成暂停图片
                ui->actionstart_capture->setIcon(QIcon(":/stop.png"));
                countNumber = 0;
                isStart = true;
            }else{
                index = !index;
                countNumber = 0;
                rowNumber = -1;
                isStart = false;
            }
        }else{
            // 51、子线程结束
            thread->setFlag();
            // 52、把combox改成可编辑的状态
            ui->comboBox->setEnabled(true);
            thread->quit();
            thread->wait();
            pcap_close(pointer);
            // 53、把图标改回来
            ui->actionstart_capture->setIcon(QIcon(":/start.png"));
            isStart = false;
        }
    });

    connect(ui->actionclear_all,&QAction::triggered,this,[=]{
        if(!isStart){
            int type = QMessageBox::information(this,"information","Do you want to clear all?","Yes","Cancel");
            if(type == 0){
                ui->tableWidget->clearContents();
                ui->tableWidget->setRowCount(0);
                ui->treeWidget->clear();
                countNumber = 0;
                rowNumber = -1;
                int dataSize = this->data.size();
                for(int i = 0;i < dataSize;i++){
                    free((char*)(this->data[i].pkt_content));
                    this->data[i].pkt_content = nullptr;
                }
                QVector<DataPackage>().swap(data);
            }else return;
        }
    });

    connect(ui->actionup,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(index - 1,0);
            on_tableWidget_cellClicked(index - 1,0);
        }else return;
    });

    connect(ui->actiondown,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index >= 0 && index < ui->tableWidget->rowCount() - 1){
            ui->tableWidget->setCurrentCell(index + 1,0);
            on_tableWidget_cellClicked(index + 1,0);
        }else return;
    });

    connect(ui->actionTop,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(0,0);
            on_tableWidget_cellClicked(0,0);
        }else return;
    });

    connect(ui->actionEnd,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->rowCount() - 1;
        if(index > 0){
            ui->tableWidget->setCurrentCell(index,0);
            on_tableWidget_cellClicked(index,0);
        }
    });

    // 86、将自定义的发送信号的函数sent、自定义的槽函数handleMessage连接起来
    connect(thread,&Capture::send,this,&MainWindow::handleMessage);

    ui->tableWidget->setShowGrid(false);
    // 123、下面都是设置GUI界面属性
    ui->toolBar->setMovable(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    // 125、设置列数，并调整宽度
    ui->tableWidget->setColumnCount(7);
    readOnlyDelegate = new ReadOnlyDelegate();
    ui->tableWidget->setItemDelegate(readOnlyDelegate);
    // 124、第一列是顺序，第二列是时间戳，第三列是源地址，第四列是目的地址，第五列是协议，第六列是数据包长度，第七列是信息字段
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);

    // 133、选中一行
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);
}


MainWindow::~MainWindow()
{
    int dataSize = this->data.size();
    for(int i = 0;i<dataSize;i++){
        free((char*)(this->data[i].pkt_content));
        this->data[i].pkt_content = nullptr;
    }
    QVector<DataPackage>().swap(data);
    delete readOnlyDelegate;
    delete ui;
}



// 6、实现mainWindow.h里定义的测试网卡的成员函数
void MainWindow::showNetworkCard(){
    // 7、获取所有的网卡
    int n = pcap_fin'
            Zdalldevs(&all_devices,errbuf);
    ui->comboBox->clear();
    // 8、若获取失败，前端comboBOX就显示错误信息
    if(n == -1){
        statusBar()->showMessage("There is something wrong" + QString(errbuf));
        ui->comboBox->addItem("Cannot find a matching network card, please restart and test");
        return;
    }
    // 9、若获取成功，就把网卡的名字逐个添加到前端comboBOX里
    ui->comboBox->clear();
    // 10、第一行为提示选择一张网卡
    ui->comboBox->addItem("please chose the Network Card!");
    // 11、遍历所有网卡，存储于以all_device为头结点的链表里
    for(device = all_devices;device!= nullptr;device = device->next){
        // 12、把网卡设备的名字和描述符两个字符串加起来并输出到comboBOX
        QString device_name = device->name;
        device_name.replace("\\Device\\","");
        QString device_description = device->description;
        QString item = device_name + "   " + device_description;
        ui->comboBox->addItem(item);
    }
}


// 14、利用槽函数(这里槽函数作为普通函数使用)让device获得选择的网卡的信号，index是网卡在栏目里的位置，为下面遍历做准备
void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    // 15、等于0则槽函数未获取信息，也就是没有点击网卡进行选择，不等于0则把device指向鼠标选中的网卡设备
    if(index!=0){
        for(device = all_devices;i<index - 1;i++,device = device->next);
    }else{
        device = nullptr;
    }
    return;
}


// 17、抓包函数编写
int MainWindow::capture(){
    // 18、如果device为空，则证明16步的打开是有问题的，不为空则用pointer去接收指向设备的描述符
    // pcap_t * pcap_open_live(char*device,int snaplen,int promisc,int to_ms,char*errbuf);
    if(device)
        // 19、设置数据包捕获长度为65536，混杂模式打开
        pointer = pcap_open_live(device->name,65536,1,1000,errbuf);
    else{
        statusBar()->showMessage("pls choose Network Card!");
        return -1;
    }
    // 20、获取失败则释放device指针
    if(!pointer){
        statusBar()->showMessage(errbuf);
        pcap_freealldevs(all_devices);
        device = nullptr;
        return -1;
    }else{
        // 21、设备可正常工作,则判断捕获的数据包是否为DLT_EN10MB主流数据包的宏，如果不是，则此网卡不能工作，释放所有指针！
        if(pcap_datalink(pointer) != DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            return -1;
        }
        // 22、设置状态栏用来显示具体是哪个网卡在工作
        statusBar()->showMessage(device->name);
    }
    return 0;
}

// 85、实现自定义的槽函数
void MainWindow::handleMessage(DataPackage data){
    // 126、让槽函数处理一个数据包
    ui->tableWidget->insertRow(countNumber);
    this->data.push_back(data);

    // 127、获取数据包类型
    QString type = data.getPackageType();

    // 128、对不同的数据包类型显示不同的颜色
    QColor color;
    if(type == TCP){
        color = QColor(216,191,216);
    }else if(type == TCP){
        color = QColor(144,238,144);
    }
    else if(type == ARP){
        color = QColor(238,238,0);
    }
    else if(type == DNS){
        color = QColor(255,255,224);
    }else if(type == TLS || type == SSL){
        color = QColor(210,149,210);
    }else{
        color = QColor(255,218,185);
    }

    // 129、插入7个单元格元素，分别对应之前定义的表格的序号时间戳等等
    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber + 1)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));

    // 130、把颜色填入对应单元格
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(countNumber,i)->setBackground(color);
    }
    countNumber++;
}

// 138、鼠标选中行
void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if(rowNumber == row || row < 0){
        return;
    }else{
        // 139、点击成功后，清空treeWidget，为显示当前行做好准备
        ui->treeWidget->clear();
        rowNumber = row;
        if(rowNumber < 0 || rowNumber > data.size())
            return;
        QString desMac = data[rowNumber].getDesMacAddr();
        QString srcMac = data[rowNumber].getSrcMacAddr();
        QString type = data[rowNumber].getMacType();
        QString tree1 = "Ethernet, Src:" +srcMac + ", Dst:" + desMac;
        // 140、定义树形结构
        QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<tree1);

        // 141、定义顶层
        ui->treeWidget->addTopLevelItem(item);

        // 142、 把孩子嵌套进去
        item->addChild(new QTreeWidgetItem(QStringList()<<"Destination:" + desMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Source:" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type));

        QString packageType = data[rowNumber].getPackageType();
        // arp package analysis
        if(packageType == ARP){
            QString ArpType = data[rowNumber].getArpOperationCode();
            QTreeWidgetItem*item2 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol " + ArpType);
            ui->treeWidget->addTopLevelItem(item2);
            QString HardwareType = data[rowNumber].getArpHardwareType();
            QString protocolType = data[rowNumber].getArpProtocolType();
            QString HardwareSize = data[rowNumber].getArpHardwareLength();
            QString protocolSize = data[rowNumber].getArpProtocolLength();
            QString srcMacAddr = data[rowNumber].getArpSourceEtherAddr();
            QString desMacAddr = data[rowNumber].getArpDestinationEtherAddr();
            QString srcIpAddr = data[rowNumber].getArpSourceIpAddr();
            QString desIpAddr = data[rowNumber].getArpDestinationIpAddr();

            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:" + HardwareType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:" + protocolType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:" + HardwareSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:" + protocolSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:" + ArpType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:" + srcMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:" + srcIpAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:" + desMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:" + desIpAddr));
            return;
        }else { // ip package analysis
            QString srcIp = data[rowNumber].getSrcIpAddr();
            QString desIp = data[rowNumber].getDesIpAddr();

            QTreeWidgetItem*item3 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:" + srcIp + ", Dst:" + desIp);
            ui->treeWidget->addTopLevelItem(item3);

            QString version = data[rowNumber].getIpVersion();
            QString headerLength = data[rowNumber].getIpHeaderLength();
            QString Tos = data[rowNumber].getIpTos();
            QString totalLength = data[rowNumber].getIpTotalLength();
            QString id = "0x" + data[rowNumber].getIpIdentification();
            QString flags = data[rowNumber].getIpFlag();
            if(flags.size()<2)
                flags = "0" + flags;
            flags = "0x" + flags;
            QString FragmentOffset = data[rowNumber].getIpFragmentOffset();
            QString ttl = data[rowNumber].getIpTTL();
            QString protocol = data[rowNumber].getIpProtocol();
            QString checksum = "0x" + data[rowNumber].getIpCheckSum();
            int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
            item3->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version:" + version));
            item3->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length:" + headerLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + totalLength));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + id));

            QString reservedBit = data[rowNumber].getIpReservedBit();
            QString DF = data[rowNumber].getIpDF();
            QString MF = data[rowNumber].getIpMF();
            QString FLAG = ",";

            if(reservedBit == "1"){
                FLAG += "Reserved bit";
            }
            else if(DF == "1"){
                FLAG += "Don't fragment";
            }
            else if(MF == "1"){
                FLAG += "More fragment";
            }
            if(FLAG.size() == 1)
                FLAG = "";
            QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
            item3->addChild(bitTree);
            QString temp = reservedBit == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:" + temp));
            temp = DF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
            temp = MF == "1"?"Set":"Not set";
            bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

            item3->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset:" + FragmentOffset));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live:" + ttl));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Protocol:" + protocol));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:" + srcIp));
            item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:" + desIp));

            if(packageType == TCP || packageType == TLS || packageType == SSL){
                QString desPort = data[rowNumber].getTcpDestinationPort();
                QString srcPort = data[rowNumber].getTcpSourcePort();
                QString ack = data[rowNumber].getTcpAcknowledgment();
                QString seq = data[rowNumber].getTcpSequence();
                QString headerLength = data[rowNumber].getTcpHeaderLength();
                int rawLength = data[rowNumber].getTcpRawHeaderLength().toUtf8().toInt();
                dataLengthofIp -= (rawLength * 4);
                QString dataLength = QString::number(dataLengthofIp);
                QString flag = data[rowNumber].getTcpFlags();
                while(flag.size()<2)
                    flag = "0" + flag;
                flag = "0x" + flag;
                QTreeWidgetItem*item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

                ui->treeWidget->addTopLevelItem(item4);
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) :" + seq));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) :" + ack));


                QString sLength = QString::number(rawLength,2);
                while(sLength.size()<4)
                    sLength = "0" + sLength;
                item4->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Header Length:" + headerLength));

                QString PSH = data[rowNumber].getTcpPSH();
                QString URG = data[rowNumber].getTcpURG();
                QString ACK = data[rowNumber].getTcpACK();
                QString RST = data[rowNumber].getTcpRST();
                QString SYN = data[rowNumber].getTcpSYN();
                QString FIN = data[rowNumber].getTcpFIN();
                QString FLAG = "";

                if(PSH == "1")
                    FLAG += "PSH,";
                if(URG == "1")
                    FLAG += "UGR,";
                if(ACK == "1")
                    FLAG += "ACK,";
                if(RST == "1")
                    FLAG += "RST,";
                if(SYN == "1")
                    FLAG += "SYN,";
                if(FIN == "1")
                    FLAG += "FIN,";
                FLAG = FLAG.left(FLAG.length()-1);
                if(SYN == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
                }
                if(SYN == "1" && ACK == "1"){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
                }
                QTreeWidgetItem*flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flag + " (" + FLAG + ")");
                item4->addChild(flagTree);
                QString temp = URG == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
                temp = ACK == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
                temp = PSH == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
                temp = RST == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
                temp = SYN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
                temp = FIN == "1"?"Set":"Not set";
                flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));

                QString window = data[rowNumber].getTcpWindowSize();
                QString checksum = "0x" + data[rowNumber].getTcpCheckSum();
                QString urgent = data[rowNumber].getTcpUrgentPointer();
                item4->addChild(new QTreeWidgetItem(QStringList()<<"window:" + window));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
                item4->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:" + urgent));
                if((rawLength * 4) > 20){
                    QTreeWidgetItem * optionTree = new QTreeWidgetItem(QStringList()<<"Options: (" + QString::number(rawLength * 4 - 20) + ") bytes");
                    item4->addChild(optionTree);
                    for(int j = 0;j < (rawLength * 4 - 20);){
                        int kind = data[rowNumber].getTcpOperationRawKind(j);
                        switch (kind) {
                        case 0:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - End of List (EOL)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind:End of List (0)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }case 1:{
                            QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - No-Operation (NOP)");
                            optionTree->addChild(subTree);
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: No-Operation (1)"));
                            optionTree->addChild(subTree);
                            j++;
                            break;
                        }
                        case 2:{
                            u_short mss;
                            if(data[rowNumber].getTcpOperationMSS(j,mss)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Maximun Segment Size: " + QString::number(mss) + " bytes");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Maximun Segment Size (2)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 4"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"MSS Value: " + QString::number(mss)));
                                j += 4;
                            }
                            break;
                        }
                        case 3:{
                            u_char shift;
                            if(data[rowNumber].getTcpOperationWSOPT(j,shift)){
                                int factor = 1 << shift;
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Window scale: " + QString::number(shift) + " (multiply by " + QString::number(factor) + ")");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Window scale (3)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 3"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Shift Count: " + QString::number(shift)));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"[Multiplier: " + QString::number(factor) + "]"));
                                j += 3;
                            }
                            break;
                        }
                        case 4:{
                            if(data[rowNumber].getTcpOperationSACKP(j)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK Permitted");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK Permitted (4)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 2"));
                                j += 2;
                            }
                            break;
                        }
                        case 5:{
                            u_char length = 0;
                            QVector<u_int>edge;
                            if(data[rowNumber].getTcpOperationSACK(j,length,edge)){
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK");
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK (5)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(length)));
                                int num = edge.size();
                                for(int k = 0;k < num;k += 2){
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"left edge = " + QString::number(edge[k])));
                                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"right edge = " + QString::number(edge[k + 1])));
                                }
                                j += length;
                            }
                            break;
                        }
                        case 8:{
                            u_int value = 0;
                            u_int reply = 0;
                            if(data[rowNumber].getTcpOperationTSPOT(j,value,reply)){
                                QString val = QString::number(value);
                                QString rep = QString::number(reply);
                                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - TimeStamps: TSval " +val + ", TSecr " + rep);
                                optionTree->addChild(subTree);
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: Time Stamp Option (8)"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 10"));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp value: " + val));
                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp echo reply: " + rep));
                                j += 10;
                            }
                            break;
                        }
                        case 19:{
                            j += 18;
                            break;
                        }
                        case 28:{
                            j += 4;
                            break;
                        }
                        default:{
                            j++;
                            break;
                        }
                        }
                    }
                }
                if(dataLengthofIp > 0){
                    item4->addChild(new QTreeWidgetItem(QStringList()<<"TCP Payload (" + QString::number(dataLengthofIp) + ")"));
                    if(packageType == TLS){
                        QTreeWidgetItem* tlsTree = new QTreeWidgetItem(QStringList()<<"Transport Layer Security");
                        ui->treeWidget->addTopLevelItem(tlsTree);
                        u_char contentType = 0;
                        u_short version = 0;
                        u_short length = 0;
                        data[rowNumber].getTlsBasicInfo((rawLength * 4),contentType,version,length);
                        QString type = data[rowNumber].getTlsContentType(contentType);
                        QString vs = data[rowNumber].getTlsVersion(version);
                        switch (contentType) {
                        case 20:{
                            // ... TODO
                            break;
                        }
                        case 21:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: Encrypted Alert");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Alert Message: Encrypted Alert"));
                            break;
                        }
                        case 22:{ // handshake
                            u_char handshakeType = 0;
                            data[rowNumber].getTlsHandshakeType((rawLength * 4 + 5),handshakeType);
                            if(handshakeType == 1){ // client hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipherLength = 0;
                                QVector<u_short>cipher;
                                u_char cmLength = 0;
                                QVector<u_char>compressionMethod;
                                u_short extensionLength = 0;
                                data[rowNumber].getTlsClientHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipherLength,cipher,cmLength,compressionMethod,extensionLength);

                                QString type = data[rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = data[rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites Length: " + QString::number(cipherLength)));
                                if(cipherLength > 0){
                                    QTreeWidgetItem* cipherTree = new QTreeWidgetItem(QStringList()<<"Cipher Suites (" + QString::number(cipherLength/2) + " suites)");
                                    handshakeTree->addChild(cipherTree);
                                    for(int k = 0;k < cipherLength/2;k++){
                                        QString temp = data[rowNumber].getTlsHandshakeCipherSuites(cipher[k]);
                                        cipherTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suite: " + temp));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Method Length: " + QString::number(cmLength)));
                                if(cmLength > 0){
                                    QTreeWidgetItem* cmTree = new QTreeWidgetItem(QStringList()<<"Compression Methods (" + QString::number(cmLength) + " method)");
                                    handshakeTree->addChild(cmTree);
                                    for(int k = 0;k < cmLength;k++){
                                        QString temp = data[rowNumber].getTlsHandshakeCompression(compressionMethod[k]);
                                        cmTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod[k]) + ")"));
                                    }
                                }
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = data[rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            data[rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            data[rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            data[rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            data[rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            data[rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            data[rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            data[rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = data[rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = data[rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            data[rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = data[rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            data[rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }
                            }
                            else if(handshakeType == 2){// Server hello
                                int tlsLength = 0;
                                u_short rawVersion = 0;
                                QString random = "";
                                u_char sessionLength = 0;
                                QString sessionId = "";
                                u_short cipher = 0;
                                u_char compressionMethod = 0;
                                u_short extensionLength = 0;
                                data[rowNumber].getTlsServerHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipher,compressionMethod,extensionLength);
                                QString type = data[rowNumber].getTlsHandshakeType(handshakeType);
                                QString tlsVersion = data[rowNumber].getTlsVersion(rawVersion);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion,16) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
                                if(sessionLength > 0){
                                    handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
                                }
                                QString temp = data[rowNumber].getTlsHandshakeCipherSuites(cipher);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites: " +temp));
                                temp = data[rowNumber].getTlsHandshakeCompression(compressionMethod);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
                                if(extensionLength > 0){
                                    int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                                    for(int k = 0;k < extensionLength;){
                                        int code = data[rowNumber].getTlsExtensionType(exOffset);
                                        u_short exType = 0;
                                        u_short exLength = 0;
                                        switch (code) {
                                        case 0:{ // server_name
                                            u_short listLength = 0;
                                            u_char nameType = 0;
                                            u_short nameLength = 0;
                                            QString name = "";
                                            data[rowNumber].getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            if(exLength > 0 && listLength > 0){
                                                QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                                                extensionTree->addChild(serverTree);
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                                                serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                                            }
                                            break;
                                        }
                                        case 11:{// ec_point_format
                                            u_char ecLength = 0;
                                            QVector<u_char>EC;
                                            data[rowNumber].getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                                            QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                                            extensionTree->addChild(EXTree);
                                            for(int g = 0;g < ecLength;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionECPointFormat(EC[g]);
                                                EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                                            }
                                            break;
                                        }
                                        case 10:{// supported_groups
                                            u_short groupListLength = 0;
                                            QVector<u_short>group;
                                            data[rowNumber].getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                                            QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                                            extensionTree->addChild(sptTree);
                                            for(int g = 0;g < groupListLength/2;g++){
                                                QString temp = data[rowNumber].getTlsHandshakeExtensionSupportGroup(group[g]);
                                                sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                                            }
                                            break;
                                        }
                                        case 35:{// session_ticket
                                            data[rowNumber].getTlsExtensionSessionTicket(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 22:{// encrypt_then_mac
                                            data[rowNumber].getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 23:{// extended_master_secret
                                            data[rowNumber].getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            break;
                                        }
                                        case 13:{// signature_algorithms
                                            u_short algorithmLength = 0;
                                            QVector<u_short>algorithm;
                                            data[rowNumber].getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                                            QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                                            extensionTree->addChild(sigTree);
                                            for(int g = 0;g < algorithmLength/2;g++){
                                                QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                                                sigTree->addChild(subTree);
                                                QString hash = data[rowNumber].getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                                                QString sig = data[rowNumber].getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                                                subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                                            }
                                            break;
                                        }
                                        case 43:{// supported_versions
                                            u_char supportLength = 0;
                                            QVector<u_short>supportVersion;
                                            data[rowNumber].getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                                            for(int g = 0;g < supportLength/2;g++){
                                                QString temp = data[rowNumber].getTlsVersion(supportVersion[g]);
                                                extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                                            }
                                            break;
                                        }
                                        case 51:{// key_share
                                            u_short shareLength = 0;
                                            u_short group = 0;
                                            u_short exchangeLength = 0;
                                            QString exchange = "";
                                            data[rowNumber].getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                                            extensionTree->addChild(subTree);
                                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                                            QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                                            subTree->addChild(entryTree);
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                                            entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                                            break;
                                        }
                                        case 21:{// padding
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                                            break;
                                        }
                                        default:{
                                            QString rdata = "";
                                            data[rowNumber].getTlsExtensionOther(exOffset,exType,exLength,rdata);
                                            QString subType = data[rowNumber].getTlsHandshakeExtension(exType);
                                            QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                                            handshakeTree->addChild(extensionTree);
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                                            break;
                                        }
                                        }
                                        k += (exLength + 4);
                                        exOffset += (exLength + 4);
                                    }
                                }

                            }
                            else if(handshakeType == 12){// Server Key Exchange
                                int tlsLength = 0;
                                u_char curveType = 0;
                                u_short curveName = 0;
                                u_char pubLength = 0;
                                QString pubKey = "";
                                u_short sigAlgorithm = 0;
                                u_short sigLength = 0;
                                QString sig = "";
                                data[rowNumber].getTlsServerKeyExchange((rawLength * 4 + 5),handshakeType,tlsLength,curveType,curveName,pubLength,pubKey,sigAlgorithm,sigLength,sig);
                                QString type = data[rowNumber].getTlsHandshakeType(handshakeType);

                                QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
                                tlsTree->addChild(tlsSubTree);
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                                tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

                                QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
                                tlsSubTree->addChild(handshakeTree);
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
                                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

                            }
                            break;
                        }
                        case 23:{
                            QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: http-over-tls");
                            tlsTree->addChild(tlsSubree);
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
                            tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Encrypted Application Data: ..."));
                            break;
                        }
                        default:break;
                        }
                    }else if(packageType == SSL){
                        ui->treeWidget->addTopLevelItem(new QTreeWidgetItem(QStringList()<<"Transport Layer Security"));
                    }
                }
            }else if(packageType == UDP || packageType == DNS){
                QString srcPort = data[rowNumber].getUdpSourcePort();
                QString desPort = data[rowNumber].getUdpDestinationPort();
                QString Length = data[rowNumber].getUdpDataLength();
                QString checksum = "0x" + data[rowNumber].getUdpCheckSum();
                QTreeWidgetItem*item5 = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort);
                ui->treeWidget->addTopLevelItem(item5);
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
                item5->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                int udpLength = Length.toUtf8().toInt();
                if(udpLength > 0){
                    item5->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
                }
                if(packageType == DNS){
                    QString transaction = "0x" + data[rowNumber].getDnsTransactionId();
                    QString QR = data[rowNumber].getDnsFlagsQR();
                    QString temp = "";
                    if(QR == "0") temp = "query";
                    if(QR == "1") temp = "response";
                    QString flags = "0x" + data[rowNumber].getDnsFlags();
                    QTreeWidgetItem*dnsTree = new QTreeWidgetItem(QStringList()<<"Domain Name System (" + temp + ")");
                    ui->treeWidget->addTopLevelItem(dnsTree);
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Transaction ID:" + transaction));
                    QTreeWidgetItem* flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags);
                    dnsTree->addChild(flagTree);
                    temp = QR == "1"?"Message is a response":"Message is a query";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<QR + "... .... .... .... = Response:" + temp));
                    QString Opcode = data[rowNumber].getDnsFlagsOpcode();
                    if(Opcode == "0") temp = "Standard query (0)";
                    else if(Opcode == "1") temp = "Reverse query (1)";
                    else if(Opcode == "2") temp = "Status request (2)";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".000 " + Opcode + "... .... .... = Opcode:" + temp));
                    if(QR == "1"){
                        QString AA = data[rowNumber].getDnsFlagsAA();
                        temp = AA == "1"?"Server is an authority for domain":"Server is not an authority for domain";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ." + AA + ".. .... .... = Authoritative:" + temp));
                    }
                    QString TC = data[rowNumber].getDnsFlagsTC();
                    temp = TC == "1"?"Message is truncated":"Message is not truncated";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + TC + ". .... .... = Truncated:" + temp));

                    QString RD = data[rowNumber].getDnsFlagsRD();
                    temp = RD == "1"?"Do query recursively":"Do query not recursively";
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + RD + " .... .... = Recursion desired:" + temp));

                    if(QR == "1"){
                        QString RA = data[rowNumber].getDnsFlagsRA();
                        temp = RA == "1"?"Server can do recursive queries":"Server can not do recursive queries";
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + RA + "... .... = Recursion available:" + temp));
                    }
                    QString Z = data[rowNumber].getDnsFlagsZ();
                    while(Z.size()<3)
                        Z = "0" + Z;
                    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + Z + " .... = Z:reserved(" + Z + ")"));
                    if(QR == "1"){
                        QString Rcode = data[rowNumber].getDnsFlagsRcode();
                        if(Rcode == "0")
                            temp = "No error (0)";
                        else if(Rcode == "1") temp = "Format error (1)";
                        else if(Rcode == "2") temp = "Server failure (2)";
                        else if(Rcode == "3") temp = "Name Error (3)";
                        else if(Rcode == "4") temp = "Not Implemented (4)";
                        else if(Rcode == "5") temp = "Refused (5)";
                        int code = Rcode.toUtf8().toInt();
                        QString bCode = QString::number(code,2);
                        while (bCode.size()<4)
                            bCode = "0" + bCode;
                        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .... " + bCode + " = Reply code:" + temp));
                    }

                    QString question = data[rowNumber].getDnsQuestionNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Questions:" + question));
                    QString answer = data[rowNumber].getDnsAnswerNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Answer RRs:" + answer));
                    QString authority = data[rowNumber].getDnsAuthorityNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Authority RRs:" + authority));
                    QString additional = data[rowNumber].getDnsAdditionalNumber();
                    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Additional RRs:" + additional));
                    int offset = 0;
                    if(question == "1"){
                        QString domainInfo;
                        int Type;
                        int Class;
                        data[rowNumber].getDnsQueriesDomain(domainInfo,Type,Class);
                        QTreeWidgetItem*queryDomainTree = new QTreeWidgetItem(QStringList()<<"Queries");
                        dnsTree->addChild(queryDomainTree);
                        offset += (4 + domainInfo.size() + 2);
                        QString type = data[rowNumber].getDnsDomainType(Type);
                        QTreeWidgetItem*querySubTree = new QTreeWidgetItem(QStringList()<<domainInfo + " type " + type + ", class IN");
                        queryDomainTree->addChild(querySubTree);
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + domainInfo));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"[Name Length:" + QString::number(domainInfo.size()) + "]"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type + "(" + QString::number(Type) + ")"));
                        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                    }
                    int answerNumber = answer.toUtf8().toInt();
                    if(answerNumber > 0){
                        QTreeWidgetItem*answerTree = new QTreeWidgetItem(QStringList()<<"Answers");
                        dnsTree->addChild(answerTree);
                        for(int i = 0;i< answerNumber;i++){
                            QString name1;
                            QString name2;
                            u_short type;
                            u_short Class;
                            u_int ttl;
                            u_short length;

                            int tempOffset = data[rowNumber].getDnsAnswersDomain(offset,name1,type,Class,ttl,length,name2);
                            QString sType = data[rowNumber].getDnsDomainType(type);
                            QString temp = "";
                            if(type == 1) temp = "addr";
                            else if(type == 5) temp = "cname";
                            QTreeWidgetItem*answerSubTree = new QTreeWidgetItem(QStringList()<<name1 + ": type " + sType + ",class IN, " + temp + ":" + name2);
                            answerTree->addChild(answerSubTree);
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + name1));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + sType + "(" + QString::number(type) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Time to live:" + QString::number(ttl) + "(" + QString::number(ttl) + " second)"));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Data length:" + QString::number(length)));
                            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<sType + ":" + name2));

                            offset += tempOffset;
                        }
                    }
                }
            }else if(packageType == ICMP){
                dataLengthofIp -= 8;
                QTreeWidgetItem*item6 = new QTreeWidgetItem(QStringList()<<"Internet Message Protocol");
                ui->treeWidget->addTopLevelItem(item6);
                QString type = data[rowNumber].getIcmpType();
                QString code = data[rowNumber].getIcmpCode();
                QString info = ui->tableWidget->item(row,6)->text();
                QString checksum = "0x" + data[rowNumber].getIcmpCheckSum();
                QString id = data[rowNumber].getIcmpIdentification();
                QString seq = data[rowNumber].getIcmpSequeue();
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Identifier:" + id));
                item6->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:" + seq));
                if(dataLengthofIp > 0){
                    QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(dataLengthofIp) + ") bytes");
                    item6->addChild(dataItem);
                    QString icmpData = data[rowNumber].getIcmpData(dataLengthofIp);
                    dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
                }
            }
        }
        int macDataLength = data[rowNumber].getIpTotalLength().toUtf8().toInt();
        int dataPackageLength = data[rowNumber].getDataLength().toUtf8().toInt();
        int delta = dataPackageLength - macDataLength;
        if(delta > 14){
            int padding = delta - 14;
            QString pad = "";
            while (pad.size() < padding * 2) {
                pad += "00";
            }
            item->addChild(new QTreeWidgetItem(QStringList()<<"Padding: " + pad));
        }
    }
}


void MainWindow::on_lineEdit_returnPressed()
{
    QString text = ui->lineEdit->text();
    text = text.toUpper();
    QString target = "#";
    if(text == "" || text == "UDP" || text == "TCP" || text == "DNS" || text == "ARP"|| text == "ICMP"|| text == "SSL" || text == "TLS"){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
        target = text;
    }else{
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
    int count = 0;
    int number = ui->tableWidget->rowCount();
    if(!isStart && target != "#"){
        if(target!=""){
            for(int i = 0;i < number;i++){
                if(ui->tableWidget->item(i,4)->text() != target){
                    ui->tableWidget->setRowHidden(i,true);
                }else{
                    ui->tableWidget->setRowHidden(i,false);
                    count++;
                }
            }
        }else{
            int number = ui->tableWidget->rowCount();
            for(int i = 0;i < number;i++){
                ui->tableWidget->setRowHidden(i,false);
                count++;
            }
        }
    }

    double res = 0;
    if(number != 0)
        res = (count*100.0)/number;
    statusBar()->showMessage("Have show (" + QString::number(count) + ") " +QString::number(res,10,2) + "%");
}


void MainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    QString text = arg1;
    text = text.toLower();
    if(text == "" || text == "udp" || text == "tcp" || text == "dns" || text == "arp" || text == "icmp" || text == "tls" || text == "ssl"){
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(154,255,154);}");
    }else{
        ui->lineEdit->setStyleSheet("QLineEdit {background-color: rgb(250,128,114);}");
    }
}


void MainWindow::on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn)
{
    if((currentRow != previousRow) && previousRow >= 0){
        on_tableWidget_cellClicked(currentRow,currentColumn);
    }else return;
}
