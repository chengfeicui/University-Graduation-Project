#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "capture.h"
#include "readonlydelegate.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // 5、定义测试网卡的成员函数
    void showNetworkCard();
    // 16、开始写抓包
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
    void on_lineEdit_returnPressed();
    void on_lineEdit_textChanged(const QString &arg1);
    void on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn);

// 84、定义自定义信号DataPackage data的槽函数
public slots:
    void handleMessage(DataPackage data);
private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices; // 1、为了测试网卡，定义指向所有设备的指针，存储的数据结构为链表
    pcap_if_t *device;  // 2、定义指针指向当前的网卡
    pcap_t *pointer;  // 3、打开设备的描述符
    ReadOnlyDelegate* readOnlyDelegate;
    int countNumber;
    int rowNumber;  // 137、代表选中的那一行
    QVector<DataPackage>data;  // 125、定义获取数据包个数，自定义datapackage类型初始化data
    char errbuf[PCAP_ERRBUF_SIZE];  // 4、错误信息的缓冲区
    bool isStart;
};
#endif // MAINWINDOW_H
