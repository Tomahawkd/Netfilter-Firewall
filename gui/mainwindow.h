#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QWidget>
#include <QPushButton>
#include <QLayout>
#include <QMouseEvent>
#include <QApplication>
#include <QDesktopWidget>
#include <QPoint>
#include <QPixmap>
#include <QString>
#include <QBitmap>
#include <QLabel>
#include <QLineEdit>
#include <QAction>
#include <fstream>
#include <string>

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = 0);
    ~MainWindow();
private:
    QLayout* getLoginLayout();
    QLayout* setWindowTitleBtn();
    QLayout* getHeadImg(QString src);
    QLayout* Firewall_records();
    QPixmap pixmapToRound(QPixmap &src, int radius);
    QPushButton *minBtn; //最小化按钮
    QPushButton *closeBtn; //关闭按钮
    QLineEdit *ip1; //起始ip地址
    QLineEdit *ip2; //结束ip地址
    QPushButton *start; //启动IP过滤器
    QPushButton *Records; //查看防火墙信息
    QPushButton *date_filter; //按时间过滤按钮
    QPushButton *source_filter; //按来源过滤按钮
    QPushButton *level_filter;//按危险等级过滤按钮
    QPoint offset;
    bool ismove;
    bool isShowPsw;


protected:

    void mousePressEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);
private slots:
    void doNotMove();
    void write_filter();

};

#endif // MAINWINDOW_H
