#include "mainwindow.h"
#include <QFont>
#include <QDebug>
#include <QRect>
#include <QSize>
#include <QPainter>
#include <QMessageBox>
using namespace std;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setMouseTracking(true);
    ismove = false;
    isShowPsw = false;
    this->setWindowFlags(Qt::FramelessWindowHint);
    setFixedSize(1024,720);
    this->setAutoFillBackground(true);
    QPalette palette = this->palette();
    palette.setBrush(QPalette::Window,
                QBrush(QPixmap(":/img/back.png").scaled(
                    this->size(),
                    Qt::IgnoreAspectRatio,
                    Qt::SmoothTransformation)));            
    this->setPalette(palette);
    QHBoxLayout *titlelayout = new QHBoxLayout;
    titlelayout->addLayout(setWindowTitleBtn());
    QVBoxLayout *btlayout = new QVBoxLayout;
    QVBoxLayout *mainlayout = new QVBoxLayout;
    mainlayout->addLayout(titlelayout);
    mainlayout->addStretch();
    btlayout->addLayout(getHeadImg(":/img/head.png")); //logo
    btlayout->addLayout(getLoginLayout());
    btlayout->addLayout(Firewall_records());
    mainlayout->addLayout(btlayout);
    mainlayout->addStretch();
    QLabel *btlabel = new QLabel("@Web Security"); //底部标签
    btlabel->setStyleSheet("QLabel{color:white}");
    QHBoxLayout *btlabellayout = new QHBoxLayout;
    btlabellayout->addStretch();
    btlabellayout->addWidget(btlabel);
    btlabellayout->addStretch();
    btlabellayout->setMargin(5);
    mainlayout->addLayout(btlabellayout);
    mainlayout->setSpacing(0);
    mainlayout->setMargin(0);
    QWidget *wid = new QWidget;
    wid->setMouseTracking(true);
    this->setCentralWidget(wid);
    wid->setLayout(mainlayout);
}

MainWindow::~MainWindow()
{

}

QLayout* MainWindow::setWindowTitleBtn()
{
    QHBoxLayout *layout = new QHBoxLayout;
    minBtn = new QPushButton;
    closeBtn = new QPushButton;
    QPixmap icon1(":/img/min.png");
    QPixmap icon2(":/img/close.png");
    minBtn->setIcon(icon1);
    closeBtn->setIcon(icon2);
    minBtn->setStyleSheet("QPushButton{border-left:0px;border-right:0px;border-top:0px;border-bottom:0px;width:30px;height:20px;color:#D6D6D6}"
                          "QPushButton:hover{border-left:0px;border-right:0px;border-top:0px;border-bottom:0px;width:30px;height:20px;"
                          "background-color:qconicalgradient(cx:0.5, cy:0.5, angle:0, stop:0.368182 rgba(198,198,198,75))}"
                          "QPushButton:pressed{border-left:0px;border-right:0px;border-top:0px;border-bottom:0px;width:30px;height:20px;"
                          "background-color:qconicalgradient(cx:0.5, cy:0.5, angle:0, stop:0.368182 rgba(100,100,100,75))}");
    closeBtn->setStyleSheet("QPushButton{border-left:0px;border-right:0px;border-top:0px;border-bottom:0px;width:30px;height:20px;color:#D6D6D6}"
                          "QPushButton:hover{border-left:0px;border-right:0px;border-top:0px;border-bottom:0px;width:30px;height:20px;"
                          "background-color:qconicalgradient(cx:0.5, cy:0.5, angle:0, stop:0.368182 rgba(198,198,198,75))}"
                          "QPushButton:pressed{border-left:0px;border-right:0px;border-top:0px;border-bottom:0px;width:30px;height:20px;"
                          "background-color:red}");
    QFont font1("Microsoft YaHei",20,75);
    QFont font2("Microsoft YaHei",15,75);
    minBtn->setFont(font1);
    closeBtn->setFont(font2);
    connect(closeBtn,SIGNAL(clicked(bool)),this,SLOT(close()));
    connect(minBtn,SIGNAL(clicked(bool)),this,SLOT(showMinimized()));
    connect(closeBtn,SIGNAL(pressed()),this,SLOT(doNotMove()));
    connect(minBtn,SIGNAL(pressed()),this,SLOT(doNotMove()));
    QHBoxLayout *titlelayout = new QHBoxLayout;
    QLabel *title = new QLabel("Netfilter-Firewall");//程序标题
    title->setStyleSheet("QLabel{color:white}");
    QLabel *titleicon = new QLabel;
    titleicon->setPixmap(QPixmap(":/img/icon.png").scaled(18,18)); //图标
    titleicon->setFixedSize(18,18);
    title->setFont(QFont("Microsoft YaHei",8,QFont::Bold));
    titlelayout->addWidget(titleicon);
    titlelayout->addWidget(title);
    titlelayout->setMargin(0);
    titlelayout->setSpacing(5);
    layout->addLayout(titlelayout);
    layout->addStretch();
    layout->addWidget(minBtn);
    layout->addWidget(closeBtn);
    layout->setSpacing(0);
    layout->setMargin(0);
    return layout;
}

void MainWindow::mousePressEvent(QMouseEvent *event)
{
    if(event->buttons() & Qt::LeftButton)
    {
        if(event->pos().ry()<30 && event->pos().rx()<250)
        {
            offset.setX(event->globalPos().rx()-this->pos().rx());
            offset.setY(event->globalPos().ry()-this->pos().ry());
            ismove = true;
        }
    }
}

void MainWindow::mouseMoveEvent(QMouseEvent *event)
{
    if(event->buttons() & Qt::LeftButton)
    {
        if(event->pos().ry() < 30 && event->pos().rx()<250)
        {
            if(ismove)
            {
                move(event->globalX()-this->offset.rx(),event->globalY()-this->offset.ry());
            }
        }
    }
}

void MainWindow::doNotMove()
{
    ismove = false;
}

QPixmap MainWindow::pixmapToRound(QPixmap &src, int radius)
{
    if (src.isNull()) {
        return QPixmap();
    }

    QSize size(2*radius, 2*radius);
    QBitmap mask(size);
    QPainter painter(&mask);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    painter.fillRect(0, 0, size.width(), size.height(), Qt::white);
    painter.setBrush(QColor(0, 0, 0));
    painter.drawRoundedRect(0, 0, size.width(), size.height(), 99, 99);

    QPixmap image = src.scaled(size);
    image.setMask(mask);
    return image;
}

QLayout* MainWindow::getHeadImg(QString src)
{
    QPixmap pixmap_userIcon;
    pixmap_userIcon.load(src);
    QPixmap fitpixmap_userIcon=pixmap_userIcon.scaled(160, 160, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
    fitpixmap_userIcon = this->pixmapToRound(fitpixmap_userIcon,100);
    QHBoxLayout *layout = new QHBoxLayout;
    QLabel *headimg = new QLabel;
    headimg->setScaledContents(true);
    headimg->setFixedSize(160,160);
    headimg->setPixmap(fitpixmap_userIcon);
    layout->addWidget(headimg);
    return layout;
}


void MainWindow::write_filter(){
    ofstream ofs;
	//!!!!文件写入位置，自定义
    string filename = "/home/Vshows/test" ;
    QString ip_ori = ip1->text();
    string ip_ori_text = ip_ori.toStdString();
    QString ip_des = ip2->text();
    string ip_des_text = ip_des.toStdString();
    if(ip_ori_text.empty() || ip_des_text.empty()){
        QMessageBox::information(this,"Failed","You type the wrong format!");
    }
    else{
        string ip_text = ip_ori_text + "-"+ip_des_text+"\n";
        ofs.open(filename,ostream::app);
        ofs<<ip_text; 
        ofs.close(); 
        ofs.clear(); 
        QMessageBox::information(this,"Success","The Filter Starts!");
    }

}

QLayout* MainWindow::getLoginLayout()
{

    ip1 = new QLineEdit;
    ip1->setStyleSheet("QLineEdit{border:1.5px solid white;border-top:0px;border-left:0px;border-right:0px;background:transparent;height:40px;"
                            "font-size:20px;color:white}");
    ip1->setAlignment(Qt::AlignCenter);
    ip1->setPlaceholderText("Input the original IP address ");
    ip1->setFixedSize(300,60);
    //ip1->setInputMask("000.000.000.000---000.000.000.000");

    ip2 = new QLineEdit;
    ip2->setStyleSheet("QLineEdit{border:1.5px solid white;border-top:0px;border-left:0px;border-right:0px;background:transparent;height:40px;"
                            "font-size:20px;color:white}");
    ip2->setAlignment(Qt::AlignCenter);
    ip2->setPlaceholderText("Input the destination IP address ");
    ip2->setFixedSize(300,60);

    start = new QPushButton("Start Filter");
    start->setStyleSheet("QPushButton{border:0.5px solid white;background:transparent;height:30px;font-size:20px;"
                            "border-radius:5px;padding:2px 4px;color:white}"
                            "QPushButton:hover{padding-left:-3px}"
                            "QPushButton:pressed{padding-top:6px}");
    start->setFont(QFont("Microsoft YaHei",25,QFont::Bold));
    start->setFixedWidth(200);
    connect(start,SIGNAL(clicked(bool)),this,SLOT(write_filter()));
    QVBoxLayout *layout = new QVBoxLayout;
    QHBoxLayout *input = new QHBoxLayout;
    input->addStretch();
    input->addWidget(ip1);
    input->addStretch();
    input->addWidget(ip2);
    input->addWidget(start);
    input->addStretch();
    layout->addLayout(input);
    layout->setStretchFactor(input,2);
    layout->setSpacing(10);
    layout->setMargin(60);
    return layout;
}




QLayout* MainWindow::Firewall_records()
{
    Records = new QPushButton("Firewall Recording");
    Records->setStyleSheet("QPushButton{border:1.5px solid white;background:transparent;height:30px;font-size:20px;"
                            "border-radius:10px;padding:2px 4px;color:white}"
                            "QPushButton:hover{padding-left:-3px}"
                            "QPushButton:pressed{padding-top:6px}");
    Records->setFont(QFont("Microsoft YaHei",25,QFont::Bold));
    Records->setFixedWidth(250);

    date_filter = new QPushButton("Date Filter");
    date_filter->setStyleSheet("QPushButton{background:transparent;height:40px;font-size:20px;color:white}"
                           "QPushButton:hover{padding-left:-3px}"
                           "QPushButton:pressed{padding-top:6px}");
    date_filter->setFixedWidth(120);
    date_filter->setFont(QFont("Microsoft YaHei",60,QFont::Bold));

    source_filter = new QPushButton("Source Filter");
    source_filter->setStyleSheet("QPushButton{background:transparent;height:40px;font-size:20px;color:white}"
                              "QPushButton:hover{padding-left:-3px}"
                              "QPushButton:pressed{padding-top:6px}");
    source_filter->setFixedWidth(150);
    source_filter->setFont(QFont("Microsoft YaHei",60,QFont::Bold));

    level_filter = new QPushButton("Level Filter");
    level_filter->setStyleSheet("QPushButton{background:transparent;height:40px;font-size:20px;color:white}"
        "QPushButton:hover{padding-left:-3px}"
        "QPushButton:pressed{padding-top:6px}");
    level_filter->setFixedWidth(120);
    level_filter->setFont(QFont("Microsoft YaHei", 60, QFont::Bold));

    QHBoxLayout *btn = new QHBoxLayout;
    btn->addStretch();
    btn->addWidget(Records);
    btn->addStretch();
    QHBoxLayout *ot = new QHBoxLayout;
    ot->addStretch();
    ot->addWidget(date_filter);
    ot->addStretch();
    ot->addWidget(source_filter);
    ot->addStretch();
    ot->addWidget(level_filter);
    ot->addStretch();
    QVBoxLayout *layout = new QVBoxLayout;
    layout->addLayout(btn);
    layout->addLayout(ot);
    layout->setStretchFactor(btn,1);
    layout->setStretchFactor(ot,2);
    layout->setSpacing(25);
    return layout;
}
