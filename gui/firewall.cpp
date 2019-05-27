#include "firewall.h"
#include "ui_firewall.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <getopt.h>
#include <string>

#define FW_ADD_RULE 0
#define FW_DEL_RULE 1
#define FW_CLEAR_RULE 2


firewall::firewall(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::firewall) {

    ui->setupUi(this);

    initRuleListTable();



    rulesFilename = "/var/netfilter/rules";

    QFile file(rulesFilename);
    QString line;

    Node item;
    if(QFileInfo::exists(rulesFilename)) {
        file.open(QFile::ReadOnly);
        item.next = NULL;
        while(!file.atEnd()) {
           line = QString::fromLocal8Bit(file.readLine().data());
           item.sip =  line.section(":",0,0).trimmed();
           item.dip = line.section(":",1,1).trimmed();
           item.sport = line.section(":",2,2).trimmed().toUShort();
           item.dport = line.section(":",3,3).trimmed().toUShort();
           item.protocol = line.section(":",4,4).trimmed().toUShort();
           item.sMask = line.section(":",5,5).trimmed().toShort();
           item.dMask = line.section(":",6,6).trimmed().toShort();


           if(line.section(":",7,7).trimmed().toUShort() == 1) {
                item.isPermit = true;
           } else {
               item.isPermit = false;
           }

           ruleList.push_back(item);
        }
        file.close();
    }
    else{
        file.open(QIODevice::ReadWrite | QIODevice::Text);
        file.close();
    }



    for(int i = 0, len = ruleList.length(); i < len; i++) {
        addARuleToTable(ruleList[i],i);
        ioctl(fd, FW_ADD_RULE, &ruleList[i]);
    }

}


void firewall::addARuleToTable(Node item,unsigned int i) {
    QString sip;
    QString dip;
    QString protocol;
    QTableWidget *ruleListTable = ui->ruleListTable;
    sip = item.sip;
    protocol = getProtocolName(item.protocol);
    if(item.sMask > 0) {
        sip += QString("/") + QString::number(item.sMask);
    }


    dip = item.dip;
    if(item.dMask > 0) {
        dip += QString("/") + QString::number(item.dMask);
    }

    // check rows, if rows is not enough, add one rows
    unsigned int len = ruleListTable->rowCount();
    if(len == i) { //
       ruleListTable->setRowCount(i + 1);
    }

    // set item
    ruleListTable->setItem(i,0,new QTableWidgetItem(sip));
    ruleListTable->setItem(i,1,new QTableWidgetItem(dip));
    if(item.sport) {
        ruleListTable->setItem(i,2,new QTableWidgetItem(QString::number(item.sport)));
    } else {
        ruleListTable->setItem(i,2,new QTableWidgetItem("ANY"));
    }
    if(item.dport) {
        ruleListTable->setItem(i,3,new QTableWidgetItem(QString::number(item.dport)));
    } else {
        ruleListTable->setItem(i,3,new QTableWidgetItem("ANY"));
    }
    ruleListTable->setItem(i,4,new QTableWidgetItem(protocol));

    if(item.isPermit) {
        ruleListTable->setItem(i,5,new QTableWidgetItem("Permit"));
    } else {
        ruleListTable->setItem(i,5,new QTableWidgetItem("Reject"));
    }


}

firewall::~firewall() {
    delete ui;
}


void firewall::on_addBtn_clicked(){

    Node item;
    QString sIPstr = ui->sourceIPInput->text().trimmed();
    QString dIPstr = ui->destIPInput->text().trimmed();

    // checked ip
    if(!check_ip(sIPstr) || !check_ip(dIPstr)) {
       warningBox("IP is not correct, please check your ip input.");
       return;
    }

    // checked port
    QString sPortStr = ui->sourcePortInput->text().trimmed();
    QString dPortStr = ui->destPortInput->text().trimmed();
    if(!check_port(sPortStr) || !check_port(dPortStr)){
        warningBox("Port is not correct, please check your port input.");
        return;
    }


    item.sip = sIPstr;
    item.sport = get_port(sPortStr);



    item.dip = dIPstr;
    item.dport = get_port(dPortStr);

    //get mask
    QString sMask = ui->sourceMaskInput->text().trimmed();
    QString dMask = ui->destMaskInput->text().trimmed();


    // get protocol, 0 is as any
    QString protocol = ui->protocolComboBox->currentText().trimmed();
    item.protocol = getProtocolNumber(protocol.toLocal8Bit().data());
    // if ICMP, port as any
    if(protocol == "ICMP") {
        item.sport = 0;
        item.dport = 0;
    }

    // if value 0, means not a subnet mask, else as subnet mask number
    item.sMask = get_mask(sMask);
    item.dMask = get_mask(dMask);

    if(ui->buttonGroup->checkedButton()->objectName().trimmed() == "permit") {
        item.isPermit = true;
    } else {
        item.isPermit = false;
    }


    // judge if has the same record, ip ,port, protocol all the same
    bool isExisted = false;
    for(int i = 0,len = ruleList.length(); i < len; i++) {
        if(ruleList[i].sip != item.sip || ruleList[i].dip != item.dip) {
            continue;
        }

        if(ruleList[i].protocol != item.protocol) {
            continue;
        }

        // if ICMP, not need to check port
        if(item.protocol == IPPROTO_ICMP) {
            isExisted = true;
            break;
        }

        if(ruleList[i].sport != item.sport || ruleList[i].dport != item.dport) {
            continue;
        }

        isExisted = true;
        break;
    }

    if(isExisted) {
        warningBox("There is a consistent record! So you are failed to add!");
        return;
    }

    // add to ruleList
    ruleList.append(item);

    // add to table shows
    unsigned int len = ruleList.length();
    addARuleToTable(item,len -1);

    ioctl(fd, FW_ADD_RULE, &item);


}


void firewall::refreshRulesFile() {

    QFile file(rulesFilename);
    if(file.open(QFile::WriteOnly)) {
        QTextStream out(&file);
        QString str;
        Node item;
        for(int i = 0, len = ruleList.length(); i < len; i++) {
            item = ruleList[i];
            QString str = item.sip + ":"  + item.dip + ":";
            str += QString::number(item.sport) + ":";
            str += QString::number(item.dport) + ":";
            str += QString::number(item.protocol) + ":";
            str += QString::number(item.sMask) + ":";
            str += QString::number(item.dMask) + ":";
            if(item.isPermit) {
                str += "1\n";
            } else {
                str += "0\n";
            }


            out << str;
        }
        file.close();
    }


}


void firewall::on_deleteBtn_clicked(){


    int len = ruleList.length();
    if(len <= 0) {
        warningBox("Nothing to delete!");
        return;
    }

    // check current row
    int row = ui->ruleListTable->currentRow();
    if(row < 0) {
        warningBox("Not any row select yet, please select the row you want to delete.");
        return;
    }

    // check is out of range
    if(row >= len) {
        // out of range
        return;
    }
    // checked delete again
    bool reply = questionBox("delete checked","You are going to delete the selected row, sure ?","Yes!", "No!");
    if(!reply) {
        return;
    }

    // delete in the table, if delete a row, the rowCount will auto reduce 1
    ui->ruleListTable->removeRow(row);


    ioctl(fd, FW_DEL_RULE, &ruleList[row]);
    ruleList.remove(row);

}


void firewall::on_clearBtn_clicked(){

    // question
    bool reply = questionBox("clear check","Are you sure to clear all the filter rules ?", "Yes", "No");
    if(!reply){
        return;
    }

    ruleList.clear();

    ui->ruleListTable->clear();

    Node item = {QString(),QString(),0,0,0,0,0,false};
    ioctl(fd, FW_CLEAR_RULE,&item);

}


bool firewall::check_ip(QString ipstr){
    QRegExp reg("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(\\/[0-9]{1,2})?$");
    if(!reg.exactMatch(ipstr)) {
        return false;
    }

    char *str = ipstr.toLocal8Bit().data();
    int a,b,c,d;
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);

    // judge if is a correct ip
    if(a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
        return false;
    }

    return true;
}

// checked port

bool firewall::check_port(QString portStr){
    QRegExp reg("^[0-9]{1,5}$");
    if(!reg.exactMatch(portStr)){
        return false;
    }

    // if use to ushort, maybe not true
    unsigned int t = portStr.toUInt();
    if(t >= MAX_PORT){
        return false;
    }
    return true;
}

// get port

unsigned short firewall::get_port(QString portStr){
    unsigned short port = portStr.toUShort();
    return port;
}

unsigned short firewall::get_mask(QString Mask){
    unsigned short mask = Mask.toUShort();
    return mask;
}




unsigned short firewall::getProtocolNumber(QString protocol) {

    // default as any, use 0
    unsigned short t = 0;
    if(QString::compare(protocol,"TCP") == 0){
        t = IPPROTO_TCP;
    } else if(QString::compare(protocol,"UDP") == 0){
        t = IPPROTO_UDP;
    } else if(QString::compare(protocol,"ICMP") == 0){
        t = IPPROTO_ICMP;
    }
    return t;
}


QString firewall::getProtocolName(unsigned short protocolNumber) {
    QString t = "ANY";
    switch(protocolNumber){
        case IPPROTO_TCP:
            t = "TCP";
            break;
        case IPPROTO_UDP:
            t = "UDP";
            break;
        case IPPROTO_ICMP:
            t = "ICMP";
            break;
        default:

            break;
    }

    return t;
}



void firewall::warningBox(QString str){
    QMessageBox box(QMessageBox::Warning, "warning",str);
    box.setStandardButtons(QMessageBox::Ok);
    box.setButtonText(QMessageBox::Ok,QString("OK!"));
    box.exec();
}


bool firewall::questionBox(QString title,QString msg,QString yesStr,QString noStr){
    QMessageBox reply(QMessageBox::Question, title,msg);
    reply.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    reply.setButtonText(QMessageBox::Yes,QString(yesStr));
    reply.setButtonText(QMessageBox::No,QString(noStr));
    reply.setDefaultButton(QMessageBox::No);
    if (reply.exec() == QMessageBox::Yes) {
       return true;
    } else {
       return false;
    }
}

/*
 * init the table to show rules
 */
void firewall::initRuleListTable() {
    QStringList header;
    QTableWidget *ruleListTable = ui->ruleListTable;

    ruleListTable->setRowCount(15);
    ruleListTable->setColumnCount(6);
    header << "source ip" << "destination ip" << "S port" << "D port" << "protocol" << "action";
    ruleListTable->setWindowTitle("rule list table");
    ruleListTable->setHorizontalHeaderLabels(header);
    ruleListTable->setEditTriggers(QAbstractItemView::NoEditTriggers);   // set readonly
    ruleListTable->setSelectionMode(QAbstractItemView::SingleSelection); //设置选择的模式为单选择
    ruleListTable->setSelectionBehavior(QAbstractItemView::SelectRows);  //设置选择行为时每次选择一行
    ruleListTable->horizontalHeader()->setStyleSheet("QHeaderView::section {background-color:white;color: black;padding-left: 4px;border: 1px solid #6c6c6c;}");    //设置表头字体，颜色，模式
    ruleListTable->verticalHeader()->setStyleSheet("QHeaderView::section {  background-color:white;color: black;padding-left: 4px;border: 1px solid #6c6c6c}");   //设置纵列的边框项的字体颜色模式等
    ruleListTable->horizontalHeader()->setStretchLastSection(true);

    ruleListTable->setColumnWidth(0,160);
    ruleListTable->setColumnWidth(1,160);
    ruleListTable->setColumnWidth(2,60);
    ruleListTable->setColumnWidth(3,60);
    ruleListTable->setColumnWidth(4,80);
    ruleListTable->setColumnWidth(5,60);
    ruleListTable->setColumnWidth(6,60);

}




// close event
void firewall::closeEvent(QCloseEvent *event) {
    bool reply = questionBox("close check","Close this program?","Yes!","No");
    if(!reply){
        event->ignore();
        return;
    }
    //close(fd);
    event->accept();
}

/**
 * @brief firewall::on_rewriteDefaultRulesFile_clicked
 * rewrite the default
 */
void firewall::on_rewriteDefaultRulesFile_clicked(){
    bool reply = questionBox("refresh rules file check","You want to rerwite the trle file?","Yes!","No!");
    if(!reply){
        return;
    }
    refreshRulesFile();
}
