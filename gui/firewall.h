#ifndef FIREWALL_H
#define FIREWALL_H


#include <QMainWindow>
#include <QIcon>
#include <QString>
#include <QAbstractButton>
#include <QRegExp>
#include <QMessageBox>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QTableWidget>
#include <QCloseEvent>
#include <QIcon>
#include <QLabel>

#define FW_ADD_RULE 0
#define FW_DEL_RULE 1
#define FW_CLEAR_RULE 2

/* some limit conditions */
#define MAX_RECORD 256   // max record number
#define MIN_PORT 0
#define MAX_PORT 0xFFFF

class Node{
public:
  QString sip;
  QString dip;
  unsigned short sport;
  unsigned short dport;
  unsigned short protocol;
  unsigned short sMask;
  unsigned short dMask;
  bool isPermit;
  struct Node *next;          //单链表的指针域
};

namespace Ui {
class firewall;
}

class firewall : public QMainWindow
{
    Q_OBJECT

public:
    explicit firewall(QWidget *parent = 0);
    ~firewall();
    void warningBox(QString str);
    bool check_ip(QString ipstr);
    bool check_port(QString portStr);
    unsigned short get_port(QString portStr);
    unsigned short get_mask(QString Mask);
    unsigned short getProtocolNumber(QString protocol);
    QString getProtocolName(unsigned short protocolNumber) ;
    bool questionBox(QString title,QString msg,QString yesStr,QString noStr);
    void initRuleListTable();
    void addARuleToTable(Node item, unsigned int i);
    void refreshRulesFile();
    void closeEvent(QCloseEvent *event);
private slots:
    void on_addBtn_clicked();
    void on_deleteBtn_clicked();
    void on_clearBtn_clicked();
    void on_rewriteDefaultRulesFile_clicked();

private:
    Ui::firewall *ui;

    int fd;

    // rules name
    QString rulesFilename;
    QVector<Node> ruleList;
    QLabel *statusLabel;
};

#endif // FIREWALL_H
