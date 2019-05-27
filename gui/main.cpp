#include "firewall.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    firewall w;
    w.setWindowTitle("NetFilterFirewall");
    w.setFixedSize(1200, 800);
    w.show();

    return a.exec();
}
