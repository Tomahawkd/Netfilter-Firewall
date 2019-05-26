#-------------------------------------------------
#
# Project created by QtCreator 2019-05-25T23:47:00
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = GUI
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp

HEADERS += \
        mainwindow.h

FORMS += \
    test.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    ../UI/img/background.jpg \
    ../UI/img/headimg.jpg \
    ../UI/img/safe.jpg \
    ../UI/img/test.jpg \
    ../UI/img/back.png \
    ../UI/img/close.png \
    ../UI/img/head.png \
    ../UI/img/icon.png \
    ../UI/img/min.png \
    ../UI/img/password.png \
    ../UI/img/psw.png \
    ../UI/img/username.png

RESOURCES += \
    img.qrc
