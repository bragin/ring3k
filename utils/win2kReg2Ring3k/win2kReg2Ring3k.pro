#-------------------------------------------------
#
# Project created by QtCreator 2015-11-06T16:15:09
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = win2kReg2Ring3k
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app
CONFIG += c++11
QMAKE_CXXFLAGS += -std=c++11

SOURCES += main.cpp \
    regnode.cpp \
    regvalue.cpp \
    storage.cpp \
    parser.cpp

HEADERS += \
    regnode.h \
    regvalue.h \
    storage.h \
    parser.h
