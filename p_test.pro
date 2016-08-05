TEMPLATE = app
CONFIG += console c++11
CONFIG += thread
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnet
SOURCES += main.cpp
