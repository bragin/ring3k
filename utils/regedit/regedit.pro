
HEADERS += \
	registryeditor.h \
	registryitem.h \
	registrymodel.h \
	registrytreeview.h \
	registryvalue.h

SOURCES += \
	main.cpp \
	registryeditor.cpp \
	registryitem.cpp \
	registrymodel.cpp \
	registrytreeview.cpp \
	registryvalue.cpp

INCLUDEPATH += ../libntreg

LIBS += ../libntreg/libntreg.a

QT += widgets

CONFIG += qt

