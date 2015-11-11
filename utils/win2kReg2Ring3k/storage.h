#ifndef STORAGE_H
#define STORAGE_H

#include <QObject>
#include <QIODevice>
#include <QXmlStreamWriter>
#include "regnode.h"

class Storage : public QObject
{
    Q_OBJECT
public:
    explicit Storage(QObject *parent = 0);

    void store(QSharedPointer<RegNode> root, QIODevice &device);

    void store(QSharedPointer<RegNode> root, QXmlStreamWriter &xml);

    QString safe2Hex(unsigned char byte);
signals:

public slots:

};

#endif // STORAGE_H
