#ifndef REGNODE_H
#define REGNODE_H

#include <QObject>
#include <QMap>
#include <QDebug>
#include <QString>
#include <QSharedPointer>
#include "regvalue.h"

class RegNode : public QObject
{
    Q_OBJECT
public:
    explicit RegNode(QObject *parent = 0);

    bool isContainsNode(QString key);
    bool isContainsValue(QString key);
    QSharedPointer<RegValue> getNode(QString key);
    QSharedPointer<RegValue> getValue(QString key);
    void removeNode(QString key);
    void removeValue(QString key);
    void insert(QString key, QSharedPointer<RegValue> value);
    QList<QString> nodes();
    QList<QString> data();

    void print(QString sep);

signals:

public slots:
private:

    QMap<QString, QSharedPointer<RegValue>> m_nodes;
    QMap<QString, QSharedPointer<RegValue>> m_data;
};

#endif // REGNODE_H
