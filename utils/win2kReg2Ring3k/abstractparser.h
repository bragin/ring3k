#ifndef ABSTRACTPARSER_H
#define ABSTRACTPARSER_H

#include <QObject>
#include "regnode.h"

class AbstractParser : public QObject
{
    Q_OBJECT
public:
    explicit AbstractParser(QObject *parent = 0);
    virtual QSharedPointer<RegNode> parse(const QByteArray &array) = 0;
    virtual QString name() = 0;
signals:

public slots:
};

#endif // ABSTRACTPARSER_H
