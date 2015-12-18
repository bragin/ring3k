#ifndef PARSER2_H
#define PARSER2_H

#include <QObject>
#include <QByteArray>
#include <QStringList>
#include "regnode.h"


class Parser : public QObject
{
    Q_OBJECT
public:
    explicit Parser(QObject *parent = 0);

    QSharedPointer<RegNode> parse(const QByteArray &array);

private:
    void checkHeader();
    bool isSection();
    void parseSection(QSharedPointer<RegNode> node);
    QSharedPointer<RegNode> findAndCreate(QSharedPointer<RegNode> node, QString name);
    void addKeyValue(QSharedPointer<RegNode> node);
    void readEqual(int &pos);
    RegKey readType(int &pos, int &hexType);
    uint32_t readDword(int &pos);
    QByteArray readHex(int &pos);
    QString readString(int &pos);
    QString readKey(int &pos);
    uint32_t hex2Int(QString data) const;
    int getHexDigit(QChar c) const;
    void skipWhitespaces(QString &data, int &pos);
    QString printableArray(QByteArray arr);
    void replaceHKEY(QSharedPointer<RegNode> node);
    void split(const QByteArray &array);
    bool isQuote(int position);
signals:

public slots:
private:
    QVector<QString> m_data;
    int m_ptr;
};

#endif // PARSER2_H