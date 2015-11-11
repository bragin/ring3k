#ifndef REGVALUE_H
#define REGVALUE_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QSharedPointer>

enum class RegKey {
    UNKNOWN,
    STRING,
    HEX,
    DWORD,
    NODE
};

class RegNode;
class RegValue : public QObject
{
    Q_OBJECT

public:
    explicit RegValue(QObject *parent = 0);
    virtual ~RegValue();

    RegKey type();
    QString string();
    QByteArray hex();
    int hexType();
    uint32_t dword();
    QSharedPointer<RegNode> node();
    void set(QString s);
    void set(QByteArray a, int type);
    void set(uint32_t n);
    void set(QSharedPointer<RegNode> node);

signals:

public slots:
private:
    RegKey m_type;

    QString m_string;
    QByteArray m_hex;
    int m_hexType;
    uint32_t m_dword;
    QSharedPointer<RegNode> m_node;
};

#endif // REGVALUE_H
