#include "regnode.h"

RegNode::RegNode(QObject *parent) :
    QObject(parent)
{
}

bool RegNode::isContainsNode(QString key) {
    return m_nodes.contains(key);
}

bool RegNode::isContainsValue(QString key) {
    return m_data.contains(key);
}

QSharedPointer<RegValue> RegNode::getNode(QString key) {
    Q_ASSERT(isContainsNode(key));
    return m_nodes[key];
}

QSharedPointer<RegValue> RegNode::getValue(QString key) {
    Q_ASSERT(isContainsValue(key));
    return m_data[key];
}

void RegNode::removeNode(QString key) {
    Q_ASSERT(isContainsNode(key));

    m_nodes.remove(key);
}

void RegNode::removeValue(QString key) {
    Q_ASSERT(isContainsValue(key));

    m_data.remove(key);
}

void RegNode::insert(QString key, QSharedPointer<RegValue> value) {
    if (value->type() == RegKey::NODE) {
        Q_ASSERT(!isContainsNode(key));
        m_nodes[key] = value;
    } else {
        Q_ASSERT(!isContainsValue(key));
        m_data[key] = value;
    }
}

QList<QString> RegNode::nodes() {
    return m_nodes.keys();
}

QList<QString> RegNode::data() {
    return m_data.keys();
}

void RegNode::print(QString sep) {
    for (auto it = m_data.constBegin();it != m_data.constEnd();++it) {
        switch (it.value()->type()) {
        case RegKey::DWORD:
            qDebug()<<sep<<it.key()<<":"<<it.value()->dword();
            break;
        case RegKey::HEX:
            qDebug()<<sep<<it.key()<<":"<<it.value()->hex();
            break;
        case RegKey::NODE:
            qDebug()<<sep<<it.key()<<":";
            it.value()->node()->print(sep + "   ");
            break;
        case RegKey::STRING:
            qDebug()<<sep<<it.key()<<":"<<it.value()->string();
            break;
        case RegKey::UNKNOWN:
            qDebug()<<sep<<it.key()<<":"<<"ERROR ACCESS REGKEY, UNKNOWN VALUE";
            break;
        default:
            Q_ASSERT(0);
        }
    }
}
