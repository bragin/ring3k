#include "regvalue.h"

RegValue::RegValue(QObject *parent) :
    QObject(parent)
{
    m_type = RegKey::UNKNOWN;
    m_hexType = -1;
}

RegValue::~RegValue()
{

}

RegKey RegValue::type() {
    return m_type;
}

QString RegValue::string() {
    Q_ASSERT(m_type == RegKey::STRING);
    return m_string;
}

QByteArray RegValue::hex() {
    Q_ASSERT(m_type == RegKey::HEX);
    return m_hex;
}

int RegValue::hexType() {
    return m_hexType;
}

uint32_t RegValue::dword() {
    Q_ASSERT(m_type == RegKey::DWORD);
    return m_dword;
}

QSharedPointer<RegNode> RegValue::node() {
    Q_ASSERT(m_type == RegKey::NODE);
    return m_node;
}

void RegValue::set(QString s) {
    m_type = RegKey::STRING;
    m_string = s;
}

void RegValue::set(QByteArray a, int type) {
    m_type = RegKey::HEX;
    m_hex = a;
    m_hexType = type;
}

void RegValue::set(uint32_t n) {
    m_type = RegKey::DWORD;
    m_dword = n;
}

void RegValue::set(QSharedPointer<RegNode> node) {
    m_type = RegKey::NODE;
    m_node = node;
}
