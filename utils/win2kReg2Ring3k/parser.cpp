#include "parser.h"

extern bool isDebugMode;

Parser::Parser(QObject *parent) :
    QObject(parent)
{
    m_ptr = 0;
}

QSharedPointer<RegNode> Parser::parse(const QByteArray &array) {

    auto root = QSharedPointer<RegNode>(new RegNode);

    split(array);

    checkHeader();

    while (isSection()) {
        parseSection(root);
    }

    replaceHKEY(root);

    return root;
}

void Parser::checkHeader() {
    Q_ASSERT(m_data[0] == "Windows Registry Editor Version 5.00");
    m_ptr++;
}

bool Parser::isSection() {
    return m_ptr < m_data.size() && m_data[m_ptr][0] == '[';
}

void Parser::parseSection(QSharedPointer<RegNode> node) {
    auto section = m_data[m_ptr];

    Q_ASSERT(section.at(0) == '[' && section.at(section.length() - 1) == ']');

    section = section.mid(1, section.size() - 2);
    node = findAndCreate(node, section);

    m_ptr++;

    while (!isSection() && m_ptr < m_data.size() ) {
        qDebug()<<"adding pair"<<m_data[m_ptr];
        addKeyValue(node);
        m_ptr++;
    }

}

QSharedPointer<RegNode> Parser::findAndCreate(QSharedPointer<RegNode> node, QString name) {

    auto path = name.split("\\");

    for (auto el: path) {
        if (node->isContainsNode(el)) {
            qDebug()<<"already contains"<<el;
            auto value = node->getNode(el);
            Q_ASSERT(value->type() == RegKey::NODE);
            node = value->node();
        } else {
            qDebug()<<"creaing node"<<el;
            auto value = QSharedPointer<RegValue>(new RegValue);
            value->set(QSharedPointer<RegNode>(new RegNode));
            node->insert(el, value);
            node = value->node();
        }
    }

    return node;

}

void Parser::addKeyValue(QSharedPointer<RegNode> node) {
    int pos = 0;
    auto key = readKey(pos);
    qDebug()<<key;
    readEqual(pos);
    int hexType = -1;
    auto type = readType(pos, hexType);

    auto value = QSharedPointer<RegValue>(new RegValue);

    switch (type) {
    case RegKey::DWORD: {
        auto v = readDword(pos);
        qDebug()<<key<<":"<<v;
        value->set(v);
    } break;
    case RegKey::HEX: {
        auto v = readHex(pos);
        qDebug()<<key<<":"<<printableArray(v);
        value->set(v, hexType);
    } break;
    case RegKey::STRING: {
        auto v = readString(pos);
        qDebug()<<key<<":"<<v;
        value->set(v);
    } break;
    default:
        Q_ASSERT(0);
    }
    node->insert(key, value);
}

void Parser::split(const QByteArray &array) {

    int i=0;
    while (i < array.size()) {
        QByteArray a;
        while (array.at(i) != 0 || array.at(i+1) != 0) {
            a.append(array.at(i));
            a.append(array.at(i+1));
            i += 2;
        }
        i += 2;

        if (a.size()) {
            a.append('\0');
            m_data.append(QString::fromUtf16(reinterpret_cast<const unsigned short*>(a.constData())));
        }
    }

    if (isDebugMode) {
        qDebug()<<m_data.size();
        for (int i=0;i<30;i++) {
            qDebug()<<m_data[i];
        }
        qDebug()<<"....";
        for (int i=30;i>=0;i--) {
            qDebug()<<m_data[m_data.size() - 1 - i];
        }
    }

}

bool Parser::isQuote(int position) {
    auto data = m_data[m_ptr];
    if (data[position] != '"') {
        return false;
    }

    if (position >= 2) {
        if (data[position - 1] == '\\' && data[position -2] == '\\') {
            return true;
        }
    }

    if (position >= 1) {
        if (data[position - 1] == '\\') {
            return false;
        }
    }

    return true;
}


QString Parser::readKey(int &pos) {

    QString data = m_data[m_ptr];
    if (data[pos] == '@') {
        pos++;
        return "";
    }

    if (data[pos] == '"') {
        pos++;
        int beginPos = pos;
        for (;pos<data.size() && !isQuote(pos);pos++);
        pos++;
        return data.mid(beginPos, pos - beginPos - 1);
    }

    Q_ASSERT(0);
    return "";
}

void Parser::readEqual(int &pos) {
    Q_ASSERT(m_data[m_ptr][pos++] == '=');
}

RegKey Parser::readType(int &pos, int &hexType) {
    auto data = m_data[m_ptr];
    if (data[pos] == '"') {
        return RegKey::STRING;
    }
    if (data.indexOf("hex",pos) == pos) {
        pos += 3;
        if (data[pos] == '(') {
            hexType = data.mid(pos+1, data.indexOf(')', pos) - pos).toInt();
            pos = data.indexOf(')', pos) + 1;
        }
        //skip ':'
        Q_ASSERT(data[pos] == ':');
        pos++;
        return RegKey::HEX;
    }
    if (data.indexOf("dword:") == pos) {
        pos += 6;
        return RegKey::DWORD;
    }

    qDebug()<<"Cannot get key from position"<<pos<<"data:"<<m_data[m_ptr];
    Q_ASSERT(0);
    return RegKey::UNKNOWN;
}

uint32_t Parser::readDword(int &pos) {
    QString data = m_data[m_ptr].mid(pos, 8);
    qDebug()<<"converting"<<data<<"to Hex";
    return hex2Int(data);
}

QByteArray Parser::readHex(int &pos) {

    QByteArray array;

    QString data = m_data[m_ptr];
    if (data.size() <= pos) {
        qDebug()<<"empty data";
        return array;
    }

    qDebug()<<data;

    while (true) {
        array.append(hex2Int(data.mid(pos, 2)));
        if (data.size() <= pos) {
            break;
        }
        pos += 2;

        if (data[pos] == ',') {
            pos++;
            if (data[pos] == '\\') {
                data = m_data[++m_ptr];
                pos = 0;
                skipWhitespaces(data, pos);
            }
        } else {
            break;
        }
    }

    return array;
}

QString Parser::readString(int &pos) {
    QString data = m_data[m_ptr];
    Q_ASSERT(data[pos] == '"');
    pos++;

    qDebug()<<data.mid(pos);


    int beginPos = pos;
    while (!isQuote(pos)) {
        pos++;
    }

    qDebug()<<"readString"<<data.mid(beginPos, pos - beginPos);

    return data.mid(beginPos, pos - beginPos);
}


uint32_t Parser::hex2Int(QString data) const {
    uint32_t num = 0;
    uint32_t multiplier = 1;
    for (int i=data.size()-1; i>=0; i--) {
        int digit = getHexDigit(data[i]);
        Q_ASSERT(digit != -1);
        num += multiplier * digit;
        multiplier <<= 4;
    }
    return num;
}


int Parser::getHexDigit(QChar c) const {
    if (c.isDigit()) {
        return c.digitValue();
    }
    char ch = c.toLatin1();
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    return -1;
}

void Parser::skipWhitespaces(QString &data, int &pos) {
    while (data[pos].isSpace()) {
        pos++;
    }
}

QString Parser::printableArray(QByteArray arr) {
    if (isDebugMode) {
        QStringList sl;
        if (arr.size() <= 20) {
            for (int i=0;i<arr.size();i++) {
                sl.append(QString::number(arr.at(i), 16));
            }
            return sl.join(",");
        } else {
            for (int i=0;i<10;i++) {
                sl.append(QString::number(arr.at(i), 16));
            }
            sl.append("...");
            for (int i=0;i<10;i++) {
                sl.append(QString::number(arr.at(arr.size() - 10 + i), 16));
            }
            return sl.join(",");
        }
    } else {
        return "";
    }
}

void Parser::replaceHKEY(QSharedPointer<RegNode> node) {

    QMap<QString, QString> m;
    m["HKEY_LOCAL_MACHINE"] = "Machine";
    m["HKEY_CURRENT_USER"] = "User";


    for (auto e: node->nodes()) {
        if (!m.contains(e)) continue;
        auto v = node->getNode(e);
        node->removeNode(e);
        node->insert(m[e], v);
    }

}

