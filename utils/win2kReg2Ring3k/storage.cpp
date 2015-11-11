#include "storage.h"

Storage::Storage(QObject *parent) :
    QObject(parent)
{
}

void Storage::store(QSharedPointer<RegNode> root, QIODevice &device) {

    QXmlStreamWriter xml(&device);
    xml.setAutoFormatting(true);

    xml.writeStartDocument();
    xml.writeStartElement("REGISTRY");

    Q_ASSERT(!root.isNull());
    store(root, xml);

    xml.writeEndElement();
    xml.writeEndDocument();
}

void Storage::store(QSharedPointer<RegNode> root, QXmlStreamWriter &xml) {

    auto keys = root->data();
    for (auto k: keys) {
        auto attr = root->getValue(k);
        switch (attr->type()) {
        case RegKey::DWORD: {
            xml.writeStartElement("n");
            xml.writeAttribute("n", k);
            xml.writeCharacters(QString("0x%1").arg(QString::number(attr->dword(), 16)));
            xml.writeEndElement();
        } break;
        case RegKey::HEX: {
            xml.writeStartElement("x");
            xml.writeAttribute("n", k);
            if (attr->hexType() != -1) {
                xml.writeAttribute("t", QString::number(attr->hexType()));
            }
            auto data = attr->hex();
            QString dataHex;
            for (auto e: data) {
                dataHex += safe2Hex(e);
            }
            xml.writeCharacters(dataHex);
            xml.writeEndElement();
        } break;
        case RegKey::STRING: {
            xml.writeStartElement("s");
            xml.writeAttribute("n", k);
            xml.writeCharacters(attr->string());
            xml.writeEndElement();
        } break;
        default:
            Q_ASSERT(0);
        }
    }

    auto nodes = root->nodes();
    for (auto k: nodes) {
        auto attr = root->getNode(k);
        xml.writeStartElement("k");
        xml.writeAttribute("n", k);
        store(attr->node(), xml);
        xml.writeEndElement();
    }

}

QString Storage::safe2Hex(unsigned char byte) {
    auto s = QString::number(byte, 16);
    if (s.size() == 1) {
        return QString("0%1").arg(s);
    }
    return s.mid(s.size() - 2, 2);
}

