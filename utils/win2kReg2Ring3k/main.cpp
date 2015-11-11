#include <QCoreApplication>
#include <QFile>
#include <QStringList>
#include <QString>
#include <QDebug>
#include <QSharedPointer>
#include "parser.h"
#include "regnode.h"
#include "storage.h"

bool isDebugMode = false;

void myMessageOutput(QtMsgType type, const QMessageLogContext &context, const QString &msg) {
    QString stringType;
    switch (type) {
    case QtDebugMsg:
        stringType = "D";
        break;
    case QtWarningMsg:
        stringType = "W";
        break;
    case QtCriticalMsg:
        stringType = "C";
        break;
    case QtFatalMsg:
        stringType = "Fatal";
        break;
    default:
        stringType = "Unknown";
    }


    if (type == QtDebugMsg && !isDebugMode) {
        return;
    }

    QString functionName(context.function);
    functionName = functionName.mid(0, functionName.indexOf('('));

    QString logString = QString("[%1] %2:%3 - %4\n")
            .arg(stringType)
            .arg(functionName)
            .arg(context.line)
            .arg(msg);

    QTextStream stderrStream(stderr, QIODevice::WriteOnly);
    stderrStream<<logString;

}

void printHelp() {
    qFatal("\nNo filename specified!\n"
           "Usage: ./win2kReg2Ring3k [options] file\n"
           "Options:\n"
           "    -d      Enable debug log\n"
           "    -h      Print help\n");
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qInstallMessageHandler(myMessageOutput);

    if (a.arguments().size() < 2) {
        printHelp();
        return -1;
    }

    isDebugMode = a.arguments().contains("-d");
    if (a.arguments().contains("-h")) {
        printHelp();
        return 0;
    }

    auto path = a.arguments().last();
    qDebug()<<"Opening file"<<path;

    QFile in(path);
    if (!in.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning()<<"Cannot open file"<<in.fileName();
        return -1;
    }

    QByteArray array;
    while (!in.atEnd()) {
        char c;
        in.getChar(&c);
        if (c == '\n') {
            continue;
        }

        array.append(c);
    }

    in.close();


    QFile out(path + ".new");
    if (!out.open(QIODevice::WriteOnly)) {
        qWarning()<<"Cannot open file"<<in.fileName()<<"for write";
    }

    Parser parser;
    auto root = parser.parse(array);

    qDebug()<<"Successfully parsed, saving";

    Storage storage;
    storage.store(root, out);

    out.close();

    qDebug()<<"Saved";

    return 0;
}
