#include <QCoreApplication>
#include <QFile>
#include <QStringList>
#include <QString>
#include <QDebug>
#include <QSharedPointer>
#include <QCommandLineParser>
#include "abstractparser.h"
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
           "Usage: ./win2kReg2Ring3k [options] file type\n"
           "    file - file name\n"
           "    type - type of input file [regedit | parseWin32Registry]\n"
           "Options:\n"
           "    -d      Enable debug log\n"
           "    -h      Print help\n");
}

QString getTypeDescriptions(QVector<AbstractParser*> parsers) {
    QStringList lst;
    for (auto p: parsers) {
        lst << p->name();
    }
    return QString("[%1]").arg(lst.join("|"));
}

AbstractParser* getParser(QVector<AbstractParser*> parsers, QString type) {
    for (auto p : parsers) {
        if (p->name() == type) {
            return p;
        }
    }
    qFatal("Cannot find parser with name %s\nAborting", type.toLatin1().data());
    exit(-1);
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qInstallMessageHandler(myMessageOutput);

    QCoreApplication::setApplicationName("win2kReg2Ring3k");
    QCoreApplication::setApplicationVersion("1.1");


    QCommandLineParser cmdParser;
    cmdParser.addHelpOption();
    cmdParser.addVersionOption();


    QVector<AbstractParser*> parsers;
    parsers.push_back(new Parser);
    cmdParser.addPositionalArgument("file", "The file name to open");
    cmdParser.addPositionalArgument("type", QString("Type of the file %1").arg(getTypeDescriptions(parsers)));
    auto debugOption = QCommandLineOption("d", "Enable debug log");
    cmdParser.addOption(debugOption);


    cmdParser.process(a);

    isDebugMode = cmdParser.isSet(debugOption);
    auto positionalArgs = cmdParser.positionalArguments();

    if (positionalArgs.length() < 2) {
        qFatal("ERROR: Not enougth arguments. Requested 2");
    }

    auto path = positionalArgs[0];
    auto type = positionalArgs[1];

    AbstractParser *parser = getParser(parsers, type);

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
        /*if (c == '\n') {
            continue;
        }*/

        array.append(c);
    }

    in.close();


    QFile out(path + ".new");
    if (!out.open(QIODevice::WriteOnly)) {
        qWarning()<<"Cannot open file"<<in.fileName()<<"for write";
    }

    qDebug()<<"Start parsing";

    auto root = parser->parse(array);

    qDebug()<<"Successfully parsed, saving";

    Storage storage;
    storage.store(root, out);

    out.close();

    qDebug()<<"Saved";

    return 0;
}
