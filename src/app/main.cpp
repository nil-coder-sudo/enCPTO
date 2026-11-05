// enCPTO desktop application

#include "MainWindow.hpp"
#include "Prefs.hpp"

#include <encpto/crypto.hpp>
#include <encpto/version.hpp>

#include <QApplication>
#include <QFont>
#include <QIcon>
#include <QStyleFactory>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("enCPTO"));
    QApplication::setApplicationVersion(QStringLiteral(ENCPTO_VERSION));
    QApplication::setOrganizationName(QStringLiteral("nil-coder"));
    QApplication::setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    QApplication::setWindowIcon(QIcon(QStringLiteral(":/app-icon.svg")));

    QFont font = QApplication::font();
    if (font.pointSizeF() > 0 && font.pointSizeF() < 10) {
        font.setPointSizeF(10);
        QApplication::setFont(font);
    }

    encpto::crypto::init();
    Prefs::instance().load();

    MainWindow w;
    w.show();
    const QStringList args = QApplication::arguments();
    if (args.size() > 1) {
        w.loadPath(args.at(1));  // "Open with enCPTO" / drag onto the app icon
    }
    return QApplication::exec();
}
