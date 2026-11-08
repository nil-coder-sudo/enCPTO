#include "Theme.hpp"

#include <QApplication>
#include <QDir>
#include <algorithm>
#include <QFile>
#include <QFontDatabase>
#include <QHash>
#include <QPainter>
#include <QPalette>
#include <QStyleHints>
#include <QSvgRenderer>
#include <QTime>

namespace theme {
namespace {

Palette g_current;

QString rgba(const QColor& c, int alphaPercent) {
    return QStringLiteral("rgba(%1,%2,%3,%4)")
        .arg(c.red())
        .arg(c.green())
        .arg(c.blue())
        .arg(QString::number(alphaPercent / 100.0, 'f', 2));
}

bool systemIsDark() {
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    const auto scheme = QGuiApplication::styleHints()->colorScheme();
    if (scheme != Qt::ColorScheme::Unknown) {
        return scheme == Qt::ColorScheme::Dark;
    }
#endif
    const QColor w = QGuiApplication::palette().color(QPalette::Window);
    return (w.red() * 299 + w.green() * 587 + w.blue() * 114) / 1000 < 128;
}

}  // namespace

const QStringList& names() {
    static const QStringList n = {"Dark", "Light", "System", "Auto", "Army Green", "Deep Hacker"};
    return n;
}

QString resolve(const QString& name) {
    if (name == "System") {
        return systemIsDark() ? "Dark" : "Light";
    }
    if (name == "Auto") {
        const int h = QTime::currentTime().hour();
        return (h >= 7 && h < 19) ? "Light" : "Dark";
    }
    return names().contains(name) ? name : "Dark";
}

Palette palette(const QString& name) {
    const QString n = resolve(name);
    Palette p;
    if (n == "Light") {  // drafting paper
        p = {QColor("#EDF2F7"), QColor("#FFFFFF"), QColor("#F5F8FB"), QColor("#C6D3E1"),
             QColor("#DCE5EF"), QColor("#2E6DA4"), QColor("#0B2545"), QColor("#56697F"),
             QColor("#E9A520"), QColor("#1C1405"), QColor("#B9461E"), QColor("#A86A00"),
             QColor("#1F7A4D")};
    } else if (n == "Army Green") {
        p = {QColor("#182011"), QColor("#202B17"), QColor("#28351D"), QColor("#44552F"),
             QColor("#222D18"), QColor("#9DBB5C"), QColor("#DDE6C6"), QColor("#A2B087"),
             QColor("#C9A227"), QColor("#18200F"), QColor("#E06A40"), QColor("#D9B43A"),
             QColor("#8BC34A")};
    } else if (n == "Deep Hacker") {
        p = {QColor("#000000"), QColor("#020D03"), QColor("#041505"), QColor("#0E4A14"),
             QColor("#031A06"), QColor("#00FF41"), QColor("#B4FFC3"), QColor("#4CC064"),
             QColor("#00FF41"), QColor("#000000"), QColor("#FF5533"), QColor("#E5FF00"),
             QColor("#00FF41")};
        p.mono = true;
    } else {  // Dark: blueprint
        p = {QColor("#0A1A33"), QColor("#0F2545"), QColor("#122C52"), QColor("#2A4F7E"),
             QColor("#11284A"), QColor("#6FB8E6"), QColor("#EAF2FA"), QColor("#9FB8D1"),
             QColor("#F5B942"), QColor("#0A1A33"), QColor("#E8724C"), QColor("#F5B942"),
             QColor("#5FC08A")};
    }
    return p;
}

const Palette& current() { return g_current; }

QString monoFamily() {
    const QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    return f.family();
}

void apply(const QString& name, int panelOpacity) {
    g_current = palette(name);
    const Palette& p = g_current;
    const int a = std::clamp(panelOpacity, 0, 100);
    const int inputA = std::min(100, a + 10);

    QPalette pal = QApplication::palette();
    pal.setColor(QPalette::Window, p.bg);
    pal.setColor(QPalette::WindowText, p.text);
    pal.setColor(QPalette::Base, p.surface2);
    pal.setColor(QPalette::AlternateBase, p.surface);
    pal.setColor(QPalette::Text, p.text);
    pal.setColor(QPalette::Button, p.surface2);
    pal.setColor(QPalette::ButtonText, p.text);
    pal.setColor(QPalette::Highlight, p.frame);
    pal.setColor(QPalette::HighlightedText, p.bg);
    pal.setColor(QPalette::PlaceholderText, p.dim);
    pal.setColor(QPalette::ToolTipBase, p.surface);
    pal.setColor(QPalette::ToolTipText, p.text);
    pal.setColor(QPalette::Link, p.frame);
    QApplication::setPalette(pal);

    const QString mono = p.mono ? QStringLiteral("font-family: \"%1\";").arg(monoFamily()) : QString();

    QString qss = QStringLiteral(R"(
* { %MONO% }
QWidget { color: %TEXT%; }
QToolTip { background: %SURF_SOLID%; color: %TEXT%; border: 1px solid %LINE%; padding: 4px 6px; }

#Header { background: transparent; }
#Wordmark { font-size: 17px; font-weight: 700; letter-spacing: 0.5px; }
#Footer { background: %SURF%; border-top: 1px solid %LINE%; }
#Rule { background: %LINE%; border: none; }

QPushButton#Tab { background: transparent; border: none; border-bottom: 2px solid transparent;
                  color: %DIM%; padding: 8px 4px; margin: 0 10px; font-weight: 600; }
QPushButton#Tab:hover { color: %TEXT%; }
QPushButton#Tab:checked { color: %TEXT%; border-bottom: 2px solid %ACCENT%; }

#Panel { background: %SURF%; border: 1px solid %LINE%; border-radius: 10px; }
#PanelTitle { font-size: 15px; font-weight: 700; }
#SectionTitle { font-size: 14px; font-weight: 700; padding: 6px 0px 0px 0px; margin: 0px; }
#Dim, QLabel[dim="true"] { color: %DIM%; }
#Small { color: %DIM%; font-size: 12px; }
#SourceName { font-size: 15px; font-weight: 700; }
#DropTitle { font-size: 18px; font-weight: 700; }

QLineEdit, QComboBox, QSpinBox {
    background: %INPUT%; border: 1px solid %LINE%; border-radius: 7px;
    padding: 8px 10px; selection-background-color: %FRAME%; selection-color: %BG%;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid %FRAME%; }
QLineEdit#Password, QLineEdit#Generated { font-family: "%MONOFAMILY%"; font-size: 15px; padding: 10px 10px; }
QLineEdit#Generated { font-size: 17px; }
QComboBox::drop-down { border: none; width: 26px; }
QComboBox QAbstractItemView { background: %SURF_SOLID%; border: 1px solid %LINE%;
    selection-background-color: %INPUT_SOLID%; selection-color: %TEXT%; outline: none; }

QPushButton { background: %INPUT%; border: 1px solid %LINE%; border-radius: 7px;
              padding: 8px 14px; font-weight: 600; }
QPushButton:hover { border-color: %FRAME%; }
QPushButton:pressed { background: %SURF%; }
QPushButton:disabled { color: %DIM%; border-color: %LINE%; }
QPushButton:focus { border-color: %FRAME%; }
QPushButton#Primary { background: %ACCENT%; color: %ONACCENT%; border: 1px solid %ACCENT%;
                      padding: 11px 16px; font-size: 15px; }
QPushButton#Primary:hover { background: %ACCENT_HOVER%; }
QPushButton#Primary:disabled { background: %LINE%; border-color: %LINE%; color: %DIM%; }
QPushButton#Secondary { padding: 11px 16px; font-size: 15px; }
QPushButton#Quiet, QToolButton#Quiet { background: transparent; border: 1px solid transparent; color: %DIM%; padding: 6px 10px; }
QPushButton#Quiet:hover, QToolButton#Quiet:hover { color: %TEXT%; border-color: %LINE%; }
QPushButton#Quiet:disabled, QToolButton#Quiet:disabled { color: %LINE%; border-color: transparent; }
QPushButton#Link { background: transparent; border: none; color: %FRAME%; padding: 2px 4px; font-weight: 600; }
QPushButton#Link:hover { text-decoration: underline; }
QPushButton#Danger { color: %DANGER%; }

QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid %LINE%; border-radius: 4px; background: %INPUT%; }
QCheckBox::indicator:hover { border-color: %FRAME%; }
QCheckBox::indicator:checked { background: %ACCENT%; border-color: %ACCENT%; image: url(%CHECK%); }

QSlider::groove:horizontal { height: 4px; background: %LINE%; border-radius: 2px; }
QSlider::sub-page:horizontal { background: %FRAME%; border-radius: 2px; }
QSlider::handle:horizontal { background: %TEXT%; width: 14px; height: 14px; margin: -6px 0; border-radius: 7px; }

QProgressBar { background: %LINE%; border: none; border-radius: 2px; max-height: 4px; min-height: 4px; }
QProgressBar::chunk { background: %ACCENT%; border-radius: 2px; }

QTextEdit, QPlainTextEdit { background: transparent; border: none; font-family: "%MONOFAMILY%"; font-size: 12px; color: %DIM%; }
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: %LINE%; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QMessageBox { background: %SURF_SOLID%; }
)");

    // Tick image for checkboxes, rendered to a temp PNG in the accent-text colour.
    static QString checkPath;
    {
        const QString path = QDir::temp().filePath(QStringLiteral("encpto-check-%1.png").arg(p.onAccent.name().mid(1)));
        if (!QFile::exists(path)) {
            pixmap("check", p.onAccent, 16, 2.0).save(path);
        }
        checkPath = path;
    }

    const QColor accentHover = p.accent.lighter(112);
    const QHash<QString, QString> vars = {
        {"%MONO%", mono},
        {"%MONOFAMILY%", monoFamily()},
        {"%TEXT%", p.text.name()},
        {"%DIM%", p.dim.name()},
        {"%BG%", p.bg.name()},
        {"%LINE%", p.line.name()},
        {"%FRAME%", p.frame.name()},
        {"%ACCENT%", p.accent.name()},
        {"%ACCENT_HOVER%", accentHover.name()},
        {"%ONACCENT%", p.onAccent.name()},
        {"%DANGER%", p.danger.name()},
        {"%SURF%", rgba(p.surface, a)},
        {"%SURF_SOLID%", p.surface.name()},
        {"%INPUT%", rgba(p.surface2, inputA)},
        {"%INPUT_SOLID%", p.surface2.name()},
        {"%CHECK%", QString(checkPath).replace('\\', '/')},
    };
    for (auto it = vars.constBegin(); it != vars.constEnd(); ++it) {
        qss.replace(it.key(), it.value());
    }
    qApp->setStyleSheet(qss);
}

QPixmap pixmap(const QString& name, const QColor& color, int size, qreal dpr) {
    QFile f(QStringLiteral(":/icons/%1.svg").arg(name));
    if (!f.open(QIODevice::ReadOnly)) {
        return {};
    }
    QByteArray svg = f.readAll();
    svg.replace("currentColor", color.name().toLatin1());
    QSvgRenderer r(svg);
    QPixmap pm(QSize(size, size) * dpr);
    pm.fill(Qt::transparent);
    QPainter painter(&pm);
    painter.setRenderHint(QPainter::Antialiasing);
    r.render(&painter);
    painter.end();
    pm.setDevicePixelRatio(dpr);
    return pm;
}

QIcon icon(const QString& name, const QColor& color, int size) {
    QIcon i;
    i.addPixmap(pixmap(name, color, size, 1.0));
    i.addPixmap(pixmap(name, color, size, 2.0));
    return i;
}

}  // namespace theme
