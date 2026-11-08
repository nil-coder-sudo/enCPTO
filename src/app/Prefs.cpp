#include "Prefs.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

#include <algorithm>

Prefs& Prefs::instance() {
    static Prefs p;
    return p;
}

QString Prefs::filePath() {
    return QDir::home().filePath(QStringLiteral(".encpto/ui_prefs.cfg"));
}

void Prefs::load() {
    QFile f(filePath());
    if (!f.open(QIODevice::ReadOnly)) {
        return;
    }
    const QJsonObject o = QJsonDocument::fromJson(f.readAll()).object();
    theme = o.value("theme").toString(theme);
    backgroundImage = o.value("bg_image").toString();
    if (!backgroundImage.isEmpty() && !QFileInfo::exists(backgroundImage)) {
        backgroundImage.clear();
    }
    backgroundOpacity = std::clamp(o.value("bg_opacity").toInt(backgroundOpacity), 0, 100);
    widgetOpacity = std::clamp(o.value("widget_opacity").toInt(widgetOpacity), 0, 100);
    language = o.value("language").toString(language);
    threads = std::clamp(o.value("threads").toInt(threads), 0, 256);
    gpuEnabled = o.value("gpu_enabled").toBool(gpuEnabled);
    gpuDevice = std::clamp(o.value("gpu_device").toInt(gpuDevice), -1, 255);
    const QJsonObject g = o.value("generator").toObject();
    genLength = std::clamp(g.value("length").toInt(genLength), 8, 128);
    genUpper = g.value("upper").toBool(genUpper);
    genLower = g.value("lower").toBool(genLower);
    genDigits = g.value("digits").toBool(genDigits);
    genSymbols = g.value("symbols").toBool(genSymbols);
    genAvoidAmbiguous = g.value("avoid_ambiguous").toBool(genAvoidAmbiguous);
}

void Prefs::save() const {
    QDir().mkpath(QFileInfo(filePath()).path());
    QJsonObject g{{"length", genLength},   {"upper", genUpper},     {"lower", genLower},
                  {"digits", genDigits},   {"symbols", genSymbols}, {"avoid_ambiguous", genAvoidAmbiguous}};
    QJsonObject o{{"theme", theme},
                  {"bg_image", backgroundImage},
                  {"bg_opacity", backgroundOpacity},
                  {"widget_opacity", widgetOpacity},
                  {"language", language},
                  {"threads", threads},
                  {"gpu_enabled", gpuEnabled},
                  {"gpu_device", gpuDevice},
                  {"generator", g}};
    QSaveFile f(filePath());
    if (f.open(QIODevice::WriteOnly)) {
        f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
        f.commit();
        QFile::setPermissions(filePath(), QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    }
}
