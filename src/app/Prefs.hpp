#pragma once

#include <QString>

/// UI preferences, stored as JSON in ~/.encpto/ui_prefs.cfg — the same file
/// and keys the Python v7 used, so existing settings carry over.
class Prefs {
public:
    static Prefs& instance();

    QString theme = QStringLiteral("Dark");
    QString backgroundImage;
    int backgroundOpacity = 60;  // overlay: 0 = image fully visible, 100 = solid theme colour
    int widgetOpacity = 85;      // panels: 0 = transparent, 100 = opaque
    QString language = QStringLiteral("TW");
    int threads = 0;             // 0 = automatic

    // password generator
    int genLength = 24;
    bool genUpper = true, genLower = true, genDigits = true, genSymbols = true, genAvoidAmbiguous = false;

    void load();
    void save() const;
    static QString filePath();

private:
    Prefs() = default;
};
