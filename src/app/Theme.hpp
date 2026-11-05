#pragma once

#include <QColor>
#include <QIcon>
#include <QString>
#include <QStringList>

namespace theme {

/// Theme identifiers (kept identical to v7 so saved preferences still work).
const QStringList& names();

struct Palette {
    QColor bg;        // window
    QColor surface;   // panels
    QColor surface2;  // inputs
    QColor line;      // borders / separators
    QColor grid;      // background drafting grid
    QColor frame;     // drop-zone linework, focus rings
    QColor text;
    QColor dim;
    QColor accent;    // primary action, progress
    QColor onAccent;  // text on accent
    QColor danger;
    QColor warning;
    QColor success;
    bool mono = false;  // terminal theme: monospace everywhere
};

/// "System" / "Auto" → "Dark" or "Light".
QString resolve(const QString& name);
Palette palette(const QString& name);
/// Active palette (set by apply()).
const Palette& current();

/// Builds and installs the application style sheet.
void apply(const QString& name, int panelOpacity);

/// Monochrome SVG icon tinted with `color`.
QIcon icon(const QString& name, const QColor& color, int size = 20);
QPixmap pixmap(const QString& name, const QColor& color, int size, qreal dpr);

QString monoFamily();

}  // namespace theme
