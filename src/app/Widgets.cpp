#include "Widgets.hpp"

#include "I18n.hpp"
#include "Theme.hpp"

#include <QDragEnterEvent>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QMimeData>
#include <QPainter>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStackedLayout>
#include <QToolButton>
#include <QVBoxLayout>

// ── BackgroundWidget ────────────────────────────────────────────────────

BackgroundWidget::BackgroundWidget(QWidget* parent) : QWidget(parent) {
    setAttribute(Qt::WA_OpaquePaintEvent);
}

void BackgroundWidget::setImage(const QString& path) {
    image_ = path.isEmpty() ? QPixmap() : QPixmap(path);
    scaled_ = {};
    update();
}

void BackgroundWidget::setOverlay(int percent) {
    overlay_ = percent;
    update();
}

void BackgroundWidget::resizeEvent(QResizeEvent* e) {
    scaled_ = {};
    QWidget::resizeEvent(e);
}

void BackgroundWidget::paintEvent(QPaintEvent*) {
    const auto& p = theme::current();
    QPainter painter(this);
    painter.fillRect(rect(), p.bg);

    if (!image_.isNull()) {
        if (scaled_.isNull() || scaled_.size() != size() * devicePixelRatioF()) {
            scaled_ = image_.scaled(size() * devicePixelRatioF(), Qt::KeepAspectRatioByExpanding,
                                    Qt::SmoothTransformation);
            scaled_.setDevicePixelRatio(devicePixelRatioF());
        }
        const QSizeF s = scaled_.deviceIndependentSize();
        painter.drawPixmap(QPointF((width() - s.width()) / 2, (height() - s.height()) / 2), scaled_);
        QColor o = p.bg;
        o.setAlpha(overlay_ * 255 / 100);
        painter.fillRect(rect(), o);
        return;
    }

    // Drafting grid: fine lines every 24 px, stronger every 4th.
    constexpr int cell = 24;
    QColor fine = p.grid;
    QColor major = p.grid.lighter(p.bg.lightness() > 128 ? 100 : 125);
    if (p.bg.lightness() > 128) {
        major = p.grid.darker(108);
    }
    for (int x = 0, i = 0; x < width(); x += cell, ++i) {
        painter.setPen(QPen(i % 4 == 0 ? major : fine, 1));
        painter.drawLine(x, 0, x, height());
    }
    for (int y = 0, i = 0; y < height(); y += cell, ++i) {
        painter.setPen(QPen(i % 4 == 0 ? major : fine, 1));
        painter.drawLine(0, y, width(), y);
    }
}

// ── BrandMark ───────────────────────────────────────────────────────────

BrandMark::BrandMark(QWidget* parent) : QWidget(parent) { setFixedSize(28, 28); }

void BrandMark::paintEvent(QPaintEvent*) {
    const auto& p = theme::current();
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(p.frame, 1.6));
    painter.drawEllipse(QRectF(1.5, 1.5, 25, 25));
    QFont f(theme::monoFamily());
    f.setPixelSize(14);
    f.setBold(true);
    painter.setFont(f);
    painter.setPen(p.frame);
    painter.drawText(rect().adjusted(0, -1, 0, 0), Qt::AlignCenter, QStringLiteral("e"));
}

// ── StrengthMeter ───────────────────────────────────────────────────────

StrengthMeter::StrengthMeter(QWidget* parent) : QWidget(parent) { setFixedHeight(6); }

void StrengthMeter::setLevel(int filled, const QColor& color) {
    filled_ = filled;
    color_ = color;
    update();
}

void StrengthMeter::paintEvent(QPaintEvent*) {
    const auto& p = theme::current();
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(Qt::NoPen);
    constexpr int segments = 4;
    constexpr qreal gap = 6;
    const qreal w = (width() - gap * (segments - 1)) / segments;
    for (int i = 0; i < segments; ++i) {
        painter.setBrush(i < filled_ ? color_ : p.line);
        painter.drawRoundedRect(QRectF(i * (w + gap), 0, w, height()), 3, 3);
    }
}

// ── Panel ───────────────────────────────────────────────────────────────

Panel::Panel(QWidget* parent) : QFrame(parent) { setObjectName("Panel"); }

// ── DropZone ────────────────────────────────────────────────────────────

DropZone::DropZone(QWidget* parent) : QFrame(parent) {
    setAcceptDrops(true);
    setMinimumSize(420, 380);

    pages_ = new QStackedLayout(this);
    pages_->setContentsMargins(0, 0, 0, 0);

    // Empty state
    auto* empty = new QWidget;
    auto* ev = new QVBoxLayout(empty);
    ev->setContentsMargins(40, 40, 40, 40);
    ev->setSpacing(10);
    ev->addStretch(3);
    dropIcon_ = new QLabel;
    dropIcon_->setAlignment(Qt::AlignCenter);
    ev->addWidget(dropIcon_);
    ev->addSpacing(6);
    dropTitle_ = new QLabel;
    dropTitle_->setObjectName("DropTitle");
    dropTitle_->setAlignment(Qt::AlignCenter);
    ev->addWidget(dropTitle_);
    dropSubtitle_ = new QLabel;
    dropSubtitle_->setObjectName("Dim");
    dropSubtitle_->setAlignment(Qt::AlignCenter);
    dropSubtitle_->setWordWrap(true);
    ev->addWidget(dropSubtitle_);
    ev->addSpacing(14);
    auto* buttons = new QHBoxLayout;
    buttons->setSpacing(10);
    buttons->addStretch();
    chooseFile_ = new QPushButton;
    chooseFolder_ = new QPushButton;
    chooseFile_->setCursor(Qt::PointingHandCursor);
    chooseFolder_->setCursor(Qt::PointingHandCursor);
    buttons->addWidget(chooseFile_);
    buttons->addWidget(chooseFolder_);
    buttons->addStretch();
    ev->addLayout(buttons);
    ev->addStretch(4);
    pages_->addWidget(empty);

    // Loaded state
    auto* loaded = new QWidget;
    auto* lv = new QVBoxLayout(loaded);
    lv->setContentsMargins(26, 24, 20, 22);
    lv->setSpacing(14);
    auto* head = new QHBoxLayout;
    head->setSpacing(12);
    srcIcon_ = new QLabel;
    srcIcon_->setFixedSize(36, 36);
    srcIcon_->setAlignment(Qt::AlignCenter);
    head->addWidget(srcIcon_, 0, Qt::AlignTop);
    auto* names = new QVBoxLayout;
    names->setSpacing(2);
    srcName_ = new QLabel;
    srcName_->setObjectName("SourceName");
    srcName_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    srcMeta_ = new QLabel;
    srcMeta_->setObjectName("Dim");
    names->addWidget(srcName_);
    names->addWidget(srcMeta_);
    head->addLayout(names, 1);
    remove_ = new QToolButton;
    remove_->setObjectName("Quiet");
    remove_->setCursor(Qt::PointingHandCursor);
    remove_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    head->addWidget(remove_, 0, Qt::AlignTop);
    lv->addLayout(head);

    auto* rule = new QFrame;
    rule->setFrameShape(QFrame::NoFrame);
    rule->setFixedHeight(1);
    rule->setObjectName("Rule");
    lv->addWidget(rule);

    auto* previewHost = new QWidget;
    preview_ = new QStackedLayout(previewHost);
    previewImage_ = new QLabel;
    previewImage_->setAlignment(Qt::AlignCenter);
    previewImage_->setMinimumSize(1, 1);
    preview_->addWidget(previewImage_);
    previewText_ = new QPlainTextEdit;
    previewText_->setReadOnly(true);
    preview_->addWidget(previewText_);
    auto* infoPage = new QWidget;
    auto* iv = new QVBoxLayout(infoPage);
    iv->addStretch();
    previewInfoIcon_ = new QLabel;
    previewInfoIcon_->setAlignment(Qt::AlignCenter);
    iv->addWidget(previewInfoIcon_);
    iv->addSpacing(8);
    previewInfo_ = new QLabel;
    previewInfo_->setObjectName("Dim");
    previewInfo_->setAlignment(Qt::AlignCenter);
    previewInfo_->setWordWrap(true);
    iv->addWidget(previewInfo_);
    iv->addStretch();
    preview_->addWidget(infoPage);
    lv->addWidget(previewHost, 1);
    pages_->addWidget(loaded);

    connect(chooseFile_, &QPushButton::clicked, this, &DropZone::chooseFileClicked);
    connect(chooseFolder_, &QPushButton::clicked, this, &DropZone::chooseFolderClicked);
    connect(remove_, &QToolButton::clicked, this, &DropZone::removeClicked);

    retranslate();
    refreshIcons();
}

void DropZone::retranslate() {
    dropTitle_->setText(t("drop_title"));
    dropSubtitle_->setText(t("drop_subtitle"));
    chooseFile_->setText(t("choose_file"));
    chooseFolder_->setText(t("choose_folder"));
    remove_->setText(t("remove_source"));
}

void DropZone::refreshIcons() {
    const auto& p = theme::current();
    dropIcon_->setPixmap(theme::pixmap("drop", hover_ ? p.accent : p.frame, 46, devicePixelRatioF()));
    chooseFile_->setIcon(theme::icon("file", p.text, 18));
    chooseFolder_->setIcon(theme::icon("folder", p.text, 18));
    remove_->setIcon(theme::icon("x", p.dim, 16));
    if (!sourceIcon_.isEmpty()) {
        srcIcon_->setPixmap(theme::pixmap(sourceIcon_, p.frame, 32, devicePixelRatioF()));
    }
    if (!infoIcon_.isEmpty()) {
        previewInfoIcon_->setPixmap(theme::pixmap(infoIcon_, p.dim, 40, devicePixelRatioF()));
    }
    update();
}

void DropZone::setPanelOpacity(int percent) {
    opacity_ = percent;
    update();
}

void DropZone::setBusy(bool busy) {
    busy_ = busy;
    setAcceptDrops(!busy);
    remove_->setEnabled(!busy);
    chooseFile_->setEnabled(!busy);
    chooseFolder_->setEnabled(!busy);
}

void DropZone::showEmpty() {
    sourceIcon_.clear();
    fullImage_ = {};
    pages_->setCurrentIndex(0);
    refreshIcons();
}

void DropZone::showSource(const QString& iconName, const QString& name, const QString& meta) {
    sourceIcon_ = iconName;
    fullName_ = name;
    srcName_->setText(srcName_->fontMetrics().elidedText(name, Qt::ElideMiddle, std::max(120, width() - 180)));
    srcName_->setToolTip(name);
    srcMeta_->setText(meta);
    pages_->setCurrentIndex(1);
    refreshIcons();
}

void DropZone::setPreviewImage(const QPixmap& pm) {
    fullImage_ = pm;
    preview_->setCurrentIndex(0);
    updateImage();
}

void DropZone::updateImage() {
    if (fullImage_.isNull()) {
        return;
    }
    const QSize target = previewImage_->size() * devicePixelRatioF();
    QPixmap s = fullImage_.scaled(target, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    s.setDevicePixelRatio(devicePixelRatioF());
    previewImage_->setPixmap(s);
}

void DropZone::setPreviewText(const QString& text) {
    fullImage_ = {};
    previewText_->setPlainText(text);
    preview_->setCurrentIndex(1);
}

void DropZone::setPreviewInfo(const QString& text, const QString& iconName) {
    fullImage_ = {};
    infoIcon_ = iconName;
    previewInfo_->setText(text);
    previewInfoIcon_->setVisible(!iconName.isEmpty());
    preview_->setCurrentIndex(2);
    refreshIcons();
}

void DropZone::resizeEvent(QResizeEvent* e) {
    QFrame::resizeEvent(e);
    if (!fullName_.isEmpty()) {
        srcName_->setText(srcName_->fontMetrics().elidedText(fullName_, Qt::ElideMiddle, std::max(120, width() - 180)));
    }
    updateImage();
}

void DropZone::paintEvent(QPaintEvent*) {
    const auto& p = theme::current();
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    QColor fill = p.surface;
    fill.setAlpha(opacity_ * 255 / 100);
    if (hover_) {
        const auto mix = [](int a, int b) { return (a * 85 + b * 15) / 100; };
        fill = QColor(mix(fill.red(), p.accent.red()), mix(fill.green(), p.accent.green()),
                      mix(fill.blue(), p.accent.blue()), std::max(fill.alpha(), 230));
    }
    QPainterPath path;
    path.addRoundedRect(r, 10, 10);
    painter.fillPath(path, fill);
    painter.setPen(QPen(hover_ ? p.accent : p.line, 1));
    painter.drawPath(path);

    // Registration marks in the corners — the drafting-frame signature.
    const QColor mark = hover_ ? p.accent : p.frame;
    painter.setPen(QPen(mark, 2, Qt::SolidLine, Qt::SquareCap));
    constexpr qreal inset = 12, len = 18;
    const QRectF in = r.adjusted(inset, inset, -inset, -inset);
    const auto corner = [&](QPointF c, qreal dx, qreal dy) {
        painter.drawLine(c, c + QPointF(dx * len, 0));
        painter.drawLine(c, c + QPointF(0, dy * len));
    };
    corner(in.topLeft(), 1, 1);
    corner(in.topRight(), -1, 1);
    corner(in.bottomLeft(), 1, -1);
    corner(in.bottomRight(), -1, -1);

    if (pages_->currentIndex() == 0) {
        // Centre crosshair ticks on the edges, like a drawing sheet.
        painter.setPen(QPen(p.line, 1));
        const QPointF c = r.center();
        painter.drawLine(QPointF(c.x(), in.top() - 4), QPointF(c.x(), in.top() + 6));
        painter.drawLine(QPointF(c.x(), in.bottom() - 6), QPointF(c.x(), in.bottom() + 4));
        painter.drawLine(QPointF(in.left() - 4, c.y()), QPointF(in.left() + 6, c.y()));
        painter.drawLine(QPointF(in.right() - 6, c.y()), QPointF(in.right() + 4, c.y()));
    }
}

void DropZone::dragEnterEvent(QDragEnterEvent* e) {
    if (busy_ || !e->mimeData()->hasUrls()) {
        return;
    }
    for (const QUrl& u : e->mimeData()->urls()) {
        if (u.isLocalFile()) {
            e->acceptProposedAction();
            hover_ = true;
            dropTitle_->setText(t("drop_release"));
            refreshIcons();
            return;
        }
    }
}

void DropZone::dragLeaveEvent(QDragLeaveEvent*) {
    hover_ = false;
    dropTitle_->setText(t("drop_title"));
    refreshIcons();
}

void DropZone::dropEvent(QDropEvent* e) {
    hover_ = false;
    dropTitle_->setText(t("drop_title"));
    refreshIcons();
    for (const QUrl& u : e->mimeData()->urls()) {
        if (u.isLocalFile() && QFileInfo::exists(u.toLocalFile())) {
            e->acceptProposedAction();
            emit pathDropped(u.toLocalFile());
            return;
        }
    }
}
