#pragma once

#include <QFrame>
#include <QLabel>
#include <QPixmap>
#include <QWidget>

#include <vector>

class QPlainTextEdit;
class QPushButton;
class QStackedLayout;
class QToolButton;

/// Window background: theme colour with a faint drafting grid, or the user's
/// image under a theme-coloured overlay.
class BackgroundWidget : public QWidget {
    Q_OBJECT
public:
    explicit BackgroundWidget(QWidget* parent = nullptr);
    void setImage(const QString& path);
    void setOverlay(int percent);

protected:
    void paintEvent(QPaintEvent*) override;
    void resizeEvent(QResizeEvent*) override;

private:
    QPixmap image_;
    QPixmap scaled_;
    int overlay_ = 60;
};

/// "e" in a ring — the enCPTO mark from the website.
class BrandMark : public QWidget {
public:
    explicit BrandMark(QWidget* parent = nullptr);
    QSize sizeHint() const override { return {28, 28}; }

protected:
    void paintEvent(QPaintEvent*) override;
};

/// Four-segment password strength bar.
class StrengthMeter : public QWidget {
public:
    explicit StrengthMeter(QWidget* parent = nullptr);
    void setLevel(int filled, const QColor& color);
    QSize sizeHint() const override { return {200, 6}; }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    int filled_ = 0;
    QColor color_;
};

/// Horizontal bar chart for the benchmark results.
class BenchChart : public QWidget {
public:
    enum class Kind { Stage, Total, Bottleneck, Info };
    struct Row {
        QString label;
        double value = 0;   // bar length (MiB/s); ignored for Info rows
        QString valueText;
        Kind kind = Kind::Stage;
    };
    explicit BenchChart(QWidget* parent = nullptr);
    void setRows(std::vector<Row> rows);
    void setBottleneckLabel(const QString& text) { bottleneckLabel_ = text; update(); }

protected:
    void paintEvent(QPaintEvent*) override;

private:
    std::vector<Row> rows_;
    QString bottleneckLabel_;
};

/// Rounded panel whose background honours the panel-opacity setting.
class Panel : public QFrame {
public:
    explicit Panel(QWidget* parent = nullptr);
};

/// The source area: an empty drafting frame that accepts drops, and once a
/// file/folder is loaded, its name, details and a preview.
class DropZone : public QFrame {
    Q_OBJECT
public:
    explicit DropZone(QWidget* parent = nullptr);

    void showEmpty();
    void showSource(const QString& iconName, const QString& name, const QString& meta);
    void setPreviewImage(const QPixmap& pm);
    void setPreviewText(const QString& text);
    void setPreviewInfo(const QString& text, const QString& iconName = {});
    void retranslate();
    void refreshIcons();
    void setPanelOpacity(int percent);
    void setBusy(bool busy);

signals:
    void pathDropped(const QString& path);
    void chooseFileClicked();
    void chooseFolderClicked();
    void removeClicked();

protected:
    void paintEvent(QPaintEvent*) override;
    void dragEnterEvent(QDragEnterEvent*) override;
    void dragLeaveEvent(QDragLeaveEvent*) override;
    void dropEvent(QDropEvent*) override;
    void resizeEvent(QResizeEvent*) override;

private:
    void updateImage();

    bool hover_ = false;
    bool busy_ = false;
    int opacity_ = 85;
    QString sourceIcon_;
    QString infoIcon_;
    QPixmap fullImage_;

    QStackedLayout* pages_ = nullptr;
    // empty page
    QLabel* dropIcon_ = nullptr;
    QLabel* dropTitle_ = nullptr;
    QLabel* dropSubtitle_ = nullptr;
    QPushButton* chooseFile_ = nullptr;
    QPushButton* chooseFolder_ = nullptr;
    // loaded page
    QLabel* srcIcon_ = nullptr;
    QLabel* srcName_ = nullptr;
    QLabel* srcMeta_ = nullptr;
    QToolButton* remove_ = nullptr;
    QStackedLayout* preview_ = nullptr;
    QLabel* previewImage_ = nullptr;
    QPlainTextEdit* previewText_ = nullptr;
    QLabel* previewInfoIcon_ = nullptr;
    QLabel* previewInfo_ = nullptr;
    QString fullName_;
};
