#include "MainWindow.hpp"

#include "I18n.hpp"
#include "Prefs.hpp"
#include "Theme.hpp"
#include "Widgets.hpp"

#include <encpto/engine.hpp>
#include <encpto/gpu.hpp>
#include <encpto/fsutil.hpp>
#include <encpto/password.hpp>
#include <encpto/secure_memory.hpp>
#include <encpto/shred.hpp>
#include <encpto/version.hpp>

#include <QAction>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QImageReader>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSlider>
#include <QStackedWidget>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include <cmath>
#include <thread>

namespace fs = std::filesystem;
using encpto::ErrorCode;
using encpto::Phase;

namespace {

fs::path toPath(const QString& s) { return encpto::fsutil::from_utf8(s.toStdString()); }
QString fromPath(const fs::path& p) { return QString::fromStdString(encpto::fsutil::to_utf8(p)); }
QString human(std::uint64_t n) { return QString::fromStdString(encpto::fsutil::human_size(n)); }

const char* phaseKey(int phase) {
    switch (static_cast<Phase>(phase)) {
        case Phase::DerivingKey: return "phase_kdf";
        case Phase::Packing: return "phase_pack";
        case Phase::Encrypting: return "phase_encrypt";
        case Phase::Verifying: return "phase_verify";
        case Phase::Decrypting: return "phase_decrypt";
        case Phase::Extracting: return "phase_extract";
        case Phase::Shredding: return "phase_shred";
    }
    return "status_ready";
}

QLabel* label(const QString& objectName = {}, bool wrap = false) {
    auto* l = new QLabel;
    if (!objectName.isEmpty()) l->setObjectName(objectName);
    l->setWordWrap(wrap);
    return l;
}

QFrame* rule() {
    auto* r = new QFrame;
    r->setObjectName("Rule");
    r->setFixedHeight(1);
    return r;
}

/// Wipes a QByteArray holding a password.
struct PasswordBytes {
    QByteArray bytes;
    explicit PasswordBytes(const QString& s) : bytes(s.toUtf8()) {}
    ~PasswordBytes() { encpto::secure_zero(bytes.data(), static_cast<std::size_t>(bytes.size())); }
    [[nodiscard]] std::string_view view() const { return {bytes.constData(), static_cast<std::size_t>(bytes.size())}; }
};

}  // namespace

// ═══════════════════════════════════════════════════════════════════════
//  Construction
// ═══════════════════════════════════════════════════════════════════════

MainWindow::MainWindow() {
    auto& prefs = Prefs::instance();
    i18n::setLanguage(i18n::fromCode(prefs.language));
    theme::apply(prefs.theme, prefs.widgetOpacity);

    background_ = new BackgroundWidget;
    background_->setImage(prefs.backgroundImage);
    background_->setOverlay(prefs.backgroundOpacity);
    auto* root = new QVBoxLayout(background_);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    root->addWidget(buildHeader());

    pages_ = new QStackedWidget;
    pages_->addWidget(buildMainPage());
    pages_->addWidget(buildGeneratorPage());
    pages_->addWidget(buildSettingsPage());
    root->addWidget(pages_, 1);
    root->addWidget(buildFooter());
    setCentralWidget(background_);

    resize(1060, 720);
    setMinimumSize(900, 620);

    autoThemeTimer_ = new QTimer(this);
    connect(autoThemeTimer_, &QTimer::timeout, this, [this] {
        const QString name = Prefs::instance().theme;
        if ((name == "Auto" || name == "System") &&
            theme::palette(name).bg != theme::current().bg) {
            applyTheme();
        }
    });
    autoThemeTimer_->start(60'000);

    retranslate();
    refreshIcons();
    clearSource();
    setStatus(Status::Idle, t("status_ready"));
    password_->setFocus();
}

QWidget* MainWindow::buildHeader() {
    auto* header = new QWidget;
    header->setObjectName("Header");
    auto* h = new QHBoxLayout(header);
    h->setContentsMargins(24, 14, 18, 6);
    h->setSpacing(10);

    h->addWidget(new BrandMark);
    wordmark_ = new QLabel(QStringLiteral("enCPTO"));
    wordmark_->setObjectName("Wordmark");
    wordmark_->setStyleSheet(QStringLiteral("font-family: \"%1\";").arg(theme::monoFamily()));
    h->addWidget(wordmark_);
    h->addSpacing(28);

    tabs_ = new QButtonGroup(this);
    tabs_->setExclusive(true);
    const auto makeTab = [&](int index) {
        auto* b = new QPushButton;
        b->setObjectName("Tab");
        b->setCheckable(true);
        b->setCursor(Qt::PointingHandCursor);
        tabs_->addButton(b, index);
        h->addWidget(b);
        return b;
    };
    tabMain_ = makeTab(0);
    tabGen_ = makeTab(1);
    tabSettings_ = makeTab(2);
    tabMain_->setChecked(true);
    connect(tabs_, &QButtonGroup::idClicked, this, [this](int id) { pages_->setCurrentIndex(id); });

    h->addStretch();
    langButton_ = new QPushButton;
    langButton_->setObjectName("Quiet");
    langButton_->setCursor(Qt::PointingHandCursor);
    connect(langButton_, &QPushButton::clicked, this, [this] {
        const auto next = i18n::language() == i18n::Lang::En ? i18n::Lang::ZhTW : i18n::Lang::En;
        i18n::setLanguage(next);
        Prefs::instance().language = i18n::code(next);
        Prefs::instance().save();
        retranslate();
    });
    h->addWidget(langButton_);
    return header;
}

QWidget* MainWindow::buildMainPage() {
    auto* page = new QWidget;
    auto* h = new QHBoxLayout(page);
    h->setContentsMargins(24, 14, 24, 20);
    h->setSpacing(18);

    drop_ = new DropZone;
    h->addWidget(drop_, 1);
    connect(drop_, &DropZone::pathDropped, this, &MainWindow::loadPath);
    connect(drop_, &DropZone::chooseFileClicked, this, &MainWindow::chooseFile);
    connect(drop_, &DropZone::chooseFolderClicked, this, &MainWindow::chooseFolder);
    connect(drop_, &DropZone::removeClicked, this, &MainWindow::clearSource);

    keyPanel_ = new Panel;
    keyPanel_->setFixedWidth(350);
    auto* v = new QVBoxLayout(keyPanel_);
    v->setContentsMargins(22, 22, 22, 22);
    v->setSpacing(10);

    keyTitle_ = label("PanelTitle");
    v->addWidget(keyTitle_);

    password_ = new QLineEdit;
    password_->setObjectName("Password");
    password_->setEchoMode(QLineEdit::Password);
    password_->setClearButtonEnabled(false);
    toggleEcho_ = password_->addAction(QIcon(), QLineEdit::TrailingPosition);
    quickGenerate_ = password_->addAction(QIcon(), QLineEdit::TrailingPosition);
    connect(toggleEcho_, &QAction::triggered, this, [this] {
        password_->setEchoMode(password_->echoMode() == QLineEdit::Password ? QLineEdit::Normal
                                                                             : QLineEdit::Password);
        refreshIcons();
        toggleEcho_->setToolTip(password_->echoMode() == QLineEdit::Password ? t("show_password")
                                                                             : t("hide_password"));
    });
    connect(quickGenerate_, &QAction::triggered, this, [this] {
        generatePassword();
        password_->setText(genOutput_->text());
        password_->setEchoMode(QLineEdit::Normal);
        refreshIcons();
        toggleEcho_->setToolTip(t("hide_password"));
    });
    connect(password_, &QLineEdit::textChanged, this, &MainWindow::updatePasswordFeedback);
    connect(shred_ = new QCheckBox, &QCheckBox::toggled, this, &MainWindow::updateActions);
    connect(password_, &QLineEdit::returnPressed, this, [this] {
        if (source_ == Source::Container) startDecrypt();
        else if (source_ == Source::File || source_ == Source::Folder) startEncrypt();
    });
    v->addWidget(password_);
    v->addSpacing(2);
    meter_ = new StrengthMeter;
    v->addWidget(meter_);
    strengthText_ = label("Small", true);
    v->addWidget(strengthText_);

    decryptHint_ = label("Small", true);
    v->addWidget(decryptHint_);

    v->addSpacing(10);
    shred_->setCursor(Qt::PointingHandCursor);
    v->addWidget(shred_);
    shredHint_ = label("Small", true);
    shredHint_->setContentsMargins(26, 0, 0, 0);
    v->addWidget(shredHint_);

    v->addStretch(1);
    auto* noteRow = new QHBoxLayout;
    noteRow->setSpacing(8);
    recoveryIcon_ = new QLabel;
    recoveryIcon_->setFixedSize(18, 18);
    noteRow->addWidget(recoveryIcon_, 0, Qt::AlignTop);
    recoveryNote_ = label("Small", true);
    noteRow->addWidget(recoveryNote_, 1);
    v->addLayout(noteRow);
    v->addSpacing(8);

    encrypt_ = new QPushButton;
    encrypt_->setObjectName("Primary");
    encrypt_->setCursor(Qt::PointingHandCursor);
    connect(encrypt_, &QPushButton::clicked, this, &MainWindow::startEncrypt);
    v->addWidget(encrypt_);
    decrypt_ = new QPushButton;
    decrypt_->setObjectName("Primary");
    decrypt_->setCursor(Qt::PointingHandCursor);
    connect(decrypt_, &QPushButton::clicked, this, &MainWindow::startDecrypt);
    v->addWidget(decrypt_);

    h->addWidget(keyPanel_);
    return page;
}

QWidget* MainWindow::buildGeneratorPage() {
    auto& prefs = Prefs::instance();
    auto* page = new QWidget;
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(24, 14, 24, 20);
    auto* panel = new Panel;
    panel->setMaximumWidth(720);
    auto* centre = new QHBoxLayout;
    centre->addStretch(1);
    centre->addWidget(panel, 4);
    centre->addStretch(1);
    outer->addLayout(centre);
    outer->addStretch();

    auto* v = new QVBoxLayout(panel);
    v->setContentsMargins(28, 26, 28, 26);
    v->setSpacing(12);
    genHeading_ = label("PanelTitle");
    v->addWidget(genHeading_);
    genIntro_ = label("Dim", true);
    v->addWidget(genIntro_);
    v->addSpacing(6);

    auto* outRow = new QHBoxLayout;
    outRow->setSpacing(8);
    genOutput_ = new QLineEdit;
    genOutput_->setObjectName("Generated");
    genOutput_->setReadOnly(true);
    genOutput_->setMinimumWidth(460);
    outRow->addWidget(genOutput_, 1);
    genCopy_ = new QPushButton;
    outRow->addWidget(genCopy_);
    v->addLayout(outRow);
    genMeter_ = new StrengthMeter;
    v->addWidget(genMeter_);
    genStrength_ = label("Small");
    v->addWidget(genStrength_);
    v->addSpacing(8);

    genLengthLabel_ = label();
    v->addWidget(genLengthLabel_);
    genLength_ = new QSlider(Qt::Horizontal);
    genLength_->setRange(8, 128);
    genLength_->setValue(prefs.genLength);
    v->addWidget(genLength_);

    auto* grid = new QGridLayout;
    grid->setHorizontalSpacing(24);
    grid->setVerticalSpacing(8);
    genUpper_ = new QCheckBox;
    genLower_ = new QCheckBox;
    genDigits_ = new QCheckBox;
    genSymbols_ = new QCheckBox;
    genAmbiguous_ = new QCheckBox;
    genUpper_->setChecked(prefs.genUpper);
    genLower_->setChecked(prefs.genLower);
    genDigits_->setChecked(prefs.genDigits);
    genSymbols_->setChecked(prefs.genSymbols);
    genAmbiguous_->setChecked(prefs.genAvoidAmbiguous);
    grid->addWidget(genUpper_, 0, 0);
    grid->addWidget(genLower_, 0, 1);
    grid->addWidget(genDigits_, 1, 0);
    grid->addWidget(genSymbols_, 1, 1);
    grid->addWidget(genAmbiguous_, 2, 0, 1, 2);
    v->addLayout(grid);
    v->addSpacing(10);

    auto* actions = new QHBoxLayout;
    actions->setSpacing(10);
    genNew_ = new QPushButton;
    genNew_->setObjectName("Primary");
    genUse_ = new QPushButton;
    genUse_->setObjectName("Secondary");
    actions->addWidget(genNew_);
    actions->addWidget(genUse_);
    actions->addStretch();
    v->addLayout(actions);
    genFeedback_ = label("Small", true);
    v->addWidget(genFeedback_);

    for (QCheckBox* c : {genUpper_, genLower_, genDigits_, genSymbols_, genAmbiguous_}) {
        c->setCursor(Qt::PointingHandCursor);
        connect(c, &QCheckBox::toggled, this, [this] {
            saveGeneratorPrefs();
            generatePassword();
        });
    }
    connect(genLength_, &QSlider::valueChanged, this, [this] {
        genLengthLabel_->setText(t("gen_length", genLength_->value()));
        saveGeneratorPrefs();
        generatePassword();
    });
    connect(genNew_, &QPushButton::clicked, this, &MainWindow::generatePassword);
    connect(genCopy_, &QPushButton::clicked, this, [this] {
        const QString pwd = genOutput_->text();
        if (pwd.isEmpty()) return;
        QApplication::clipboard()->setText(pwd);
        genFeedback_->setText(t("gen_copied"));
        QTimer::singleShot(30'000, this, [pwd] {
            if (QApplication::clipboard()->text() == pwd) QApplication::clipboard()->clear();
        });
    });
    connect(genUse_, &QPushButton::clicked, this, [this] {
        if (genOutput_->text().isEmpty()) return;
        password_->setText(genOutput_->text());
        genFeedback_->setText(t("gen_used"));
        tabMain_->setChecked(true);
        pages_->setCurrentIndex(0);
    });

    generatePassword();
    return page;
}

QWidget* MainWindow::buildSettingsPage() {
    auto& prefs = Prefs::instance();
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* page = new QWidget;
    scroll->setWidget(page);
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(24, 14, 24, 20);
    auto* panel = new Panel;
    panel->setMaximumWidth(720);
    panel->setMinimumWidth(560);
    auto* centre = new QHBoxLayout;
    centre->addStretch(1);
    centre->addWidget(panel, 4);
    centre->addStretch(1);
    outer->addLayout(centre);
    outer->addStretch();

    auto* v = new QVBoxLayout(panel);
    v->setContentsMargins(28, 24, 28, 28);
    v->setSpacing(10);

    // Appearance
    setAppearance_ = label("PanelTitle");
    v->addWidget(setAppearance_);
    auto* form = new QGridLayout;
    form->setHorizontalSpacing(18);
    form->setVerticalSpacing(12);
    form->setColumnStretch(1, 1);
    setThemeLabel_ = label();
    themeBox_ = new QComboBox;
    for (const QString& n : theme::names()) themeBox_->addItem(QString(), n);
    themeBox_->setCurrentIndex(std::max<int>(0, static_cast<int>(theme::names().indexOf(prefs.theme))));
    form->addWidget(setThemeLabel_, 0, 0);
    form->addWidget(themeBox_, 0, 1);

    setBgLabel_ = label();
    auto* bgRow = new QHBoxLayout;
    bgRow->setSpacing(8);
    bgPath_ = label("Dim");
    bgPath_->setMinimumWidth(120);
    bgChoose_ = new QPushButton;
    bgClear_ = new QPushButton;
    bgClear_->setObjectName("Quiet");
    bgRow->addWidget(bgPath_, 1);
    bgRow->addWidget(bgChoose_);
    bgRow->addWidget(bgClear_);
    form->addWidget(setBgLabel_, 1, 0);
    form->addLayout(bgRow, 1, 1);
    v->addLayout(form);

    overlayLabel_ = label();
    overlay_ = new QSlider(Qt::Horizontal);
    overlay_->setRange(0, 100);
    overlay_->setValue(prefs.backgroundOpacity);
    overlayHint_ = label("Small", true);
    panelLabel_ = label();
    panelOpacity_ = new QSlider(Qt::Horizontal);
    panelOpacity_->setRange(0, 100);
    panelOpacity_->setValue(prefs.widgetOpacity);
    panelHint_ = label("Small", true);
    v->addSpacing(4);
    v->addWidget(overlayLabel_);
    v->addWidget(overlay_);
    v->addWidget(overlayHint_);
    v->addSpacing(4);
    v->addWidget(panelLabel_);
    v->addWidget(panelOpacity_);
    v->addWidget(panelHint_);

    v->addSpacing(10);
    v->addWidget(rule());
    v->addSpacing(6);

    // Performance
    setPerformance_ = label("PanelTitle");
    v->addWidget(setPerformance_);
    auto* perf = new QHBoxLayout;
    threadsLabel_ = label();
    threadsBox_ = new QComboBox;
    const unsigned hw = std::max(1U, std::thread::hardware_concurrency());
    threadsBox_->addItem(QString(), 0);
    for (unsigned n : {1U, 2U, 4U, 8U, 16U, 32U, 64U}) {
        if (n <= hw * 2) threadsBox_->addItem(QString::number(n), n);
    }
    threadsBox_->setCurrentIndex(std::max(0, threadsBox_->findData(prefs.threads)));
    perf->addWidget(threadsLabel_);
    perf->addSpacing(12);
    perf->addWidget(threadsBox_);
    perf->addStretch();
    v->addLayout(perf);
    threadsHint_ = label("Small", true);
    v->addWidget(threadsHint_);

    v->addSpacing(10);
    v->addWidget(rule());
    v->addSpacing(6);

    // Experimental: GPU + benchmark
    setExperimental_ = label("PanelTitle");
    v->addWidget(setExperimental_);
    gpuEnable_ = new QCheckBox;
    gpuEnable_->setCursor(Qt::PointingHandCursor);
    gpuEnable_->setChecked(prefs.gpuEnabled);
    v->addWidget(gpuEnable_);
    auto* devRow = new QHBoxLayout;
    devRow->setContentsMargins(26, 0, 0, 0);
    gpuDeviceLabel_ = label();
    gpuDeviceBox_ = new QComboBox;
    gpuDeviceBox_->setMinimumWidth(280);
    devRow->addWidget(gpuDeviceLabel_);
    devRow->addSpacing(12);
    devRow->addWidget(gpuDeviceBox_, 1);
    v->addLayout(devRow);
    gpuStatus_ = label("Small", true);
    gpuStatus_->setContentsMargins(26, 0, 0, 0);
    v->addWidget(gpuStatus_);
    gpuWarning_ = label("Small", true);
    gpuWarning_->setContentsMargins(26, 0, 0, 0);
    v->addWidget(gpuWarning_);

    v->addSpacing(8);
    benchTitle_ = label("SectionTitle");
    v->addWidget(benchTitle_);
    benchIntro_ = label("Small", true);
    v->addWidget(benchIntro_);
    auto* benchRow = new QHBoxLayout;
    benchRun_ = new QPushButton;
    benchRun_->setCursor(Qt::PointingHandCursor);
    benchRow->addWidget(benchRun_);
    benchRow->addStretch();
    v->addLayout(benchRow);
    benchChart_ = new BenchChart;
    benchChart_->setVisible(false);
    v->addSpacing(4);
    v->addWidget(benchChart_);
    benchSummary_ = label(QString(), true);
    benchSummary_->setVisible(false);
    v->addWidget(benchSummary_);
    benchDetails_ = label("Small", true);
    benchDetails_->setVisible(false);
    v->addWidget(benchDetails_);

    connect(gpuEnable_, &QCheckBox::toggled, this, [this](bool on) {
        Prefs::instance().gpuEnabled = on;
        Prefs::instance().save();
        refreshGpuControls();
    });
    connect(gpuDeviceBox_, &QComboBox::activated, this, [this](int i) {
        Prefs::instance().gpuDevice = gpuDeviceBox_->itemData(i).toInt();
        Prefs::instance().save();
    });
    connect(benchRun_, &QPushButton::clicked, this, &MainWindow::runBenchmark);

    v->addSpacing(10);
    v->addWidget(rule());
    v->addSpacing(6);

    // About
    setAbout_ = label("PanelTitle");
    v->addWidget(setAbout_);
    aboutBody_ = label("Dim", true);
    aboutBody_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(aboutBody_);
    aboutLink_ = label();
    aboutLink_->setOpenExternalLinks(true);
    v->addWidget(aboutLink_);

    connect(themeBox_, &QComboBox::currentIndexChanged, this, [this](int i) {
        Prefs::instance().theme = themeBox_->itemData(i).toString();
        Prefs::instance().save();
        applyTheme();
    });
    connect(bgChoose_, &QPushButton::clicked, this, [this] {
        const QString f = QFileDialog::getOpenFileName(this, t("set_background"), QString(),
                                                       QStringLiteral("Images (*.png *.jpg *.jpeg *.bmp *.webp *.gif)"));
        if (f.isEmpty()) return;
        Prefs::instance().backgroundImage = f;
        Prefs::instance().save();
        background_->setImage(f);
        retranslate();
    });
    connect(bgClear_, &QPushButton::clicked, this, [this] {
        Prefs::instance().backgroundImage.clear();
        Prefs::instance().save();
        background_->setImage({});
        retranslate();
    });
    connect(overlay_, &QSlider::valueChanged, this, [this](int value) {
        Prefs::instance().backgroundOpacity = value;
        background_->setOverlay(value);
        overlayLabel_->setText(t("set_overlay", value));
    });
    connect(overlay_, &QSlider::sliderReleased, this, [] { Prefs::instance().save(); });
    connect(panelOpacity_, &QSlider::valueChanged, this, [this](int value) {
        Prefs::instance().widgetOpacity = value;
        panelLabel_->setText(t("set_panel_opacity", value));
        theme::apply(Prefs::instance().theme, value);
        drop_->setPanelOpacity(value);
    });
    connect(panelOpacity_, &QSlider::sliderReleased, this, [] { Prefs::instance().save(); });
    connect(threadsBox_, &QComboBox::currentIndexChanged, this, [this](int i) {
        Prefs::instance().threads = threadsBox_->itemData(i).toInt();
        Prefs::instance().save();
    });
    return scroll;
}

QWidget* MainWindow::buildFooter() {
    auto* footer = new QWidget;
    footer->setObjectName("Footer");
    footer->setAttribute(Qt::WA_StyledBackground);
    footer->setFixedHeight(54);
    auto* h = new QHBoxLayout(footer);
    h->setContentsMargins(24, 0, 18, 0);
    h->setSpacing(10);
    statusIcon_ = new QLabel;
    statusIcon_->setFixedSize(18, 18);
    h->addWidget(statusIcon_);
    statusText_ = new QLabel;
    statusText_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusText_->setMinimumWidth(180);
    h->addWidget(statusText_, 1);
    progress_ = new QProgressBar;
    progress_->setRange(0, 1000);
    progress_->setTextVisible(false);
    progress_->setFixedWidth(260);
    h->addWidget(progress_);
    speed_ = label("Small");
    speed_->setMinimumWidth(90);
    speed_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    h->addWidget(speed_);
    showInFolder_ = new QPushButton;
    showInFolder_->setObjectName("Link");
    showInFolder_->setCursor(Qt::PointingHandCursor);
    connect(showInFolder_, &QPushButton::clicked, this, [this] {
        if (lastResult_.isEmpty()) return;
        QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(lastResult_).absolutePath()));
    });
    h->addWidget(showInFolder_);
    cancel_ = new QPushButton;
    cancel_->setObjectName("Quiet");
    cancel_->setCursor(Qt::PointingHandCursor);
    connect(cancel_, &QPushButton::clicked, this, [this] {
        if (task_) task_->cancel();
        cancel_->setEnabled(false);
    });
    h->addWidget(cancel_);
    return footer;
}

// ═══════════════════════════════════════════════════════════════════════
//  Presentation
// ═══════════════════════════════════════════════════════════════════════

void MainWindow::applyTheme() {
    const auto& prefs = Prefs::instance();
    theme::apply(prefs.theme, prefs.widgetOpacity);
    drop_->setPanelOpacity(prefs.widgetOpacity);
    refreshIcons();
    updatePasswordFeedback();
    refreshGpuControls();
    showBenchmark();
    background_->update();
    setStatus(status_, statusText_->text());
}

void MainWindow::refreshIcons() {
    const auto& p = theme::current();
    const bool shown = password_->echoMode() == QLineEdit::Normal;
    toggleEcho_->setIcon(theme::icon(shown ? "eye-off" : "eye", p.dim, 18));
    quickGenerate_->setIcon(theme::icon("dice", p.dim, 18));
    langButton_->setIcon(theme::icon("globe", p.dim, 16));
    recoveryIcon_->setPixmap(theme::pixmap("key", p.dim, 16, devicePixelRatioF()));
    encrypt_->setIcon(theme::icon("lock", p.onAccent, 18));
    decrypt_->setIcon(theme::icon("unlock", p.onAccent, 18));
    genNew_->setIcon(theme::icon("dice", p.onAccent, 18));
    genCopy_->setIcon(theme::icon("copy", p.text, 16));
    genUse_->setIcon(theme::icon("key", p.text, 16));
    bgChoose_->setIcon(theme::icon("image", p.text, 16));
    cancel_->setIcon(theme::icon("x", p.dim, 14));
    drop_->refreshIcons();
}

void MainWindow::retranslate() {
    setWindowTitle(t("window_title"));
    tabMain_->setText(t("tab_main"));
    tabGen_->setText(t("tab_generator"));
    tabSettings_->setText(t("tab_settings"));
    langButton_->setText(t("switch_language"));
    langButton_->setToolTip(t("switch_language_tip"));
    drop_->retranslate();

    keyTitle_->setText(t("password"));
    password_->setPlaceholderText(t("password_placeholder"));
    toggleEcho_->setToolTip(password_->echoMode() == QLineEdit::Password ? t("show_password") : t("hide_password"));
    quickGenerate_->setToolTip(t("generate_password"));
    decryptHint_->setText(t("decrypt_hint"));
    shred_->setText(t("shred_option"));
    shredHint_->setText(t("shred_hint"));
    recoveryNote_->setText(t("no_password_recovery"));
    encrypt_->setText(t("encrypt"));
    decrypt_->setText(t("decrypt"));
    showInFolder_->setText(t("show_in_folder"));
    cancel_->setText(t("cancel"));

    genHeading_->setText(t("gen_heading"));
    genIntro_->setText(t("gen_intro"));
    genLengthLabel_->setText(t("gen_length", genLength_->value()));
    genUpper_->setText(t("gen_upper"));
    genLower_->setText(t("gen_lower"));
    genDigits_->setText(t("gen_digits"));
    genSymbols_->setText(t("gen_symbols"));
    genAmbiguous_->setText(t("gen_ambiguous"));
    genNew_->setText(t("gen_new"));
    genCopy_->setText(t("gen_copy"));
    genUse_->setText(t("gen_use"));
    genFeedback_->clear();

    setAppearance_->setText(t("set_appearance"));
    setThemeLabel_->setText(t("set_theme"));
    for (int i = 0; i < themeBox_->count(); ++i) {
        themeBox_->setItemText(i, t(("theme_" + themeBox_->itemData(i).toString()).toUtf8().constData()));
    }
    setBgLabel_->setText(t("set_background"));
    const QString bg = Prefs::instance().backgroundImage;
    bgPath_->setText(bg.isEmpty() ? t("set_background_none") : QFileInfo(bg).fileName());
    bgPath_->setToolTip(bg);
    bgChoose_->setText(t("set_background_choose"));
    bgClear_->setText(t("set_background_clear"));
    bgClear_->setEnabled(!bg.isEmpty());
    overlayLabel_->setText(t("set_overlay", overlay_->value()));
    overlayHint_->setText(t("set_overlay_hint"));
    panelLabel_->setText(t("set_panel_opacity", panelOpacity_->value()));
    panelHint_->setText(t("set_panel_opacity_hint"));
    setPerformance_->setText(t("set_performance"));
    threadsLabel_->setText(t("set_threads"));
    threadsBox_->setItemText(0, t("set_threads_auto", std::max(1U, std::thread::hardware_concurrency())));
    threadsHint_->setText(t("set_threads_hint"));
    setExperimental_->setText(t("set_experimental"));
    gpuEnable_->setText(t("gpu_enable"));
    gpuDeviceLabel_->setText(t("gpu_device"));
    gpuWarning_->setText(t("gpu_warning"));
    benchTitle_->setText(t("bench_title"));
    benchIntro_->setText(t("bench_intro"));
    benchChart_->setBottleneckLabel(t("bench_bottleneck"));
    refreshGpuControls();
    showBenchmark();
    setAbout_->setText(t("set_about"));
    aboutBody_->setText(t("set_about_body", QStringLiteral(ENCPTO_VERSION)));
    aboutLink_->setText(QStringLiteral("<a href=\"https://github.com/nil-coder-sudo/enCPTO\" style=\"color:%1\">%2</a>")
                            .arg(theme::current().frame.name(), t("set_source_link")));

    updatePasswordFeedback();
    if (!sourcePath_.isEmpty()) {
        loadPath(sourcePath_);  // re-render source details in the new language
    }
    if (status_ == Status::Idle) {
        setStatus(Status::Idle, t("status_ready"));
    }
}

void MainWindow::updatePasswordFeedback() {
    const auto& p = theme::current();
    const PasswordBytes pwd(password_->text());
    const auto a = encpto::password::assess(pwd.view());
    using S = encpto::password::Strength;
    int level = 0;
    QColor color = p.line;
    QString text;
    switch (a.strength) {
        case S::Empty: text = t("strength_empty"); break;
        case S::TooShort: level = 1; color = p.danger; text = t("strength_short"); break;
        case S::Weak: level = 1; color = p.warning; text = t("strength_weak"); break;
        case S::Fair: level = 2; color = p.accent; text = t("strength_fair"); break;
        case S::Good: level = 3; color = p.success; text = t("strength_good"); break;
        case S::Excellent: level = 4; color = p.success; text = t("strength_excellent"); break;
    }
    if (a.strength >= S::Fair) {
        text += i18n::language() == i18n::Lang::En ? QStringLiteral(", ") : QStringLiteral("，");
        text += t("strength_bits", static_cast<int>(std::lround(a.entropy_bits)));
    }
    if (source_ == Source::Container) {
        meter_->setLevel(0, p.line);  // strength rules don't apply when decrypting
        strengthText_->clear();
    } else {
        meter_->setLevel(level, color);
        strengthText_->setText(text);
    }
    updateActions();
}

void MainWindow::updateActions() {
    const bool busy = task_ != nullptr || benchThread_ != nullptr;
    const bool container = source_ == Source::Container;
    const bool encryptable = source_ == Source::File || source_ == Source::Folder;

    encrypt_->setVisible(!container);
    decrypt_->setVisible(container);
    shred_->setVisible(!container);
    shredHint_->setVisible(!container && shred_->isChecked());
    decryptHint_->setVisible(container);
    meter_->setVisible(!container);
    strengthText_->setVisible(!container);

    const PasswordBytes pwd(password_->text());
    encrypt_->setEnabled(!busy && encryptable && encpto::password::assess(pwd.view()).acceptable());
    decrypt_->setEnabled(!busy && container && !password_->text().isEmpty());
    password_->setEnabled(!busy);
    shred_->setEnabled(!busy);
    tabSettings_->setEnabled(true);
}

void MainWindow::setStatus(Status s, const QString& text) {
    status_ = s;
    const auto& p = theme::current();
    statusText_->setText(text);
    QString icon;
    QColor color = p.dim;
    switch (s) {
        case Status::Idle: icon = "shield"; break;
        case Status::Busy: icon = "lock"; color = p.accent; break;
        case Status::Success: icon = "check"; color = p.success; break;
        case Status::Error: icon = "alert"; color = p.danger; break;
    }
    statusIcon_->setPixmap(theme::pixmap(icon, color, 18, devicePixelRatioF()));
    statusText_->setStyleSheet(s == Status::Error ? QStringLiteral("color: %1;").arg(p.danger.name()) : QString());
    progress_->setVisible(s == Status::Busy);
    speed_->setVisible(s == Status::Busy);
    cancel_->setVisible(s == Status::Busy);
    showInFolder_->setVisible(s == Status::Success && !lastResult_.isEmpty());
}

void MainWindow::setBusy(bool busy) {
    drop_->setBusy(busy);
    updateActions();
    if (busy) {
        cancel_->setEnabled(true);
        progress_->setValue(0);
        speed_->clear();
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Source handling
// ═══════════════════════════════════════════════════════════════════════

void MainWindow::chooseFile() {
    const QString f = QFileDialog::getOpenFileName(this, t("choose_file_dialog"),
                                                   sourcePath_.isEmpty() ? QString() : QFileInfo(sourcePath_).absolutePath());
    if (!f.isEmpty()) loadPath(f);
}

void MainWindow::chooseFolder() {
    const QString d = QFileDialog::getExistingDirectory(this, t("choose_folder_dialog"));
    if (!d.isEmpty()) loadPath(d);
}

void MainWindow::loadPath(const QString& path) {
    const QFileInfo fi(path);
    if (fi.isDir()) loadFolder(fi.absoluteFilePath());
    else if (fi.isFile()) loadFile(fi.absoluteFilePath());
}

void MainWindow::clearSource() {
    source_ = Source::None;
    sourcePath_.clear();
    drop_->showEmpty();
    updatePasswordFeedback();
}

void MainWindow::loadFolder(const QString& path) {
    source_ = Source::Folder;
    sourcePath_ = path;
    const auto st = encpto::fsutil::scan_directory(toPath(path));
    drop_->showSource("folder", QFileInfo(path).fileName(),
                      t("meta_folder", QString::number(st.files), human(st.bytes)));
    drop_->setPreviewInfo(t("preview_folder"), "lock");
    updatePasswordFeedback();
}

void MainWindow::loadFile(const QString& path) {
    sourcePath_ = path;
    const QFileInfo fi(path);
    const auto size = static_cast<std::uint64_t>(fi.size());

    encpto::ContainerInfo info;
    try {
        info = encpto::inspect(toPath(path));
    } catch (const std::exception&) {
    }
    if (info.kind == encpto::ContainerInfo::Kind::V7) {
        source_ = Source::Container;
        drop_->showSource("lock", fi.fileName(), t("meta_container", human(size)));
        drop_->setPreviewInfo(t("preview_v7"), "shield");
        updatePasswordFeedback();
        return;
    }
    if (info.kind == encpto::ContainerInfo::Kind::LegacyV2toV6) {
        source_ = Source::Legacy;
        legacyVersion_ = info.version;
        drop_->showSource("alert", fi.fileName(), t("meta_container", human(size)));
        drop_->setPreviewInfo(t("preview_legacy", info.version), "alert");
        updatePasswordFeedback();
        return;
    }

    source_ = Source::File;
    drop_->showSource("file", fi.fileName(), t("meta_file", human(size)));
    const QString ext = fi.suffix().toLower();
    static const QStringList images = {"png", "jpg", "jpeg", "bmp", "gif", "webp", "ico"};
    static const QStringList texts = {"txt", "csv", "json", "md", "py", "js", "ts", "html", "css",
                                      "xml", "log", "ini", "cfg", "toml", "yaml", "yml", "c", "h",
                                      "cpp", "hpp", "java", "go", "rs", "sh", "bat", "ps1", "sql"};
    if (images.contains(ext)) {
        QImageReader reader(path);
        reader.setAutoTransform(true);
        const QSize s = reader.size();
        if (s.isValid() && std::max(s.width(), s.height()) > 2400) {
            reader.setScaledSize(s.scaled(2400, 2400, Qt::KeepAspectRatio));
        }
        const QImage img = reader.read();
        if (!img.isNull()) {
            drop_->setPreviewImage(QPixmap::fromImage(img));
        } else {
            drop_->setPreviewInfo(t("preview_none"), "image");
        }
    } else if (texts.contains(ext)) {
        QFile f(path);
        if (f.open(QIODevice::ReadOnly)) {
            const QByteArray head = f.read(50 * 1024);
            QString text = QString::fromUtf8(head);
            if (f.size() > head.size()) text += t("preview_truncated");
            drop_->setPreviewText(text);
        }
    } else {
        drop_->setPreviewInfo(t("preview_none"), "file");
    }
    updatePasswordFeedback();
}

// ═══════════════════════════════════════════════════════════════════════
//  Operations
// ═══════════════════════════════════════════════════════════════════════

void MainWindow::startEncrypt() {
    if (task_) return;
    if (source_ != Source::File && source_ != Source::Folder) {
        QMessageBox::information(this, t("err_title"), t("err_no_source"));
        return;
    }
    {
        const PasswordBytes pwd(password_->text());
        if (!encpto::password::assess(pwd.view()).acceptable()) {
            QMessageBox::warning(this, t("err_title"), t("err_weak_password"));
            return;
        }
    }
    const QFileInfo fi(sourcePath_);
    const QString suggested = QDir(fi.absolutePath()).filePath(fi.fileName() + ".dat");
    QString out = QFileDialog::getSaveFileName(this, t("save_dialog"), suggested,
                                               QStringLiteral("enCPTO (*.dat);;All files (*)"));
    if (out.isEmpty()) return;
    if (!out.endsWith(".dat", Qt::CaseInsensitive)) out += ".dat";
    if (QFileInfo(out).absoluteFilePath() == fi.absoluteFilePath()) {
        QMessageBox::warning(this, t("err_title"), t("err_no_source"));
        return;
    }

    const bool shred = shred_->isChecked();
    if (shred) {
        QMessageBox box(QMessageBox::Warning, t("confirm_shred_title"), t("confirm_shred_body", fi.fileName()),
                        QMessageBox::Cancel, this);
        auto* ok = box.addButton(t("confirm_shred_button"), QMessageBox::DestructiveRole);
        box.setDefaultButton(QMessageBox::Cancel);
        box.exec();
        if (box.clickedButton() != ok) return;
    }

    const bool isDir = source_ == Source::Folder;
    const fs::path in = toPath(sourcePath_);
    const fs::path outPath = toPath(out);
    auto pwd = std::make_shared<PasswordBytes>(password_->text());
    runTask(
        [=](const encpto::Options& opts) {
            if (isDir) encpto::encrypt_directory(in, outPath, pwd->view(), opts);
            else encpto::encrypt_file(in, outPath, pwd->view(), opts);
            if (shred) {
                if (isDir) encpto::shred::shred_directory(in, opts);
                else encpto::shred::shred_file(in, opts);
            }
            return Task::Result{fromPath(outPath), false};
        },
        true, shred);
}

void MainWindow::startDecrypt() {
    if (task_) return;
    if (source_ != Source::Container) {
        QMessageBox::information(this, t("err_title"), t("err_not_container"));
        return;
    }
    if (password_->text().isEmpty()) {
        QMessageBox::information(this, t("err_title"), t("err_no_password"));
        password_->setFocus();
        return;
    }
    const QString dir = QFileDialog::getExistingDirectory(this, t("restore_dialog"),
                                                          QFileInfo(sourcePath_).absolutePath());
    if (dir.isEmpty()) return;
    const fs::path in = toPath(sourcePath_);
    const fs::path outDir = toPath(dir);
    auto pwd = std::make_shared<PasswordBytes>(password_->text());
    runTask(
        [=](const encpto::Options& opts) {
            const auto r = encpto::decrypt(in, outDir, pwd->view(), opts);
            return Task::Result{fromPath(r.path), r.is_directory};
        },
        false, false);
}

void MainWindow::runTask(Task::Body body, bool encrypting, bool shredding) {
    taskEncrypting_ = encrypting;
    taskShredding_ = shredding;
    lastPhase_ = -1;
    lastResult_.clear();
    const Task::Settings settings = taskSettings();
    taskGpu_ = settings.gpu;
    task_ = new Task(std::move(body), settings, this);
    connect(task_, &Task::progress, this, &MainWindow::onProgress);
    connect(task_, &Task::succeeded, this, &MainWindow::onSucceeded);
    connect(task_, &Task::failed, this, &MainWindow::onFailed);
    connect(task_, &QThread::finished, task_, &QObject::deleteLater);
    setStatus(Status::Busy, t("phase_kdf"));
    setBusy(true);
    task_->start();
}

void MainWindow::onProgress(int phase, double fraction, double rate) {
    if (phase != lastPhase_) {
        lastPhase_ = phase;
        const auto ph = static_cast<Phase>(phase);
        const bool gpuPhase = taskGpu_ && (ph == Phase::Encrypting || ph == Phase::Decrypting);
        setStatus(Status::Busy, t(phaseKey(phase)) + (gpuPhase ? t("phase_gpu") : QString()));
    }
    progress_->setValue(static_cast<int>(fraction * 1000));
    speed_->setText(rate > 0 ? QStringLiteral("%1/s").arg(human(static_cast<std::uint64_t>(rate))) : QString());
}

void MainWindow::onSucceeded(const QString& path, bool isDir, double seconds) {
    task_ = nullptr;
    lastResult_ = path;
    const QString name = QFileInfo(path).fileName();
    const QString key = taskEncrypting_ ? (taskShredding_ ? "done_encrypt_shred" : "done_encrypt") : "done_decrypt";
    QString msg = t(key.toUtf8().constData(), name) + t("done_time", QString::number(seconds, 'f', 1));
    setBusy(false);
    if (isDir) loadFolder(path);
    else loadFile(path);
    setStatus(Status::Success, msg);
}

void MainWindow::onFailed(int code, const QString& message) {
    task_ = nullptr;
    setBusy(false);
    const auto c = static_cast<ErrorCode>(code);
    if (taskShredding_ && QFileInfo::exists(sourcePath_) == false) {
        clearSource();
    }
    if (c == ErrorCode::Cancelled) {
        setStatus(Status::Idle, t("cancelled"));
        return;
    }
    QString text;
    switch (c) {
        case ErrorCode::WrongPassword: text = t("err_wrong_password"); break;
        case ErrorCode::Tampered: text = t("err_tampered"); break;
        case ErrorCode::Corrupted: text = t("err_corrupted"); break;
        case ErrorCode::Gpu: text = t("err_gpu", message); break;
        default: text = message; break;
    }
    setStatus(Status::Error, text);
    if (c != ErrorCode::WrongPassword) {
        QMessageBox::critical(this, t("err_title"), text);
    } else {
        password_->selectAll();
        password_->setFocus();
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Generator
// ═══════════════════════════════════════════════════════════════════════

void MainWindow::saveGeneratorPrefs() {
    auto& p = Prefs::instance();
    p.genLength = genLength_->value();
    p.genUpper = genUpper_->isChecked();
    p.genLower = genLower_->isChecked();
    p.genDigits = genDigits_->isChecked();
    p.genSymbols = genSymbols_->isChecked();
    p.genAvoidAmbiguous = genAmbiguous_->isChecked();
    p.save();
}

void MainWindow::generatePassword() {
    encpto::password::GeneratorOptions o;
    o.length = genLength_->value();
    o.upper = genUpper_->isChecked();
    o.lower = genLower_->isChecked();
    o.digits = genDigits_->isChecked();
    o.symbols = genSymbols_->isChecked();
    o.avoid_ambiguous = genAmbiguous_->isChecked();
    try {
        std::string pwd = encpto::password::generate(o);
        genOutput_->setText(QString::fromStdString(pwd));
        const auto a = encpto::password::assess(pwd);
        encpto::secure_zero(pwd.data(), pwd.size());
        const auto& p = theme::current();
        const int level = a.strength >= encpto::password::Strength::Excellent ? 4
                        : a.strength >= encpto::password::Strength::Good      ? 3
                                                                               : 2;
        genMeter_->setLevel(level, level >= 3 ? p.success : p.accent);
        genStrength_->setText(t("strength_bits", static_cast<int>(std::lround(a.entropy_bits))));
        if (genFeedback_) genFeedback_->clear();
    } catch (const encpto::Error&) {
        genOutput_->clear();
        genMeter_->setLevel(0, theme::current().line);
        genStrength_->clear();
        if (genFeedback_) genFeedback_->setText(t("gen_need_set"));
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Experimental: GPU and benchmark
// ═══════════════════════════════════════════════════════════════════════

Task::Settings MainWindow::taskSettings() const {
    const auto& prefs = Prefs::instance();
    Task::Settings st;
    st.threads = static_cast<unsigned>(prefs.threads);
    const auto& devs = encpto::gpu::probe().devices;
    st.gpu = prefs.gpuEnabled && !devs.empty();
    st.gpuDevice = (prefs.gpuDevice >= 0 && prefs.gpuDevice < static_cast<int>(devs.size())) ? prefs.gpuDevice : -1;
    return st;
}

void MainWindow::refreshGpuControls() {
    const auto& st = encpto::gpu::probe();
    const auto& prefs = Prefs::instance();
    const bool any = !st.devices.empty();
    gpuEnable_->setEnabled(any && benchThread_ == nullptr);
    if (!any && gpuEnable_->isChecked()) {
        const QSignalBlocker block(gpuEnable_);
        gpuEnable_->setChecked(false);
    }
    gpuDeviceBox_->clear();
    for (const auto& d : st.devices) {
        gpuDeviceBox_->addItem(QStringLiteral("%1 (%2)").arg(QString::fromStdString(d.name),
                                                            d.is_gpu ? t("gpu_kind_gpu") : t("gpu_kind_cpu")),
                               d.index);
    }
    const int sel = gpuDeviceBox_->findData(prefs.gpuDevice >= 0 ? prefs.gpuDevice : encpto::gpu::default_device());
    gpuDeviceBox_->setCurrentIndex(std::max(0, sel));
    const bool on = any && gpuEnable_->isChecked();
    gpuDeviceLabel_->setVisible(any);
    gpuDeviceBox_->setVisible(any);
    gpuDeviceBox_->setEnabled(on && st.devices.size() > 1);
    gpuWarning_->setVisible(on);
    gpuWarning_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::current().warning.name()));
    gpuStatus_->setVisible(!any);
    gpuStatus_->setText(!st.runtime_found ? t("gpu_no_runtime") : t("gpu_no_device"));
}

void MainWindow::runBenchmark() {
    if (benchThread_ != nullptr || task_) return;
    benchCancel_ = false;
    benchError_.clear();
    benchStep_ = 0;
    benchTotal_ = 0;
    encpto::bench::Settings st;
    const Task::Settings ts = taskSettings();
    st.threads = ts.threads;
    st.gpu = ts.gpu;
    st.gpu_device = ts.gpuDevice;
    st.cancel = &benchCancel_;
    st.on_step = [this](int step, int total) {
        QMetaObject::invokeMethod(this, [this, step, total] {
            benchStep_ = step;
            benchTotal_ = total;
            benchRun_->setText(t("bench_running", step, total));
        }, Qt::QueuedConnection);
    };
    benchThread_ = QThread::create([this, st] {
        std::optional<encpto::bench::Report> report;
        QString error;
        try {
            report = encpto::bench::run(st);
        } catch (const std::exception& e) {
            error = QString::fromUtf8(e.what());
        }
        QMetaObject::invokeMethod(this, [this, report, error] {
            benchReport_ = report;
            benchError_ = error;
            benchThread_->wait();
            benchThread_->deleteLater();
            benchThread_ = nullptr;
            benchRun_->setEnabled(true);
            refreshGpuControls();
            updateActions();
            showBenchmark();
        }, Qt::QueuedConnection);
    });
    benchRun_->setEnabled(false);
    benchRun_->setText(t("bench_running", 0, ts.gpu ? 8 : 6));
    gpuEnable_->setEnabled(false);
    updateActions();
    benchThread_->start(QThread::LowPriority);
}

void MainWindow::showBenchmark() {
    using encpto::bench::StageId;
    if (benchThread_ == nullptr) benchRun_->setText(t("bench_run"));
    benchRun_->setIcon(theme::icon("cpu", theme::current().text, 16));
    const auto& p = theme::current();
    if (!benchReport_) {
        benchChart_->setVisible(false);
        benchSummary_->setVisible(!benchError_.isEmpty());
        benchSummary_->setText(benchError_);
        benchSummary_->setStyleSheet(QStringLiteral("color: %1;").arg(p.danger.name()));
        benchDetails_->setVisible(false);
        return;
    }
    const auto& r = *benchReport_;
    const auto name = [](StageId id) -> const char* {
        switch (id) {
            case StageId::Argon2id: return "bench_argon2";
            case StageId::AesOneCore: return "bench_aes";
            case StageId::ChaChaOneCore: return "bench_chacha";
            case StageId::Hmac: return "bench_hmac";
            case StageId::LayersCpu: return "bench_layers_cpu";
            case StageId::LayersGpu: return "bench_layers_gpu";
            case StageId::PipelineCpu: return "bench_pipe_cpu";
            case StageId::PipelineGpu: return "bench_pipe_gpu";
        }
        return "";
    };
    std::vector<BenchChart::Row> rows;
    for (const auto& s : r.stages) {
        BenchChart::Row row;
        row.label = t(name(s.id));
        if (s.id == StageId::Argon2id) {
            row.kind = BenchChart::Kind::Info;
            row.valueText = t("bench_seconds", QString::number(s.seconds, 'f', 2));
        } else {
            row.value = s.mib_per_s;
            row.valueText = QStringLiteral("%1 MiB/s").arg(std::lround(s.mib_per_s));
            row.kind = s.id == r.bottleneck ? BenchChart::Kind::Bottleneck
                     : (s.id == StageId::PipelineCpu || s.id == StageId::PipelineGpu) ? BenchChart::Kind::Total
                                                                                      : BenchChart::Kind::Stage;
        }
        rows.push_back(row);
    }
    benchChart_->setRows(std::move(rows));
    benchChart_->setVisible(true);

    const auto* hmac = r.find(StageId::Hmac);
    benchSummary_->setStyleSheet(QString());
    benchSummary_->setText(r.bottleneck == StageId::Hmac
                               ? t("bench_summary_hmac", std::lround(hmac != nullptr ? hmac->mib_per_s : 0))
                               : t("bench_summary_layers"));
    benchSummary_->setVisible(true);
    QStringList details{t("bench_details", r.threads, 512)};
    if (!r.gpu_device.empty()) details << t("bench_gpu_used", QString::fromStdString(r.gpu_device));
    else if (!r.gpu_error.empty()) details << t("bench_gpu_skipped", QString::fromStdString(r.gpu_error));
    else if (!encpto::gpu::probe().devices.empty()) details << t("bench_gpu_hint");
    benchDetails_->setText(details.join(QLatin1Char('\n')));
    benchDetails_->setVisible(true);
}

// ═══════════════════════════════════════════════════════════════════════

void MainWindow::closeEvent(QCloseEvent* e) {
    if (task_) {
        const auto r = QMessageBox::question(this, t("quit_busy_title"), t("quit_busy_body"));
        if (r != QMessageBox::Yes) {
            e->ignore();
            return;
        }
        task_->cancel();
        task_->wait();
    }
    if (benchThread_ != nullptr) {
        benchCancel_ = true;
        benchThread_->wait();
    }
    Prefs::instance().save();
    e->accept();
}
