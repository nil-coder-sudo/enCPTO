#pragma once

#include "Task.hpp"

#include <QMainWindow>
#include <QPointer>

class BackgroundWidget;
class DropZone;
class Panel;
class QAction;
class QButtonGroup;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QSlider;
class QStackedWidget;
class QTimer;
class StrengthMeter;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow();
    void loadPath(const QString& path);

protected:
    void closeEvent(QCloseEvent* e) override;

private:
    enum class Source { None, File, Folder, Container, Legacy };
    enum class Status { Idle, Busy, Success, Error };

    // construction
    QWidget* buildHeader();
    QWidget* buildMainPage();
    QWidget* buildGeneratorPage();
    QWidget* buildSettingsPage();
    QWidget* buildFooter();

    // state & presentation
    void applyTheme();
    void refreshIcons();
    void retranslate();
    void updatePasswordFeedback();
    void updateActions();
    void setStatus(Status s, const QString& text);
    void setBusy(bool busy);

    // source handling
    void chooseFile();
    void chooseFolder();
    void loadFile(const QString& path);
    void loadFolder(const QString& path);
    void clearSource();

    // operations
    void startEncrypt();
    void startDecrypt();
    void runTask(Task::Body body, bool encrypting, bool shredding);
    void onProgress(int phase, double fraction, double rate);
    void onSucceeded(const QString& path, bool isDir, double seconds);
    void onFailed(int code, const QString& message);

    // generator
    void generatePassword();
    void saveGeneratorPrefs();

    // widgets
    BackgroundWidget* background_ = nullptr;
    QStackedWidget* pages_ = nullptr;
    QButtonGroup* tabs_ = nullptr;
    QPushButton* tabMain_ = nullptr;
    QPushButton* tabGen_ = nullptr;
    QPushButton* tabSettings_ = nullptr;
    QPushButton* langButton_ = nullptr;
    QLabel* wordmark_ = nullptr;

    DropZone* drop_ = nullptr;
    Panel* keyPanel_ = nullptr;
    QLabel* keyTitle_ = nullptr;
    QLineEdit* password_ = nullptr;
    QAction* toggleEcho_ = nullptr;
    QAction* quickGenerate_ = nullptr;
    StrengthMeter* meter_ = nullptr;
    QLabel* strengthText_ = nullptr;
    QCheckBox* shred_ = nullptr;
    QLabel* shredHint_ = nullptr;
    QLabel* decryptHint_ = nullptr;
    QLabel* recoveryNote_ = nullptr;
    QLabel* recoveryIcon_ = nullptr;
    QPushButton* encrypt_ = nullptr;
    QPushButton* decrypt_ = nullptr;

    QLabel* statusIcon_ = nullptr;
    QLabel* statusText_ = nullptr;
    QProgressBar* progress_ = nullptr;
    QLabel* speed_ = nullptr;
    QPushButton* showInFolder_ = nullptr;
    QPushButton* cancel_ = nullptr;

    // generator page
    QLabel* genHeading_ = nullptr;
    QLabel* genIntro_ = nullptr;
    QLineEdit* genOutput_ = nullptr;
    StrengthMeter* genMeter_ = nullptr;
    QLabel* genStrength_ = nullptr;
    QLabel* genLengthLabel_ = nullptr;
    QSlider* genLength_ = nullptr;
    QCheckBox* genUpper_ = nullptr;
    QCheckBox* genLower_ = nullptr;
    QCheckBox* genDigits_ = nullptr;
    QCheckBox* genSymbols_ = nullptr;
    QCheckBox* genAmbiguous_ = nullptr;
    QPushButton* genNew_ = nullptr;
    QPushButton* genCopy_ = nullptr;
    QPushButton* genUse_ = nullptr;
    QLabel* genFeedback_ = nullptr;

    // settings page
    QLabel* setAppearance_ = nullptr;
    QLabel* setThemeLabel_ = nullptr;
    QComboBox* themeBox_ = nullptr;
    QLabel* setBgLabel_ = nullptr;
    QLabel* bgPath_ = nullptr;
    QPushButton* bgChoose_ = nullptr;
    QPushButton* bgClear_ = nullptr;
    QLabel* overlayLabel_ = nullptr;
    QLabel* overlayHint_ = nullptr;
    QSlider* overlay_ = nullptr;
    QLabel* panelLabel_ = nullptr;
    QLabel* panelHint_ = nullptr;
    QSlider* panelOpacity_ = nullptr;
    QLabel* setPerformance_ = nullptr;
    QLabel* threadsLabel_ = nullptr;
    QComboBox* threadsBox_ = nullptr;
    QLabel* threadsHint_ = nullptr;
    QLabel* setAbout_ = nullptr;
    QLabel* aboutBody_ = nullptr;
    QLabel* aboutLink_ = nullptr;

    QTimer* autoThemeTimer_ = nullptr;

    // state
    Source source_ = Source::None;
    QString sourcePath_;
    int legacyVersion_ = 0;
    QPointer<Task> task_;
    bool taskEncrypting_ = false;
    bool taskShredding_ = false;
    int lastPhase_ = -1;
    Status status_ = Status::Idle;
    QString lastResult_;
};
