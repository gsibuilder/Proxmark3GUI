#ifndef EMVTAB_H
#define EMVTAB_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QTreeWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QTabWidget>
#include <QHeaderView>
#include <QFrame>
#include <QCheckBox>
#include <QTimer>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include "common/util.h"

class EMVTab : public QWidget
{
    Q_OBJECT
public:
    explicit EMVTab(Util *utilAddr, QWidget *parent = nullptr);
    ~EMVTab();

    void loadDumpFile(const QString &filePath);

public slots:
    void onAutoPullClicked();
    void onPM3Output(const QString &output);
    void onAutoPullTimeout();
    void onContinuousPoll();
    void scheduleNextPoll();
    void onPM3Connected();

    void onBrowseDumpClicked();
    void onQuickDumpSelected(int index);
    void onScanLiveClicked();
    void onSearchAppletsClicked();
    void onCardInfoClicked();
    void onTogglePanMask();
    void onSimulate14a();
    void onSimulateJcop();
    void onCopyTrack2();
    void onCopyPan();
    void onExportAuditReport();
    void onSaveJsonClicked();
    void onSaveDumpClicked();
    void onClearCardClicked();
    void onFilterTlv(const QString &filterText);

    // Online Payment Gateway slots
    void onChargeOnlineClicked();
    void onTapAndChargeGatewayClicked();
    void onSaveGatewayConfigClicked();
    void onOpenWebPosClicked();
    void onRefreshGatewayLedger();
    void checkGatewayHealth();

private:
    Util *util;
    QNetworkAccessManager *netManager;
    QProcess *gatewayProcess;
    QTimer *gatewayHealthTimer;

    // Online Payment Gateway widgets
    QLabel *lblGatewayStatusBadge;
    QLineEdit *editChargeAmount;
    QLineEdit *editCardCvc;
    QLineEdit *editGatewayUrl;
    QLineEdit *editStripeKey;
    QLineEdit *editStripePk;
    QLineEdit *editWebhookUrl;
    QPushButton *btnChargeOnline;
    QPushButton *btnTapAndCharge;
    QPushButton *btnSaveGatewayConfig;
    QPushButton *btnOpenWebPos;
    QPushButton *btnRefreshLedger;
    QTableWidget *tableGatewayLedger;
    QTextEdit *editGatewayLog;
    QJsonArray cachedLedgerArray;

    // Auto-Pull & Live Header
    QPushButton *btnAutoPull;
    QLabel *lblAutoPullStatus;
    QCheckBox *checkContinuous;
    QCheckBox *checkClearOnRemove;
    QCheckBox *checkAutoSave;
    QTimer *autoPullTimer;
    QTimer *continuousTimer;
    bool isAutoPulling;
    bool pendingOnlineChargeAfterPull;

    // Header & Quick Action widgets
    QPushButton *btnBrowseDump;
    QPushButton *btnSaveDump;
    QPushButton *btnClearCard;
    QComboBox *comboQuickDumps;
    QPushButton *btnScanLive;
    QPushButton *btnSearchApplets;
    QPushButton *btnCardInfo;

    // Visual Card Widget
    QFrame *cardFrame;
    QLabel *labelCardBrandBadge;
    QLabel *labelCardType;
    QLabel *labelPan;
    QPushButton *btnTogglePan;
    QLabel *labelHolder;
    QLabel *labelExpiry;
    QLabel *labelServiceCode;
    QLabel *labelMode;
    QLabel *labelUid;
    QLabel *labelAts;
    QLabel *labelAid;

    // Sub-Tabs
    QTabWidget *subTabWidget;
    QTreeWidget *treeTlv;
    QLineEdit *editFilterTlv;
    QTextEdit *editRawJson;
    QPushButton *btnSaveJson;

    // Action buttons
    QPushButton *btnSim14a;
    QPushButton *btnSimJcop;
    QPushButton *btnCopyTrack2;
    QPushButton *btnCopyPan;
    QPushButton *btnExportReport;

    // Stored State
    bool panMasked;
    QString rawPan;
    QString formattedPan;
    QString cardholderName;
    QString expiryDate;
    QString serviceCode;
    QString rawTrack2;
    QString currentUid;
    QString lastDetectedUid;
    QString currentAid;
    QString currentMode;
    QString currentFilePath;
    QString currentArqc;
    QString currentAtc;
    QString currentIad;
    QString currentCid;

    void setupUI();
    void loadGatewayConfigFromDisk();
    void ensureGatewayServerRunning();
    void parseJsonData(const QByteArray &data);
    void parseTlvBytes(const QByteArray &rawBytes, QTreeWidgetItem *parentItem);
    void parseTlvHexString(const QString &hexStr, QTreeWidgetItem *parentItem);
    void updateVisualCard();
    void clearVisualCard();
    void populateQuickDumps();
    static QString getTagName(const QString &tagHex);
};

#endif // EMVTAB_H
