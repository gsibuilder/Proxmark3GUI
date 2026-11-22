#include "module/emvtab.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QClipboard>
#include <QApplication>
#include <QFileInfo>
#include <QDir>
#include <QTextStream>
#include <QRegularExpression>
#include <QDateTime>
#include <QDesktopServices>
#include <QUrl>

EMVTab::EMVTab(Util *utilAddr, QWidget *parent)
    : QWidget(parent),
      util(utilAddr),
      netManager(new QNetworkAccessManager(this)),
      gatewayProcess(nullptr),
      gatewayHealthTimer(new QTimer(this)),
      isAutoPulling(false),
      pendingOnlineChargeAfterPull(false),
      panMasked(true),
      currentUid(""),
      lastDetectedUid(""),
      currentAid(""),
      currentMode(""),
      currentFilePath(""),
      currentArqc(""),
      currentAtc(""),
      currentIad(""),
      currentCid("")
{
    autoPullTimer = new QTimer(this);
    autoPullTimer->setSingleShot(true);
    connect(autoPullTimer, &QTimer::timeout, this, &EMVTab::onAutoPullTimeout);

    continuousTimer = new QTimer(this);
    continuousTimer->setSingleShot(true);
    connect(continuousTimer, &QTimer::timeout, this, &EMVTab::onContinuousPoll);

    if (util) {
        connect(util, &Util::refreshOutput, this, &EMVTab::onPM3Output);
    }

    setupUI();
    loadGatewayConfigFromDisk();
    populateQuickDumps();

    // Start with a clean live state
    clearVisualCard();

    // Enable continuous auto-detection by default
    checkContinuous->setChecked(true);

    // Ensure Online Payment Gateway server is running & monitor health
    connect(gatewayHealthTimer, &QTimer::timeout, this, &EMVTab::checkGatewayHealth);
    gatewayHealthTimer->start(5000);
    QTimer::singleShot(300, this, &EMVTab::ensureGatewayServerRunning);
}

EMVTab::~EMVTab()
{
    if (gatewayProcess && gatewayProcess->state() != QProcess::NotRunning) {
        gatewayProcess->terminate();
        gatewayProcess->waitForFinished(1000);
    }
}

QString EMVTab::getTagName(const QString &tagHex)
{
    static const QMap<QString, QString> tagMap = {
        {"4F", "Application Identifier (AID)"},
        {"50", "Application Label"},
        {"57", "Track 2 Equivalent Data"},
        {"5A", "Application Primary Account Number (PAN)"},
        {"5F20", "Cardholder Name"},
        {"5F24", "Application Expiration Date (YYMMDD)"},
        {"5F25", "Application Effective Date (YYMMDD)"},
        {"5F28", "Issuer Country Code"},
        {"5F2A", "Transaction Currency Code"},
        {"5F2D", "Language Preference"},
        {"5F30", "Service Code"},
        {"5F34", "Application PAN Sequence Number (PSN)"},
        {"5F55", "Issuer Country Code (alpha-2)"},
        {"61", "Directory Entry"},
        {"6F", "File Control Information (FCI) Template"},
        {"70", "READ RECORD Response Template"},
        {"77", "Response Message Template Format 2"},
        {"80", "Response Message Template Format 1"},
        {"82", "Application Interchange Profile (AIP)"},
        {"84", "Dedicated File (DF) Name / AID"},
        {"87", "Application Priority Indicator"},
        {"8C", "Card Risk Management Data Object List 1 (CDOL1)"},
        {"8D", "Card Risk Management Data Object List 2 (CDOL2)"},
        {"8E", "Cardholder Verification Method (CVM) List"},
        {"8F", "Certification Authority Public Key Index"},
        {"90", "Issuer Public Key Certificate"},
        {"92", "Issuer Public Key Remainder"},
        {"94", "Application File Locator (AFL)"},
        {"95", "Terminal Verification Results (TVR)"},
        {"9A", "Transaction Date"},
        {"9C", "Transaction Type"},
        {"9F02", "Amount, Authorized"},
        {"9F03", "Amount, Other"},
        {"9F07", "Application Usage Control (AUC)"},
        {"9F08", "Application Version Number"},
        {"9F0D", "Issuer Action Code - Default"},
        {"9F0E", "Issuer Action Code - Denial"},
        {"9F0F", "Issuer Action Code - Online"},
        {"9F10", "Issuer Application Data (IAD)"},
        {"9F1A", "Terminal Country Code"},
        {"9F1E", "Interface Device (IFD) Serial Number"},
        {"9F26", "Application Cryptogram (AC)"},
        {"9F27", "Cryptogram Information Data (CID)"},
        {"9F36", "Application Transaction Counter (ATC)"},
        {"9F37", "Unpredictable Number"},
        {"9F38", "Processing Options Data Object List (PDOL)"},
        {"9F4A", "Static Data Authentication Tag List"},
        {"9F4B", "Signed Dynamic Application Data (SDAD)"},
        {"9F5A", "Program Identifier / Issuer Proprietary"},
        {"9F66", "Terminal Transaction Qualifiers (TTQ)"},
        {"9F6C", "Card Transaction Qualifiers (CTQ)"},
        {"9F6E", "Form Factor Indicator (FFI / Visa Contactless)"},
        {"A5", "FCI Proprietary Template"},
        {"BF0C", "FCI Issuer Discretionary Data"}
    };
    return tagMap.value(tagHex.toUpper(), "Proprietary / Unknown Tag");
}

void EMVTab::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    mainLayout->setSpacing(10);

    // --- Top Action Bar ---
    QFrame *topBar = new QFrame(this);
    topBar->setStyleSheet("background-color: #1a1c24; border: 1px solid #2d3142; border-radius: 6px; padding: 4px;");
    QHBoxLayout *topLayout = new QHBoxLayout(topBar);
    topLayout->setContentsMargins(8, 4, 8, 4);
    topLayout->setSpacing(8);

    // Primary prominent Auto-Pull Button
    btnAutoPull = new QPushButton(tr("⚡ Auto-Pull Card Data"), topBar);
    btnAutoPull->setStyleSheet(
        "QPushButton {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00838f, stop:1 #00e5ff);"
        "  color: #070d14;"
        "  font-weight: 900;"
        "  font-size: 10pt;"
        "  padding: 8px 16px;"
        "  border-radius: 5px;"
        "  border: 1px solid #00f0ff;"
        "}"
        "QPushButton:hover {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0097a7, stop:1 #18ffff);"
        "}"
        "QPushButton:pressed {"
        "  background: #00838f;"
        "}"
    );
    btnAutoPull->setToolTip(tr("Automatically poll Proxmark3 antenna, read contactless card records, and extract all data directly into the GUI"));
    connect(btnAutoPull, &QPushButton::clicked, this, &EMVTab::onAutoPullClicked);
    topLayout->addWidget(btnAutoPull);

    lblAutoPullStatus = new QLabel(tr("Ready to pull data"), topBar);
    lblAutoPullStatus->setStyleSheet("color: #a0a0b0; font-size: 9pt; font-weight: 600;");
    topLayout->addWidget(lblAutoPullStatus);

    checkContinuous = new QCheckBox(tr("Continuous Auto-Detect"), topBar);
    checkContinuous->setToolTip(tr("Continuously poll for contactless cards and automatically pull data whenever a card is presented"));
    checkContinuous->setStyleSheet("color: #c0c5d5; font-size: 9pt;");
    connect(checkContinuous, &QCheckBox::toggled, [this](bool checked) {
        if (checked) {
            lastDetectedUid.clear();
            scheduleNextPoll();
        } else {
            continuousTimer->stop();
            lblAutoPullStatus->setText(tr("Continuous poller stopped"));
            lblAutoPullStatus->setStyleSheet("color: #a0a0b0; font-size: 9pt; font-weight: 600;");
        }
    });
    topLayout->addWidget(checkContinuous);

    checkClearOnRemove = new QCheckBox(tr("Clear on Remove"), topBar);
    checkClearOnRemove->setToolTip(tr("Automatically clear card visual display, TLV tree, and data when the card is removed from the antenna"));
    checkClearOnRemove->setStyleSheet("color: #c0c5d5; font-size: 9pt;");
    checkClearOnRemove->setChecked(true);
    topLayout->addWidget(checkClearOnRemove);

    checkAutoSave = new QCheckBox(tr("Auto-Save Dumps"), topBar);
    checkAutoSave->setToolTip(tr("Automatically save every detected card dump to rfid_dumps/ (Default: OFF - only save when you click Save Dump)"));
    checkAutoSave->setStyleSheet("color: #c0c5d5; font-size: 9pt;");
    checkAutoSave->setChecked(false);
    topLayout->addWidget(checkAutoSave);

    topLayout->addSpacing(10);

    btnBrowseDump = new QPushButton(tr("📂 Load Dump (.json)"), topBar);
    btnBrowseDump->setStyleSheet("font-weight: 600; padding: 6px 12px;");
    connect(btnBrowseDump, &QPushButton::clicked, this, &EMVTab::onBrowseDumpClicked);
    topLayout->addWidget(btnBrowseDump);

    btnSaveDump = new QPushButton(tr("💾 Save Dump"), topBar);
    btnSaveDump->setToolTip(tr("Save currently pulled EMV card dump to a JSON file"));
    btnSaveDump->setStyleSheet("font-weight: 600; padding: 6px 12px; background-color: #1b5e20; color: #b9f6ca; border: 1px solid #00e676; border-radius: 4px;");
    connect(btnSaveDump, &QPushButton::clicked, this, &EMVTab::onSaveDumpClicked);
    topLayout->addWidget(btnSaveDump);

    btnClearCard = new QPushButton(tr("🔄 Clear"), topBar);
    btnClearCard->setToolTip(tr("Clear card display and reset detection state"));
    connect(btnClearCard, &QPushButton::clicked, this, &EMVTab::onClearCardClicked);
    topLayout->addWidget(btnClearCard);

    QLabel *lblQuick = new QLabel(tr("Quick Dumps:"), topBar);
    lblQuick->setStyleSheet("color: #a0a0b0; font-size: 9pt;");
    topLayout->addWidget(lblQuick);

    comboQuickDumps = new QComboBox(topBar);
    comboQuickDumps->setMinimumWidth(200);
    connect(comboQuickDumps, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &EMVTab::onQuickDumpSelected);
    topLayout->addWidget(comboQuickDumps);

    topLayout->addSpacing(8);

    btnScanLive = new QPushButton(tr("💳 emv scan -at"), topBar);
    connect(btnScanLive, &QPushButton::clicked, this, &EMVTab::onScanLiveClicked);
    topLayout->addWidget(btnScanLive);

    btnSearchApplets = new QPushButton(tr("🔍 emv search"), topBar);
    connect(btnSearchApplets, &QPushButton::clicked, this, &EMVTab::onSearchAppletsClicked);
    topLayout->addWidget(btnSearchApplets);

    btnCardInfo = new QPushButton(tr("📋 hf 14a info"), topBar);
    connect(btnCardInfo, &QPushButton::clicked, this, &EMVTab::onCardInfoClicked);
    topLayout->addWidget(btnCardInfo);

    topLayout->addStretch(1);
    mainLayout->addWidget(topBar);

    // --- Middle Section: Visual Card Mockup + Key Specs Grid ---
    QHBoxLayout *middleLayout = new QHBoxLayout();
    middleLayout->setSpacing(12);

    // Left: Visual Credit Card / Contactless Mockup
    cardFrame = new QFrame(this);
    cardFrame->setFixedSize(400, 210);
    cardFrame->setStyleSheet(
        "QFrame {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1a233a, stop:0.5 #141c2c, stop:1 #0b111e);"
        "  border: 1px solid #334166;"
        "  border-radius: 12px;"
        "}"
    );
    QVBoxLayout *cardLayout = new QVBoxLayout(cardFrame);
    cardLayout->setContentsMargins(18, 14, 18, 14);

    QHBoxLayout *cardHeaderLayout = new QHBoxLayout();
    QLabel *chipIcon = new QLabel(tr("☲ CONTACTLESS SMARTCARD"), cardFrame);
    chipIcon->setStyleSheet("color: #798bb4; font-size: 8pt; font-weight: 700; letter-spacing: 1px;");
    cardHeaderLayout->addWidget(chipIcon);
    cardHeaderLayout->addStretch(1);

    labelCardBrandBadge = new QLabel(tr("VISA CREDIT"), cardFrame);
    labelCardBrandBadge->setStyleSheet("background-color: #00e5ff; color: #0a0e17; font-weight: 900; font-size: 9pt; padding: 2px 8px; border-radius: 4px;");
    cardHeaderLayout->addWidget(labelCardBrandBadge);
    cardLayout->addLayout(cardHeaderLayout);

    cardLayout->addSpacing(8);

    // PAN with Mask/Reveal toggle
    QHBoxLayout *panLayout = new QHBoxLayout();
    labelPan = new QLabel(tr("•••• •••• •••• ••••"), cardFrame);
    labelPan->setStyleSheet("color: #ffffff; font-family: 'Consolas', 'Courier New', monospace; font-size: 15pt; font-weight: 700; letter-spacing: 2px;");
    panLayout->addWidget(labelPan);
    panLayout->addSpacing(8);

    btnTogglePan = new QPushButton(tr("👁 Show"), cardFrame);
    btnTogglePan->setFixedSize(65, 24);
    btnTogglePan->setStyleSheet("background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); font-size: 8pt; border-radius: 3px; color: #d0d5e5;");
    connect(btnTogglePan, &QPushButton::clicked, this, &EMVTab::onTogglePanMask);
    panLayout->addWidget(btnTogglePan);
    panLayout->addStretch(1);
    cardLayout->addLayout(panLayout);

    cardLayout->addSpacing(6);

    // Expiry & Service Code
    QHBoxLayout *subCardLayout = new QHBoxLayout();
    QVBoxLayout *expLayout = new QVBoxLayout();
    QLabel *lblExpTitle = new QLabel(tr("GOOD THRU"), cardFrame);
    lblExpTitle->setStyleSheet("color: #727e99; font-size: 7pt; font-weight: bold;");
    labelExpiry = new QLabel(tr("--/--"), cardFrame);
    labelExpiry->setStyleSheet("color: #e4e9f7; font-family: monospace; font-weight: bold; font-size: 10pt;");
    expLayout->addWidget(lblExpTitle);
    expLayout->addWidget(labelExpiry);
    subCardLayout->addLayout(expLayout);

    subCardLayout->addSpacing(25);

    QVBoxLayout *scLayout = new QVBoxLayout();
    QLabel *lblScTitle = new QLabel(tr("SVC CODE"), cardFrame);
    lblScTitle->setStyleSheet("color: #727e99; font-size: 7pt; font-weight: bold;");
    labelServiceCode = new QLabel(tr("---"), cardFrame);
    labelServiceCode->setStyleSheet("color: #e4e9f7; font-family: monospace; font-weight: bold; font-size: 10pt;");
    scLayout->addWidget(lblScTitle);
    scLayout->addWidget(labelServiceCode);
    subCardLayout->addLayout(scLayout);

    subCardLayout->addSpacing(25);

    QVBoxLayout *modeLayout = new QVBoxLayout();
    QLabel *lblModeTitle = new QLabel(tr("TX MODE"), cardFrame);
    lblModeTitle->setStyleSheet("color: #727e99; font-size: 7pt; font-weight: bold;");
    labelMode = new QLabel(tr("MSD"), cardFrame);
    labelMode->setStyleSheet("color: #ffd166; font-family: monospace; font-weight: bold; font-size: 10pt;");
    modeLayout->addWidget(lblModeTitle);
    modeLayout->addWidget(labelMode);
    subCardLayout->addLayout(modeLayout);

    subCardLayout->addStretch(1);
    cardLayout->addLayout(subCardLayout);

    // Cardholder
    labelHolder = new QLabel(tr("CARDHOLDER/NAME"), cardFrame);
    labelHolder->setStyleSheet("color: #b0bcd6; font-size: 9pt; font-weight: bold; letter-spacing: 1px;");
    cardLayout->addWidget(labelHolder);

    middleLayout->addWidget(cardFrame);

    // Right: Technical Parameters & RF Interface Box
    QGroupBox *techBox = new QGroupBox(tr("Physical & Smartcard Interface Parameters"), this);
    techBox->setStyleSheet("QGroupBox { font-weight: bold; }");
    QVBoxLayout *techLayout = new QVBoxLayout(techBox);
    techLayout->setSpacing(6);

    auto makeRow = [](const QString &title, QLabel **targetLabel, QWidget *parent) -> QHBoxLayout* {
        QHBoxLayout *row = new QHBoxLayout();
        QLabel *titleLbl = new QLabel(title, parent);
        titleLbl->setStyleSheet("color: #9094a6; font-weight: 600; min-width: 130px;");
        *targetLabel = new QLabel(parent);
        (*targetLabel)->setStyleSheet("color: #ffffff; font-family: monospace; font-size: 9pt; font-weight: bold;");
        (*targetLabel)->setTextInteractionFlags(Qt::TextSelectableByMouse);
        row->addWidget(titleLbl);
        row->addWidget(*targetLabel, 1);
        return row;
    };

    techLayout->addLayout(makeRow(tr("ISO 14443-4A UID:"), &labelUid, techBox));
    techLayout->addLayout(makeRow(tr("Application AID:"), &labelAid, techBox));
    techLayout->addLayout(makeRow(tr("Historical Bytes (ATS):"), &labelAts, techBox));

    QHBoxLayout *actionBtnsLayout = new QHBoxLayout();
    btnSim14a = new QPushButton(tr("⚡ Simulate Card UID (hf 14a sim -t 4)"), techBox);
    btnSim14a->setStyleSheet("background-color: #242938; border: 1px solid #41485e; padding: 5px 10px; font-weight: 600;");
    connect(btnSim14a, &QPushButton::clicked, this, &EMVTab::onSimulate14a);
    actionBtnsLayout->addWidget(btnSim14a);

    btnSimJcop = new QPushButton(tr("⚡ Simulate JavaCard (hf 14a sim -t 11)"), techBox);
    btnSimJcop->setStyleSheet("background-color: #242938; border: 1px solid #41485e; padding: 5px 10px; font-weight: 600;");
    connect(btnSimJcop, &QPushButton::clicked, this, &EMVTab::onSimulateJcop);
    actionBtnsLayout->addWidget(btnSimJcop);

    techLayout->addLayout(actionBtnsLayout);

    QHBoxLayout *dataBtnsLayout = new QHBoxLayout();
    btnCopyPan = new QPushButton(tr("📋 Copy PAN"), techBox);
    connect(btnCopyPan, &QPushButton::clicked, this, &EMVTab::onCopyPan);
    dataBtnsLayout->addWidget(btnCopyPan);

    btnCopyTrack2 = new QPushButton(tr("📋 Copy Track 2 Equivalent"), techBox);
    connect(btnCopyTrack2, &QPushButton::clicked, this, &EMVTab::onCopyTrack2);
    dataBtnsLayout->addWidget(btnCopyTrack2);

    btnExportReport = new QPushButton(tr("📑 Export Security Audit Report"), techBox);
    connect(btnExportReport, &QPushButton::clicked, this, &EMVTab::onExportAuditReport);
    dataBtnsLayout->addWidget(btnExportReport);

    techLayout->addLayout(dataBtnsLayout);
    middleLayout->addWidget(techBox, 1);

    mainLayout->addLayout(middleLayout);

    // --- Sub-Tabs: TLV Tree, JSON Viewer, Online Payment Gateway ---
    subTabWidget = new QTabWidget(this);

    // Tab 1: Structured EMV TLV Tree
    QWidget *tabTlv = new QWidget();
    QVBoxLayout *tlvLayout = new QVBoxLayout(tabTlv);
    tlvLayout->setContentsMargins(4, 6, 4, 4);

    QHBoxLayout *tlvSearchLayout = new QHBoxLayout();
    QLabel *lblFilter = new QLabel(tr("Filter Tags / Values:"), tabTlv);
    lblFilter->setStyleSheet("color: #a0a0b0; font-size: 9pt;");
    tlvSearchLayout->addWidget(lblFilter);

    editFilterTlv = new QLineEdit(tabTlv);
    editFilterTlv->setPlaceholderText(tr("Search by tag hex (e.g. 57, 5F20), name, or hex content..."));
    connect(editFilterTlv, &QLineEdit::textChanged, this, &EMVTab::onFilterTlv);
    tlvSearchLayout->addWidget(editFilterTlv);
    tlvLayout->addLayout(tlvSearchLayout);

    treeTlv = new QTreeWidget(tabTlv);
    treeTlv->setHeaderLabels(QStringList() << tr("Tag") << tr("Tag Name") << tr("Len") << tr("Decoded Value / Meaning") << tr("Raw Hex Value"));
    treeTlv->setAlternatingRowColors(true);
    treeTlv->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    treeTlv->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    treeTlv->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    treeTlv->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    treeTlv->header()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    treeTlv->setStyleSheet("QTreeWidget { font-family: monospace; font-size: 9pt; }");
    tlvLayout->addWidget(treeTlv);

    subTabWidget->addTab(tabTlv, tr("📊 EMV TLV Data & Records"));

    // Tab 2: Raw JSON Editor
    QWidget *tabJson = new QWidget();
    QVBoxLayout *jsonLayout = new QVBoxLayout(tabJson);
    jsonLayout->setContentsMargins(4, 6, 4, 4);

    QHBoxLayout *jsonActions = new QHBoxLayout();
    QLabel *lblJsonInfo = new QLabel(tr("Original Proxmark3 `emv scan` JSON Dump:"), tabJson);
    lblJsonInfo->setStyleSheet("color: #8c8ea0; font-weight: bold;");
    jsonActions->addWidget(lblJsonInfo);
    jsonActions->addStretch(1);

    btnSaveJson = new QPushButton(tr("💾 Save Changes to JSON"), tabJson);
    connect(btnSaveJson, &QPushButton::clicked, this, &EMVTab::onSaveJsonClicked);
    jsonActions->addWidget(btnSaveJson);
    jsonLayout->addLayout(jsonActions);

    editRawJson = new QTextEdit(tabJson);
    editRawJson->setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 9pt; background-color: #121319;");
    jsonLayout->addWidget(editRawJson);

    subTabWidget->addTab(tabJson, tr("📝 Raw JSON File"));

    // Tab 3: Online Payment Gateway & POS Terminal
    QWidget *tabGateway = new QWidget();
    QVBoxLayout *gwLayout = new QVBoxLayout(tabGateway);
    gwLayout->setContentsMargins(6, 8, 6, 6);
    gwLayout->setSpacing(6);

    // Row 1: Charge Controls + Status Badge
    QHBoxLayout *gwFormLayout = new QHBoxLayout();
    gwFormLayout->setSpacing(8);

    lblGatewayStatusBadge = new QLabel(tr("● GATEWAY STARTING..."), tabGateway);
    lblGatewayStatusBadge->setStyleSheet("background-color: #263238; color: #80deea; border: 1px solid #00acc1; border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 8.5pt;");
    gwFormLayout->addWidget(lblGatewayStatusBadge);

    QLabel *lblAmt = new QLabel(tr("Amount ($ USD):"), tabGateway);
    lblAmt->setStyleSheet("color: #00e5ff; font-weight: bold;");
    gwFormLayout->addWidget(lblAmt);

    editChargeAmount = new QLineEdit("0.50", tabGateway);
    editChargeAmount->setMaximumWidth(80);
    editChargeAmount->setToolTip(tr("Transaction amount in USD (Min $0.50 for Stripe API)"));
    editChargeAmount->setStyleSheet("font-family: monospace; font-weight: bold; color: #00e676;");
    gwFormLayout->addWidget(editChargeAmount);

    QLabel *lblCvc = new QLabel(tr("CVC2:"), tabGateway);
    lblCvc->setStyleSheet("color: #a0a0b0; font-weight: bold;");
    gwFormLayout->addWidget(lblCvc);

    editCardCvc = new QLineEdit(tabGateway);
    editCardCvc->setMaximumWidth(65);
    editCardCvc->setPlaceholderText(tr("3-digit"));
    editCardCvc->setToolTip(tr("Optional 3- or 4-digit CVC2 security code for Stripe API charges"));
    gwFormLayout->addWidget(editCardCvc);

    QLabel *lblGwUrl = new QLabel(tr("Gateway:"), tabGateway);
    lblGwUrl->setStyleSheet("color: #a0a0b0; font-weight: bold;");
    gwFormLayout->addWidget(lblGwUrl);

    editGatewayUrl = new QLineEdit("http://127.0.0.1:8080", tabGateway);
    editGatewayUrl->setMinimumWidth(165);
    gwFormLayout->addWidget(editGatewayUrl);

    btnChargeOnline = new QPushButton(tr("💳 Authorize Loaded Card Online"), tabGateway);
    btnChargeOnline->setStyleSheet("background-color: #00838f; color: #ffffff; font-weight: bold; padding: 6px 12px; border-radius: 4px;");
    connect(btnChargeOnline, &QPushButton::clicked, this, &EMVTab::onChargeOnlineClicked);
    gwFormLayout->addWidget(btnChargeOnline);

    btnTapAndCharge = new QPushButton(tr("⚡ Live RF Tap & Charge ($)"), tabGateway);
    btnTapAndCharge->setStyleSheet("background-color: #1b5e20; color: #b9f6ca; border: 1px solid #00e676; font-weight: bold; padding: 6px 12px; border-radius: 4px;");
    connect(btnTapAndCharge, &QPushButton::clicked, this, &EMVTab::onTapAndChargeGatewayClicked);
    gwFormLayout->addWidget(btnTapAndCharge);

    btnOpenWebPos = new QPushButton(tr("🌐 Open Web POS"), tabGateway);
    btnOpenWebPos->setToolTip(tr("Open the full browser POS dashboard (with Stripe.js v3 Elements & Hosted Checkout) at http://127.0.0.1:8080"));
    btnOpenWebPos->setStyleSheet("background-color: #1e293b; color: #00e5ff; border: 1px solid #00b4d8; font-weight: bold; padding: 6px 10px; border-radius: 4px;");
    connect(btnOpenWebPos, &QPushButton::clicked, this, &EMVTab::onOpenWebPosClicked);
    gwFormLayout->addWidget(btnOpenWebPos);

    gwLayout->addLayout(gwFormLayout);

    // Row 2: Processor Credentials & Webhook Configuration
    QHBoxLayout *gwCfgLayout = new QHBoxLayout();
    gwCfgLayout->setSpacing(8);

    QLabel *lblStripe = new QLabel(tr("Stripe Secret Key:"), tabGateway);
    lblStripe->setStyleSheet("color: #a0a0b0; font-size: 8.5pt; font-weight: bold;");
    gwCfgLayout->addWidget(lblStripe);

    editStripeKey = new QLineEdit(tabGateway);
    editStripeKey->setPlaceholderText(tr("sk_live_... / rk_live_... / sk_test_... (Blank = Standalone ISO-8583 Acquirer)"));
    editStripeKey->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    gwCfgLayout->addWidget(editStripeKey, 2);

    QLabel *lblStripePk = new QLabel(tr("Publishable Key:"), tabGateway);
    lblStripePk->setStyleSheet("color: #a0a0b0; font-size: 8.5pt; font-weight: bold;");
    gwCfgLayout->addWidget(lblStripePk);

    editStripePk = new QLineEdit(tabGateway);
    editStripePk->setPlaceholderText(tr("pk_live_... / pk_test_..."));
    gwCfgLayout->addWidget(editStripePk, 2);

    QLabel *lblWebhook = new QLabel(tr("Webhook URL:"), tabGateway);
    lblWebhook->setStyleSheet("color: #a0a0b0; font-size: 8.5pt; font-weight: bold;");
    gwCfgLayout->addWidget(lblWebhook);

    editWebhookUrl = new QLineEdit(tabGateway);
    editWebhookUrl->setPlaceholderText(tr("https://... (Optional)"));
    gwCfgLayout->addWidget(editWebhookUrl, 1);

    btnSaveGatewayConfig = new QPushButton(tr("💾 Save Config"), tabGateway);
    btnSaveGatewayConfig->setToolTip(tr("Save processor keys and webhook configuration persistently to data/gateway_config.json"));
    connect(btnSaveGatewayConfig, &QPushButton::clicked, this, &EMVTab::onSaveGatewayConfigClicked);
    gwCfgLayout->addWidget(btnSaveGatewayConfig);

    btnRefreshLedger = new QPushButton(tr("↻ Refresh Ledger"), tabGateway);
    connect(btnRefreshLedger, &QPushButton::clicked, this, &EMVTab::onRefreshGatewayLedger);
    gwCfgLayout->addWidget(btnRefreshLedger);

    gwLayout->addLayout(gwCfgLayout);

    // Splitter: Live Transaction Ledger Table (Left) + Detailed JSON Inspector (Right)
    QSplitter *gwSplitter = new QSplitter(Qt::Horizontal, tabGateway);

    tableGatewayLedger = new QTableWidget(0, 8, gwSplitter);
    tableGatewayLedger->setHorizontalHeaderLabels(QStringList()
        << tr("Time")
        << tr("Tx ID / Auth")
        << tr("Amount")
        << tr("Card / PAN")
        << tr("Exp")
        << tr("ATC")
        << tr("ARQC (9F26)")
        << tr("Status / Processor"));
    tableGatewayLedger->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableGatewayLedger->setSelectionMode(QAbstractItemView::SingleSelection);
    tableGatewayLedger->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableGatewayLedger->setAlternatingRowColors(true);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    tableGatewayLedger->horizontalHeader()->setSectionResizeMode(7, QHeaderView::Stretch);
    tableGatewayLedger->setStyleSheet("QTableWidget { font-family: monospace; font-size: 8.5pt; }");

    connect(tableGatewayLedger, &QTableWidget::cellClicked, this, [this](int row, int) {
        if (row >= 0 && row < cachedLedgerArray.size()) {
            QJsonObject txObj = cachedLedgerArray[row].toObject();
            editGatewayLog->setPlainText(QString::fromUtf8(QJsonDocument(txObj).toJson(QJsonDocument::Indented)));
        }
    });

    editGatewayLog = new QTextEdit(gwSplitter);
    editGatewayLog->setReadOnly(true);
    editGatewayLog->setPlaceholderText(tr("Online EMV Acquirer / Stripe Gateway Authorization responses (ARQC -> ARPC Tag 91, Auth Code DE38, RRN DE37) will appear here... Click any row in the ledger table on the left to inspect its full ISO-8583 / Stripe JSON telemetry."));
    editGatewayLog->setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 9pt; background-color: #0d1117; color: #e6edf3;");

    gwSplitter->addWidget(tableGatewayLedger);
    gwSplitter->addWidget(editGatewayLog);
    gwSplitter->setStretchFactor(0, 58);
    gwSplitter->setStretchFactor(1, 42);

    gwLayout->addWidget(gwSplitter, 1);

    subTabWidget->addTab(tabGateway, tr("🌐 Online Payment Gateway"));

    mainLayout->addWidget(subTabWidget, 1);
}

void EMVTab::loadGatewayConfigFromDisk()
{
    QString cfgPath = "/home/kali/Proxmark3GUI/data/gateway_config.json";
    QFile f(cfgPath);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        f.close();
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            if (obj.contains("stripe_api_key")) {
                editStripeKey->setText(obj["stripe_api_key"].toString().trimmed());
            }
            if (obj.contains("stripe_publishable_key")) {
                editStripePk->setText(obj["stripe_publishable_key"].toString().trimmed());
            }
            if (obj.contains("webhook_url")) {
                editWebhookUrl->setText(obj["webhook_url"].toString().trimmed());
            }
        }
    }
}

void EMVTab::ensureGatewayServerRunning()
{
    QString baseUrl = editGatewayUrl->text().trimmed();
    if (baseUrl.endsWith("/")) baseUrl.chop(1);
    QNetworkRequest req(QUrl(baseUrl + "/api/health"));
    QNetworkReply *reply = netManager->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QString mode = doc.object()["mode"].toString("Online");
            lblGatewayStatusBadge->setText(tr("● GATEWAY ONLINE (%1)").arg(mode));
            lblGatewayStatusBadge->setStyleSheet("background-color: #1b5e20; color: #b9f6ca; border: 1px solid #00e676; border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 8.5pt;");
            onRefreshGatewayLedger();
        } else {
            // Gateway not running yet — spawn it automatically if local
            if (!gatewayProcess || gatewayProcess->state() == QProcess::NotRunning) {
                QString scriptPath = "/home/kali/Proxmark3GUI/src/online_gateway.py";
                if (QFile::exists(scriptPath)) {
                    if (!gatewayProcess) {
                        gatewayProcess = new QProcess(this);
                    }
                    lblGatewayStatusBadge->setText(tr("● STARTING GATEWAY..."));
                    lblGatewayStatusBadge->setStyleSheet("background-color: #3e2723; color: #ffcc80; border: 1px solid #ffa726; border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 8.5pt;");
                    gatewayProcess->start("/usr/bin/python3", QStringList() << scriptPath);
                    QTimer::singleShot(1500, this, &EMVTab::checkGatewayHealth);
                }
            }
        }
        reply->deleteLater();
    });
}

void EMVTab::checkGatewayHealth()
{
    QString baseUrl = editGatewayUrl->text().trimmed();
    if (baseUrl.endsWith("/")) baseUrl.chop(1);
    QNetworkRequest req(QUrl(baseUrl + "/api/health"));
    QNetworkReply *reply = netManager->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QString mode = doc.object()["mode"].toString("Online");
            lblGatewayStatusBadge->setText(tr("● GATEWAY ONLINE (%1)").arg(mode));
            lblGatewayStatusBadge->setStyleSheet("background-color: #1b5e20; color: #b9f6ca; border: 1px solid #00e676; border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 8.5pt;");
            if (cachedLedgerArray.isEmpty() && doc.object()["transactions_count"].toInt() > 0) {
                onRefreshGatewayLedger();
            }
        } else {
            lblGatewayStatusBadge->setText(tr("● GATEWAY OFFLINE"));
            lblGatewayStatusBadge->setStyleSheet("background-color: #3e2723; color: #ff8a80; border: 1px solid #ff5252; border-radius: 4px; padding: 4px 8px; font-weight: bold; font-size: 8.5pt;");
        }
        reply->deleteLater();
    });
}

void EMVTab::onSaveGatewayConfigClicked()
{
    QJsonObject cfgObj;
    cfgObj["stripe_api_key"] = editStripeKey->text().trimmed();
    cfgObj["stripe_publishable_key"] = editStripePk->text().trimmed();
    cfgObj["webhook_url"] = editWebhookUrl->text().trimmed();

    QDir().mkpath("/home/kali/Proxmark3GUI/data");
    QFile f("/home/kali/Proxmark3GUI/data/gateway_config.json");
    if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        f.write(QJsonDocument(cfgObj).toJson(QJsonDocument::Indented));
        f.close();
    }

    QString baseUrl = editGatewayUrl->text().trimmed();
    if (baseUrl.endsWith("/")) baseUrl.chop(1);
    QNetworkRequest req(QUrl(baseUrl + "/api/config"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QNetworkReply *reply = netManager->post(req, QJsonDocument(cfgObj).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        checkGatewayHealth();
        lblAutoPullStatus->setText(tr("💾 Gateway configuration saved"));
        lblAutoPullStatus->setStyleSheet("color: #00e676; font-weight: bold;");
        reply->deleteLater();
    });
}

void EMVTab::onOpenWebPosClicked()
{
    QString baseUrl = editGatewayUrl->text().trimmed();
    if (baseUrl.isEmpty()) baseUrl = "http://127.0.0.1:8080";
    QDesktopServices::openUrl(QUrl(baseUrl));
}

void EMVTab::onRefreshGatewayLedger()
{
    QString baseUrl = editGatewayUrl->text().trimmed();
    if (baseUrl.endsWith("/")) baseUrl.chop(1);
    QNetworkRequest req(QUrl(baseUrl + "/api/transactions"));
    QNetworkReply *reply = netManager->get(req);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isArray()) {
                cachedLedgerArray = doc.array();
                tableGatewayLedger->setRowCount(cachedLedgerArray.size());
                for (int i = 0; i < cachedLedgerArray.size(); ++i) {
                    QJsonObject tx = cachedLedgerArray[i].toObject();
                    QJsonObject card = tx["card"].toObject();
                    QJsonObject emv = tx["emv_telemetry"].toObject();
                    bool approved = tx["approved"].toBool();
                    QString isoCode = tx["iso8583_de39_response_code"].toString();
                    QString msg = tx["response_message"].toString();

                    QString timeStr = tx["timestamp"].toString().replace("T", " ").left(19);
                    QString txAuth = QString("%1 (%2)").arg(tx["tx_id"].toString(), tx["auth_code_de38"].toString("-"));
                    QString amt = tx["amount_formatted"].toString();
                    QString panStr = card["pan_masked"].toString();
                    if (panStr.isEmpty()) panStr = card["pan_full"].toString();
                    QString expStr = card["expiry"].toString("-");
                    QString atcStr = emv["atc_9F36"].toString("-");
                    QString arqcStr = emv["arqc_9F26"].toString("-");
                    QString statusStr = approved ? QString("✅ APPROVED (%1)").arg(isoCode) : QString("❌ DECLINED (%1): %2").arg(isoCode, msg);

                    auto setCell = [&](int col, const QString &text, const QColor &color = QColor()) {
                        QTableWidgetItem *item = new QTableWidgetItem(text);
                        if (color.isValid()) item->setForeground(color);
                        tableGatewayLedger->setItem(i, col, item);
                    };

                    setCell(0, timeStr);
                    setCell(1, txAuth);
                    setCell(2, amt, QColor("#00e5ff"));
                    setCell(3, QString("%1 %2").arg(card["brand"].toString(), panStr));
                    setCell(4, expStr);
                    setCell(5, atcStr);
                    setCell(6, arqcStr);
                    setCell(7, statusStr, approved ? QColor("#00e676") : QColor("#ff5252"));
                }
            }
        }
        reply->deleteLater();
    });
}

void EMVTab::onAutoPullClicked()
{
    if (!util) return;

    if (!util->getRunningState()) {
        lblAutoPullStatus->setText(tr("⚠️ Proxmark3 not connected. Connect device first!"));
        lblAutoPullStatus->setStyleSheet("color: #ff5252; font-weight: bold;");
        if (checkContinuous->isChecked()) {
            checkContinuous->setChecked(false);
        }
        return;
    }

    if (isAutoPulling) return;

    isAutoPulling = true;
    if (!checkContinuous->isChecked()) {
        lblAutoPullStatus->setText(tr("⏳ Polling antenna... Hold card near Proxmark3!"));
        lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-weight: bold;");
    } else {
        if (lastDetectedUid.isEmpty()) {
            lblAutoPullStatus->setText(tr("📡 Auto-Detector: Polling antenna for card..."));
            lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-style: italic;");
        }
    }

    QFile::remove("/tmp/emv_auto_pulled.json");
    autoPullTimer->start(12000);

    util->execCMD("emv scan --qvsdc -a -t /tmp/emv_auto_pulled.json");
}

void EMVTab::onAutoPullTimeout()
{
    if (!isAutoPulling) return;
    isAutoPulling = false;

    if (QFile::exists("/tmp/emv_auto_pulled.json") && QFileInfo("/tmp/emv_auto_pulled.json").size() > 50) {
        loadDumpFile("/tmp/emv_auto_pulled.json");
        populateQuickDumps();
        lblAutoPullStatus->setText(tr("✅ Data pulled successfully!"));
        lblAutoPullStatus->setStyleSheet("color: #00e676; font-weight: bold;");
        if (pendingOnlineChargeAfterPull && !rawPan.isEmpty()) {
            pendingOnlineChargeAfterPull = false;
            onChargeOnlineClicked();
        }
    } else {
        pendingOnlineChargeAfterPull = false;
        bool hadCard = !lastDetectedUid.isEmpty() || !rawPan.isEmpty() || !currentUid.isEmpty();
        if (checkClearOnRemove && checkClearOnRemove->isChecked()) {
            clearVisualCard();
        } else {
            lastDetectedUid.clear();
        }

        if (hadCard && checkClearOnRemove && checkClearOnRemove->isChecked()) {
            lblAutoPullStatus->setText(tr("👋 Card removed. Data cleared — waiting for card on antenna..."));
            lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-style: italic;");
        } else if (checkContinuous->isChecked()) {
            lblAutoPullStatus->setText(tr("📡 Waiting for card on antenna..."));
            lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-style: italic;");
        } else {
            lblAutoPullStatus->setText(tr("⚠️ Scan timed out. Check antenna coupling and try again."));
            lblAutoPullStatus->setStyleSheet("color: #ffb74d; font-weight: bold;");
        }
    }

    scheduleNextPoll();
}

void EMVTab::scheduleNextPoll()
{
    if (!checkContinuous || !checkContinuous->isChecked() || isAutoPulling) return;

    continuousTimer->stop();
    continuousTimer->start(1800);
}

void EMVTab::onContinuousPoll()
{
    if (!checkContinuous->isChecked() || isAutoPulling) return;
    if (!util || !util->getRunningState()) {
        scheduleNextPoll();
        return;
    }
    onAutoPullClicked();
}

void EMVTab::onPM3Connected()
{
    if (checkContinuous && checkContinuous->isChecked() && !isAutoPulling) {
        scheduleNextPoll();
    }
}

void EMVTab::onPM3Output(const QString &output)
{
    // Always intercept dump save notification even if timeout edge occurred
    bool fileSaved = (output.contains("emv_auto_pulled.json", Qt::CaseInsensitive) && 
                      (output.contains("saved", Qt::CaseInsensitive) || output.contains("Setting ISODEP", Qt::CaseInsensitive)));

    if (!isAutoPulling && !fileSaved) return;

    // 1. Detect scan completion
    bool scanSucceeded = fileSaved;
    if (output.contains("saved.", Qt::CaseInsensitive) ||
        output.contains("Setting ISODEP -> inactive", Qt::CaseInsensitive) ||
        output.contains("Saved to json file", Qt::CaseInsensitive) ||
        output.contains("proxmark3 `emv scan`", Qt::CaseInsensitive)) {
        scanSucceeded = true;
    }

    // 2. Detect scan failure (no card present, removed, or collision)
    bool selectFailed = false;
    bool multipleDetected = false;
    if (output.contains("multiple tags", Qt::CaseInsensitive) ||
        output.contains("collision", Qt::CaseInsensitive) ||
        output.contains("more than one", Qt::CaseInsensitive)) {
        selectFailed = true;
        multipleDetected = true;
    } else if (output.contains("card select failed", Qt::CaseInsensitive) ||
        output.contains("iso14443a card select failed", Qt::CaseInsensitive) ||
        output.contains("Can't select card", Qt::CaseInsensitive) ||
        output.contains("Selection failed", Qt::CaseInsensitive) ||
        output.contains("No tag found", Qt::CaseInsensitive) ||
        output.contains("No card found", Qt::CaseInsensitive) ||
        output.contains("No card present", Qt::CaseInsensitive) ||
        output.contains("Card is not responding", Qt::CaseInsensitive) ||
        output.contains("Card communication error", Qt::CaseInsensitive) ||
        output.contains("Auto scan failed", Qt::CaseInsensitive) ||
        output.contains("error selecting card", Qt::CaseInsensitive)) {
        selectFailed = true;
    }

    // 3. Fallback when prompt returns
    if (output.contains("pm3 -->") || output.contains("pm3 >")) {
        if (QFile::exists("/tmp/emv_auto_pulled.json") && QFileInfo("/tmp/emv_auto_pulled.json").size() > 50) {
            scanSucceeded = true;
        } else {
            selectFailed = true;
        }
    }

    if (scanSucceeded) {
        autoPullTimer->stop();
        isAutoPulling = false;

        QTimer::singleShot(100, this, [this]() {
            if (QFile::exists("/tmp/emv_auto_pulled.json")) {
                // Peek at the UID from the file
                QFile f("/tmp/emv_auto_pulled.json");
                QString scannedUid = "";
                if (f.open(QIODevice::ReadOnly)) {
                    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
                    f.close();
                    if (doc.isObject()) {
                        scannedUid = doc.object()["Card"].toObject()["Contactless"].toObject()["UID"].toString().trimmed();
                    }
                }

                bool isNewCard = (!scannedUid.isEmpty() && scannedUid != lastDetectedUid);
                lastDetectedUid = scannedUid;

                loadDumpFile("/tmp/emv_auto_pulled.json");
                populateQuickDumps();

                QString panDisplay = rawPan.isEmpty() ? "Card" : formattedPan;

                if (isNewCard) {
                    if (checkAutoSave && checkAutoSave->isChecked()) {
                        QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
                        QString cleanUid = scannedUid;
                        cleanUid.replace(" ", "");
                        QString archivePath = QString("/home/kali/rfid_dumps/emv_%1_%2.json").arg(cleanUid.isEmpty() ? "card" : cleanUid, timestamp);
                        QFile::copy("/tmp/emv_auto_pulled.json", archivePath);
                        populateQuickDumps();
                    }

                    // Flash the card frame with a glowing emerald border to visually signal the new card
                    cardFrame->setStyleSheet(
                        "QFrame {"
                        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #102a3a, stop:0.5 #0d222e, stop:1 #06151c);"
                        "  border: 2px solid #00e676;"
                        "  border-radius: 12px;"
                        "}"
                    );
                    QTimer::singleShot(1800, this, [this]() {
                        cardFrame->setStyleSheet(
                            "QFrame {"
                            "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1a233a, stop:0.5 #141c2c, stop:1 #0b111e);"
                            "  border: 1px solid #334166;"
                            "  border-radius: 12px;"
                            "}"
                        );
                    });

                    QString timeStr = QTime::currentTime().toString("hh:mm:ss");
                    lblAutoPullStatus->setText(tr("✨ NEW CARD: %1 (%2) [UID: %3] | %4").arg(labelCardBrandBadge->text(), panDisplay, scannedUid, timeStr));
                    lblAutoPullStatus->setStyleSheet("color: #00e676; font-weight: 900; font-size: 10pt;");
                } else {
                    QString timeStr = QTime::currentTime().toString("hh:mm:ss");
                    lblAutoPullStatus->setText(tr("🟢 Card Present: %1 (%2) | Read at %3").arg(labelCardBrandBadge->text(), panDisplay, timeStr));
                    lblAutoPullStatus->setStyleSheet("color: #00e676; font-weight: bold;");
                }

                if (pendingOnlineChargeAfterPull && !rawPan.isEmpty()) {
                    pendingOnlineChargeAfterPull = false;
                    onChargeOnlineClicked();
                }
            }
            scheduleNextPoll();
        });
    } else if (selectFailed) {
        autoPullTimer->stop();
        isAutoPulling = false;
        pendingOnlineChargeAfterPull = false;

        bool hadCard = !lastDetectedUid.isEmpty() || !rawPan.isEmpty() || !currentUid.isEmpty();
        if (checkClearOnRemove && checkClearOnRemove->isChecked()) {
            clearVisualCard();
        } else {
            if (!lastDetectedUid.isEmpty()) {
                lastDetectedUid.clear();
            }
        }
        QFile::remove("/tmp/emv_auto_pulled.json");

        QString timeStr = QTime::currentTime().toString("hh:mm:ss");
        if (multipleDetected) {
            lblAutoPullStatus->setText(tr("⚠️ Multiple tags detected! Separate cards and place only ONE card on antenna (%1)").arg(timeStr));
            lblAutoPullStatus->setStyleSheet("color: #ff5252; font-weight: bold;");
        } else if (hadCard && checkClearOnRemove && checkClearOnRemove->isChecked()) {
            lblAutoPullStatus->setText(tr("👋 Card removed. Data cleared — waiting for card on antenna... (%1)").arg(timeStr));
            lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-weight: 600; font-style: italic;");
        } else if (checkContinuous->isChecked()) {
            lblAutoPullStatus->setText(tr("📡 Waiting for card on antenna... (Polled %1)").arg(timeStr));
            lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-weight: 600; font-style: italic;");
        } else {
            lblAutoPullStatus->setText(tr("❌ No card detected on antenna. Place card on Proxmark3 and click Auto-Pull."));
            lblAutoPullStatus->setStyleSheet("color: #ff9800; font-weight: bold;");
        }
        scheduleNextPoll();
    }
}

void EMVTab::populateQuickDumps()
{
    comboQuickDumps->blockSignals(true);
    comboQuickDumps->clear();
    comboQuickDumps->addItem(tr("-- Select Saved EMV Dump --"), "");

    QStringList searchDirs = {"/home/kali", "/home/kali/rfid_dumps", "/tmp"};
    QSet<QString> addedPaths;

    for (const QString &dirPath : searchDirs) {
        QDir dir(dirPath);
        if (!dir.exists()) continue;
        QStringList filters = {"*visa*.json", "*credit*.json", "*debit*.json", "*emv*.json"};
        QFileInfoList list = dir.entryInfoList(filters, QDir::Files, QDir::Time);
        for (const QFileInfo &info : list) {
            QString path = info.canonicalFilePath();
            if (path.isEmpty()) path = info.absoluteFilePath();
            if (!addedPaths.contains(path)) {
                addedPaths.insert(path);
                comboQuickDumps->addItem(QString("%1 (%2)").arg(info.fileName(), dirPath), path);
            }
        }
    }
    comboQuickDumps->blockSignals(false);
}

void EMVTab::loadDumpFile(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("File Error"), tr("Failed to open file:\n%1").arg(filePath));
        return;
    }

    QByteArray data = file.readAll();
    file.close();

    currentFilePath = filePath;
    editRawJson->setPlainText(QString::fromUtf8(data));
    parseJsonData(data);
}

void EMVTab::parseJsonData(const QByteArray &data)
{
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        QMessageBox::warning(this, tr("Parse Error"), tr("Invalid JSON format:\n%1").arg(err.errorString()));
        return;
    }

    QJsonObject root = doc.object();
    treeTlv->clear();

    // 1. Card Section (Physical contactless info)
    QJsonObject cardObj = root["Card"].toObject();
    QJsonObject contactlessObj = cardObj["Contactless"].toObject();
    currentUid = contactlessObj["UID"].toString().trimmed();
    QString atqa = contactlessObj["ATQA"].toString().trimmed();
    QString sak = contactlessObj["SAK"].toString().trimmed();
    QString ats = contactlessObj["ATS"].toString().trimmed();

    labelUid->setText(currentUid.isEmpty() ? tr("Unknown") : currentUid);
    labelAts->setText(ats.isEmpty() ? tr("None") : ats);

    QTreeWidgetItem *cardNode = new QTreeWidgetItem(treeTlv);
    cardNode->setText(0, "PHYS");
    cardNode->setText(1, tr("ISO 14443-4 Type A Physical Layer"));
    cardNode->setText(3, QString("UID: %1 | ATQA: %2 | SAK: %3").arg(currentUid, atqa, sak));
    cardNode->setText(4, ats);

    // 2. PPSE (Proximity Payment System Environment)
    QJsonObject ppseObj = root["PPSE"].toObject();
    QString ppseAid = ppseObj["AID"].toString().trimmed();
    QJsonObject ppseFci = ppseObj["FCITemplate"].toObject();

    QTreeWidgetItem *ppseNode = new QTreeWidgetItem(treeTlv);
    ppseNode->setText(0, "PPSE");
    ppseNode->setText(1, tr("PPSE Directory (2PAY.SYS.DDF01)"));
    ppseNode->setText(3, ppseAid);
    ppseNode->setText(4, ppseFci["value"].toString());

    if (ppseFci.contains("value")) {
        parseTlvHexString(ppseFci["value"].toString(), ppseNode);
    }

    // 3. Application Section
    QJsonObject appObj = root["Application"].toObject();
    currentAid = appObj["AID"].toString().trimmed();
    currentMode = appObj["Mode"].toString().trimmed();
    labelAid->setText(currentAid);
    labelMode->setText(currentMode.isEmpty() ? "EMV" : currentMode);

    QJsonObject appFci = appObj["FCITemplate"].toObject();
    QTreeWidgetItem *appFciNode = new QTreeWidgetItem(treeTlv);
    appFciNode->setText(0, "6F");
    appFciNode->setText(1, tr("Application FCI Template"));
    appFciNode->setText(2, appFci["length"].toString());
    appFciNode->setText(3, QString("AID: %1 (Mode: %2)").arg(currentAid, currentMode));
    appFciNode->setText(4, appFci["value"].toString());

    if (appFci.contains("value")) {
        parseTlvHexString(appFci["value"].toString(), appFciNode);
    }

    // 4. GPO (Get Processing Options)
    QJsonObject gpoObj = appObj["GPO"].toObject();
    QTreeWidgetItem *gpoNode = new QTreeWidgetItem(treeTlv);
    gpoNode->setText(0, gpoObj["tag"].toString());
    gpoNode->setText(1, gpoObj["name"].toString());
    gpoNode->setText(2, gpoObj["length"].toString());
    gpoNode->setText(3, tr("GPO Response (AIP, AFL & qVSDC Data)"));
    gpoNode->setText(4, gpoObj["value"].toString());

    if (gpoObj.contains("value")) {
        parseTlvHexString(gpoObj["value"].toString(), gpoNode);
    }

    // 5. Records (Read Record APDU results)
    QJsonArray recordsArr = appObj["Records"].toArray();
    for (int i = 0; i < recordsArr.size(); ++i) {
        QJsonObject recObj = recordsArr[i].toObject();
        QString sfi = recObj["SFI"].toString();
        QString recNum = recObj["RecordNum"].toString();
        QJsonObject dataObj = recObj["Data"].toObject();

        QTreeWidgetItem *recNode = new QTreeWidgetItem(treeTlv);
        recNode->setText(0, "70");
        recNode->setText(1, QString("READ RECORD [SFI %1, Rec %2]").arg(sfi, recNum));
        recNode->setText(2, dataObj["length"].toString());
        recNode->setText(3, dataObj["name"].toString());
        recNode->setText(4, dataObj["value"].toString());

        if (dataObj.contains("value")) {
            parseTlvHexString(dataObj["value"].toString(), recNode);
        }
    }

    treeTlv->expandAll();
    updateVisualCard();
}

void EMVTab::parseTlvHexString(const QString &hexStr, QTreeWidgetItem *parentItem)
{
    QString cleanHex = hexStr;
    cleanHex.remove(' ');
    QByteArray bytes = QByteArray::fromHex(cleanHex.toLatin1());
    parseTlvBytes(bytes, parentItem);
}

void EMVTab::parseTlvBytes(const QByteArray &rawBytes, QTreeWidgetItem *parentItem)
{
    int idx = 0;
    int totalLen = rawBytes.size();

    while (idx < totalLen) {
        int tagStart = idx;
        unsigned char b = static_cast<unsigned char>(rawBytes[idx++]);

        // Multibyte tag check: if low 5 bits are 11111 (0x1F)
        if ((b & 0x1F) == 0x1F) {
            while (idx < totalLen) {
                unsigned char nb = static_cast<unsigned char>(rawBytes[idx++]);
                if (!(nb & 0x80)) {
                    break;
                }
            }
        }
        QByteArray tagBytes = rawBytes.mid(tagStart, idx - tagStart);
        QString tagHex = QString::fromLatin1(tagBytes.toHex()).toUpper();

        if (idx >= totalLen) break;

        // Length byte parsing
        unsigned char lenByte = static_cast<unsigned char>(rawBytes[idx++]);
        int valLength = 0;
        if (lenByte < 0x80) {
            valLength = lenByte;
        } else if (lenByte == 0x81) {
            if (idx >= totalLen) break;
            valLength = static_cast<unsigned char>(rawBytes[idx++]);
        } else if (lenByte == 0x82) {
            if (idx + 1 >= totalLen) break;
            valLength = (static_cast<unsigned char>(rawBytes[idx]) << 8) | static_cast<unsigned char>(rawBytes[idx + 1]);
            idx += 2;
        } else {
            valLength = lenByte & 0x7F;
        }

        if (idx + valLength > totalLen) {
            valLength = totalLen - idx;
        }

        QByteArray valBytes = rawBytes.mid(idx, valLength);
        QString valHex = QString::fromLatin1(valBytes.toHex()).toUpper();
        idx += valLength;

        bool isConstructed = (static_cast<unsigned char>(rawBytes[tagStart]) & 0x20) != 0;
        QString tagName = getTagName(tagHex);
        QString decodedMeaning = "";

        // Check for ASCII representation
        bool isAscii = true;
        for (char c : valBytes) {
            if (c < 32 || c > 126) {
                isAscii = false;
                break;
            }
        }
        if (isAscii && valBytes.size() > 1) {
            decodedMeaning = QString("ASCII: \"%1\"").arg(QString::fromLatin1(valBytes));
        }

        // Tag-specific decoders
        if (tagHex == "50") {
            // Application Label
            decodedMeaning = QString::fromLatin1(valBytes);
            labelCardBrandBadge->setText(decodedMeaning.toUpper());
        } else if (tagHex == "5F20") {
            // Cardholder Name
            cardholderName = QString::fromLatin1(valBytes).trimmed();
            decodedMeaning = cardholderName;
        } else if (tagHex == "57") {
            // Track 2 Equivalent Data
            rawTrack2 = valHex;
            QString trackStr = valHex;
            int dIndex = trackStr.indexOf('D');
            if (dIndex != -1) {
                rawPan = trackStr.left(dIndex);
                QString afterD = trackStr.mid(dIndex + 1);
                if (afterD.size() >= 7) {
                    QString yy = afterD.mid(0, 2);
                    QString mm = afterD.mid(2, 2);
                    expiryDate = QString("%1/%2").arg(mm, yy);
                    serviceCode = afterD.mid(4, 3);
                    QString discretionary = afterD.mid(7);
                    discretionary.remove('F');
                    decodedMeaning = QString("PAN: %1 | Exp: %2 | Svc: %3 | Disc: %4")
                                     .arg(rawPan, expiryDate, serviceCode, discretionary);
                } else {
                    decodedMeaning = QString("PAN: %1").arg(rawPan);
                }
            }
        } else if (tagHex == "5F24") {
            // Application Expiration Date (YYMMDD)
            if (valHex.size() >= 4) {
                QString yy = valHex.mid(0, 2);
                QString mm = valHex.mid(2, 2);
                QString dd = valHex.size() >= 6 ? valHex.mid(4, 2) : "";
                decodedMeaning = dd.isEmpty() ? QString("%1/%2").arg(mm, yy) : QString("20%1-%2-%3").arg(yy, mm, dd);
                expiryDate = QString("%1/%2").arg(mm, yy);
            }
        } else if (tagHex == "5F25") {
            // Application Effective Date (YYMMDD)
            if (valHex.size() >= 4) {
                QString yy = valHex.mid(0, 2);
                QString mm = valHex.mid(2, 2);
                QString dd = valHex.size() >= 6 ? valHex.mid(4, 2) : "";
                decodedMeaning = dd.isEmpty() ? QString("%1/%2").arg(mm, yy) : QString("20%1-%2-%3").arg(yy, mm, dd);
            }
        } else if (tagHex == "5A") {
            // PAN directly
            rawPan = valHex;
            decodedMeaning = QString("PAN: %1").arg(rawPan);
        } else if (tagHex == "9F26") {
            currentArqc = valHex;
            decodedMeaning = QString("ARQC / Cryptogram: %1").arg(valHex);
        } else if (tagHex == "9F27") {
            currentCid = valHex;
            decodedMeaning = (valHex == "80") ? tr("ARQC (Online Authorization Requested)") : QString("CID: %1").arg(valHex);
        } else if (tagHex == "9F36") {
            currentAtc = valHex;
            bool ok = false;
            int atcDec = valHex.toInt(&ok, 16);
            decodedMeaning = ok ? QString("ATC: #%1 (0x%2)").arg(atcDec).arg(valHex) : valHex;
        } else if (tagHex == "9F10") {
            currentIad = valHex;
            decodedMeaning = QString("IAD: %1").arg(valHex);
        } else if (tagHex == "9F6E") {
            decodedMeaning = tr("Visa Form Factor Indicator (Contactless)");
        } else if (tagHex == "9F38") {
            decodedMeaning = tr("PDOL (Processing Options Data Object List)");
        } else if (tagHex == "84") {
            if (isAscii) {
                decodedMeaning = QString("DF Name: %1").arg(QString::fromLatin1(valBytes));
            } else {
                decodedMeaning = QString("AID: %1").arg(valHex);
            }
        }

        QTreeWidgetItem *node = new QTreeWidgetItem(parentItem);
        node->setText(0, tagHex);
        node->setText(1, tagName);
        node->setText(2, QString::number(valLength));
        node->setText(3, decodedMeaning);
        node->setText(4, valHex);

        if (isConstructed && valLength > 0) {
            parseTlvBytes(valBytes, node);
        }
    }
}

void EMVTab::updateVisualCard()
{
    // 1. Format PAN
    if (!rawPan.isEmpty()) {
        QString clean = rawPan;
        clean.remove(' ');
        QString formatted;
        for (int i = 0; i < clean.size(); ++i) {
            if (i > 0 && i % 4 == 0) formatted += " ";
            formatted += clean[i];
        }
        formattedPan = formatted;

        if (panMasked && clean.size() >= 8) {
            QString masked = clean.left(4);
            masked += " •••• •••• ";
            masked += clean.right(4);
            labelPan->setText(masked);
            btnTogglePan->setText(tr("👁 Show"));
        } else {
            labelPan->setText(formattedPan);
            btnTogglePan->setText(tr("👁 Hide"));
        }
    } else {
        labelPan->setText(tr("•••• •••• •••• ••••"));
    }

    // 2. Expiry & Service Code
    labelExpiry->setText(expiryDate.isEmpty() ? "--/--" : expiryDate);
    labelServiceCode->setText(serviceCode.isEmpty() ? "---" : serviceCode);
    labelHolder->setText(cardholderName.isEmpty() ? "CARDHOLDER / VALUED CUSTOMER" : cardholderName);

    // 3. Card Brand Coloring
    QString brand = labelCardBrandBadge->text().toUpper();
    if (brand.contains("DEBIT")) {
        labelCardBrandBadge->setStyleSheet("background-color: #00e676; color: #0a0e17; font-weight: 900; font-size: 9pt; padding: 2px 8px; border-radius: 4px;");
    } else if (brand.contains("CREDIT") || brand.contains("VISA")) {
        labelCardBrandBadge->setStyleSheet("background-color: #00e5ff; color: #0a0e17; font-weight: 900; font-size: 9pt; padding: 2px 8px; border-radius: 4px;");
    } else if (brand.contains("MASTER")) {
        labelCardBrandBadge->setStyleSheet("background-color: #ff5722; color: #ffffff; font-weight: 900; font-size: 9pt; padding: 2px 8px; border-radius: 4px;");
    } else {
        labelCardBrandBadge->setStyleSheet("background-color: #ffd166; color: #0a0e17; font-weight: 900; font-size: 9pt; padding: 2px 8px; border-radius: 4px;");
    }
}

void EMVTab::clearVisualCard()
{
    currentUid.clear();
    lastDetectedUid.clear();
    currentAid.clear();
    currentMode.clear();
    rawPan.clear();
    formattedPan.clear();
    cardholderName.clear();
    expiryDate.clear();
    serviceCode.clear();
    rawTrack2.clear();
    currentArqc.clear();
    currentAtc.clear();
    currentIad.clear();
    currentCid.clear();

    labelCardBrandBadge->setText(tr("READY TO SCAN"));
    labelCardBrandBadge->setStyleSheet("background-color: #2b3650; color: #8896b4; font-weight: 700; font-size: 8pt; padding: 2px 6px; border-radius: 4px;");
    labelPan->setText(tr("•••• •••• •••• ••••"));
    labelExpiry->setText("--/--");
    labelServiceCode->setText("---");
    labelMode->setText("---");
    labelHolder->setText(tr("HOLD CARD NEAR ANTENNA"));
    labelUid->setText(tr("Waiting for card..."));
    labelAts->setText(tr("---"));
    labelAid->setText(tr("---"));
    btnTogglePan->setText(tr("👁 Show"));
    treeTlv->clear();
    editRawJson->clear();

    cardFrame->setStyleSheet(
        "QFrame {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #101624, stop:0.5 #0c111a, stop:1 #06090e);"
        "  border: 1px dashed #2e3a54;"
        "  border-radius: 12px;"
        "}"
    );
}

void EMVTab::onClearCardClicked()
{
    clearVisualCard();
    lblAutoPullStatus->setText(tr("Screen cleared. Polling antenna for card..."));
    lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-style: italic;");
}

void EMVTab::onSaveDumpClicked()
{
    QString jsonContent = editRawJson->toPlainText().trimmed();
    if (jsonContent.isEmpty()) {
        if (QFile::exists("/tmp/emv_auto_pulled.json")) {
            QFile f("/tmp/emv_auto_pulled.json");
            if (f.open(QIODevice::ReadOnly)) {
                jsonContent = QString::fromUtf8(f.readAll());
                f.close();
            }
        }
    }

    if (jsonContent.isEmpty()) {
        QMessageBox::information(this, tr("No Data"), tr("No card dump data is available to save. Please present a card or click Auto-Pull first."));
        return;
    }

    QString cleanUid = currentUid;
    if (cleanUid.isEmpty()) cleanUid = lastDetectedUid;
    cleanUid.remove(' ');
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
    QString defaultFilename = QString("emv_%1_%2.json").arg(cleanUid.isEmpty() ? "card" : cleanUid, timestamp);
    QString defaultPath = QString("/home/kali/rfid_dumps/%1").arg(defaultFilename);

    QDir().mkpath("/home/kali/rfid_dumps");

    QString savePath = QFileDialog::getSaveFileName(
        this,
        tr("Save EMV Card Dump"),
        defaultPath,
        tr("JSON Files (*.json);;All Files (*)")
    );

    if (savePath.isEmpty()) return;

    QFile outFile(savePath);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Save Error"), tr("Could not write to file:\n%1").arg(savePath));
        return;
    }

    QTextStream out(&outFile);
    out << jsonContent;
    outFile.close();

    populateQuickDumps();

    lblAutoPullStatus->setText(tr("💾 Dump saved: %1").arg(QFileInfo(savePath).fileName()));
    lblAutoPullStatus->setStyleSheet("color: #00e676; font-weight: bold;");
    QMessageBox::information(this, tr("Dump Saved"), tr("Card dump successfully saved to:\n%1").arg(savePath));
}

void EMVTab::onBrowseDumpClicked()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("Open EMV Scan JSON File"),
        "/home/kali/rfid_dumps",
        tr("JSON Files (*.json);;All Files (*)")
    );
    if (!filePath.isEmpty()) {
        if (checkContinuous && checkContinuous->isChecked()) {
            checkContinuous->setChecked(false);
        }
        loadDumpFile(filePath);
        populateQuickDumps();
    }
}

void EMVTab::onQuickDumpSelected(int index)
{
    if (index <= 0) return;
    QString path = comboQuickDumps->itemData(index).toString();
    if (!path.isEmpty()) {
        if (checkContinuous && checkContinuous->isChecked()) {
            checkContinuous->setChecked(false);
        }
        loadDumpFile(path);
    }
}

void EMVTab::onScanLiveClicked()
{
    if (util) {
        util->execCMD("emv scan -at");
        if (Util::onGotoRawTab) {
            Util::onGotoRawTab();
        }
    }
}

void EMVTab::onSearchAppletsClicked()
{
    if (util) {
        util->execCMD("emv search");
        if (Util::onGotoRawTab) {
            Util::onGotoRawTab();
        }
    }
}

void EMVTab::onCardInfoClicked()
{
    if (util) {
        util->execCMD("hf 14a info");
        if (Util::onGotoRawTab) {
            Util::onGotoRawTab();
        }
    }
}

void EMVTab::onTogglePanMask()
{
    panMasked = !panMasked;
    updateVisualCard();
}

void EMVTab::onSimulate14a()
{
    if (currentUid.isEmpty()) {
        QMessageBox::information(this, tr("No UID"), tr("No ISO 14443-4A UID is available to simulate."));
        return;
    }
    QString cleanUid = currentUid;
    cleanUid.remove(' ');
    QString cmd = QString("hf 14a sim -t 4 --uid %1").arg(cleanUid);
    if (util) {
        util->execCMD(cmd);
        if (Util::onGotoRawTab) {
            Util::onGotoRawTab();
        }
    }
}

void EMVTab::onSimulateJcop()
{
    if (currentUid.isEmpty()) {
        QMessageBox::information(this, tr("No UID"), tr("No ISO 14443-4A UID is available to simulate."));
        return;
    }
    QString cleanUid = currentUid;
    cleanUid.remove(' ');
    QString cmd = QString("hf 14a sim -t 11 --uid %1").arg(cleanUid);
    if (util) {
        util->execCMD(cmd);
        if (Util::onGotoRawTab) {
            Util::onGotoRawTab();
        }
    }
}

void EMVTab::onCopyTrack2()
{
    if (rawTrack2.isEmpty()) {
        QMessageBox::information(this, tr("Info"), tr("No Track 2 Equivalent data is loaded."));
        return;
    }
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(rawTrack2);
    QMessageBox::information(this, tr("Copied"), tr("Track 2 Equivalent data copied to clipboard:\n%1").arg(rawTrack2));
}

void EMVTab::onCopyPan()
{
    if (rawPan.isEmpty()) {
        QMessageBox::information(this, tr("Info"), tr("No Primary Account Number (PAN) is loaded."));
        return;
    }
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(rawPan);
    QMessageBox::information(this, tr("Copied"), tr("PAN copied to clipboard:\n%1").arg(rawPan));
}

void EMVTab::onExportAuditReport()
{
    QString savePath = QFileDialog::getSaveFileName(
        this,
        tr("Export Security Audit Report"),
        QString("/home/kali/emv_security_report_%1.md").arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")),
        tr("Markdown (*.md);;Text (*.txt)")
    );
    if (savePath.isEmpty()) return;

    QFile file(savePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Could not write to file:\n%1").arg(savePath));
        return;
    }

    QTextStream out(&file);
    out << "# Contactless EMV Smartcard Security Assessment\n\n";
    out << "- **Report Generated:** " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
    out << "- **Dump File Source:** `" << currentFilePath << "`\n\n";
    out << "---\n\n";
    out << "## 1. Card Identity & Profile\n\n";
    out << "| Field | Value |\n";
    out << "| :--- | :--- |\n";
    out << "| **Brand / Label** | " << labelCardBrandBadge->text() << " |\n";
    out << "| **Primary Account Number (PAN)** | `" << (rawPan.isEmpty() ? "N/A" : rawPan) << "` |\n";
    out << "| **Expiration Date** | `" << expiryDate << "` |\n";
    out << "| **Service Code** | `" << serviceCode << "` |\n";
    out << "| **Cardholder Name** | `" << cardholderName << "` |\n";
    out << "| **Application ID (AID)** | `" << currentAid << "` |\n";
    out << "| **Transaction Mode** | `" << currentMode << "` |\n";
    out << "| **Contactless UID** | `" << currentUid << "` |\n";
    out << "| **ATS** | `" << labelAts->text() << "` |\n\n";
    out << "---\n\n";
    out << "## 2. Security & Vulnerability Analysis\n\n";
    if (currentMode.contains("MSD", Qt::CaseInsensitive)) {
        out << "### ⚠️ Magnetic Stripe Data (MSD) Mode Exposure\n";
        out << "- **Risk:** This contactless card permits transactions using legacy **MSD mode**.\n";
        out << "- **Impact:** The card transmits unencrypted Track 2 equivalent data over the contactless interface during `READ RECORD` without requiring dynamic cryptogram (qVSDC/CDA) challenge-response authentication. An unauthorized NFC reader can skim the full PAN and expiration date without user interaction.\n\n";
    }
    out << "### Plaintext Tag Exposure\n";
    out << "- **Track 2 Hex:** `" << rawTrack2 << "`\n";
    out << "- **Service Code:** `" << serviceCode << "` (Indicates interchange rules and PIN requirement constraints).\n";
    out << "\n---\n*Generated by Proxmark3GUI EMV Security Inspector*\n";

    file.close();
    QMessageBox::information(this, tr("Export Successful"), tr("Audit report saved successfully:\n%1").arg(savePath));
}

void EMVTab::onSaveJsonClicked()
{
    if (currentFilePath.isEmpty()) {
        onBrowseDumpClicked();
        return;
    }
    QFile file(currentFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Failed to write to file:\n%1").arg(currentFilePath));
        return;
    }
    QTextStream out(&file);
    out << editRawJson->toPlainText();
    file.close();
    QMessageBox::information(this, tr("Saved"), tr("File saved successfully."));
    parseJsonData(editRawJson->toPlainText().toUtf8());
}

void EMVTab::onFilterTlv(const QString &filterText)
{
    QString term = filterText.trimmed().toLower();
    std::function<bool(QTreeWidgetItem*)> filterItem = [&](QTreeWidgetItem *item) -> bool {
        bool match = false;
        if (term.isEmpty()) {
            match = true;
        } else {
            for (int col = 0; col < item->columnCount(); ++col) {
                if (item->text(col).toLower().contains(term)) {
                    match = true;
                    break;
                }
            }
        }

        bool anyChildMatch = false;
        for (int i = 0; i < item->childCount(); ++i) {
            if (filterItem(item->child(i))) {
                anyChildMatch = true;
            }
        }

        bool visible = match || anyChildMatch;
        item->setHidden(!visible);
        if (visible && !term.isEmpty()) {
            item->setExpanded(true);
        }
        return visible;
    };

    for (int i = 0; i < treeTlv->topLevelItemCount(); ++i) {
        filterItem(treeTlv->topLevelItem(i));
    }
}

void EMVTab::onChargeOnlineClicked()
{
    if (rawPan.isEmpty()) {
        QMessageBox::warning(this, tr("No Card Loaded"), tr("Please pull a card from the Proxmark3 or load a dump before submitting an online charge."));
        return;
    }

    double dollars = editChargeAmount->text().toDouble();
    int cents = qRound(dollars * 100.0);
    if (cents <= 0) cents = 50;

    QString baseUrl = editGatewayUrl->text().trimmed();
    if (baseUrl.endsWith("/")) baseUrl.chop(1);
    QUrl url(baseUrl + "/api/authorize");

    QJsonObject payload;
    payload["pan"] = rawPan;
    payload["expiry"] = expiryDate;
    payload["amount_cents"] = cents;
    payload["currency"] = "USD";
    payload["cryptogram_arqc"] = currentArqc;
    payload["cid"] = currentCid.isEmpty() ? "80" : currentCid;
    payload["atc"] = currentAtc;
    payload["iad"] = currentIad;
    payload["track2"] = rawTrack2;
    payload["uid"] = currentUid;
    payload["aid"] = currentAid;
    payload["cardholder"] = cardholderName;
    payload["app_label"] = labelCardBrandBadge->text();
    if (!editCardCvc->text().trimmed().isEmpty()) {
        payload["cvc"] = editCardCvc->text().trimmed();
    }
    QString sk = editStripeKey->text().trimmed();
    payload["stripe_api_key"] = sk.isEmpty() ? "NONE" : sk;
    payload["stripe_publishable_key"] = editStripePk->text().trimmed();
    payload["webhook_url"] = editWebhookUrl->text().trimmed();

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    editGatewayLog->append(QString("\n[%1] >>> Sending Online Authorization Request ($%2 USD) to %3...")
                           .arg(QTime::currentTime().toString("hh:mm:ss"))
                           .arg(QString::number(cents / 100.0, 'f', 2))
                           .arg(url.toString()));

    btnChargeOnline->setEnabled(false);
    QNetworkReply *reply = netManager->post(req, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        btnChargeOnline->setEnabled(true);
        QByteArray respBytes = reply->readAll();
        if (reply->error() != QNetworkReply::NoError && respBytes.isEmpty()) {
            editGatewayLog->append(QString("❌ Network Error: %1").arg(reply->errorString()));
            lblAutoPullStatus->setText(tr("❌ Gateway Connection Failed — Starting local gateway..."));
            lblAutoPullStatus->setStyleSheet("color: #ff5252; font-weight: bold;");
            ensureGatewayServerRunning();
        } else {
            QJsonDocument doc = QJsonDocument::fromJson(respBytes);
            QString pretty = doc.isNull() ? QString::fromUtf8(respBytes) : QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
            editGatewayLog->setPlainText(pretty);

            if (doc.isObject()) {
                QJsonObject obj = doc.object();
                bool approved = obj["approved"].toBool();
                QString authCode = obj["auth_code_de38"].toString();
                QString arpc = obj["emv_telemetry"].toObject()["issuer_arpc_91"].toString();
                QString amtStr = obj["amount_formatted"].toString();
                if (approved) {
                    lblAutoPullStatus->setText(tr("✅ ONLINE APPROVED: %1 | Auth: %2 | ARPC: %3").arg(amtStr, authCode, arpc));
                    lblAutoPullStatus->setStyleSheet("color: #00e676; font-weight: 900;");
                } else {
                    lblAutoPullStatus->setText(tr("❌ ONLINE DECLINED: %1").arg(obj["response_message"].toString()));
                    lblAutoPullStatus->setStyleSheet("color: #ff5252; font-weight: bold;");
                }
            }
            onRefreshGatewayLedger();
        }
        subTabWidget->setCurrentIndex(2);
        reply->deleteLater();
    });
}

void EMVTab::onTapAndChargeGatewayClicked()
{
    double dollars = editChargeAmount->text().toDouble();
    int cents = qRound(dollars * 100.0);
    if (cents <= 0) cents = 50;

    // If Proxmark3 client is connected inside GUI:
    // 1. If a card is already loaded on screen, authorize it immediately.
    // 2. If no card is loaded yet, pull the card via GUI's connected PM3Process and chain the online charge!
    if (util && util->getRunningState()) {
        if (!rawPan.isEmpty()) {
            onChargeOnlineClicked();
        } else {
            pendingOnlineChargeAfterPull = true;
            lblAutoPullStatus->setText(tr("⚡ Reading card on Proxmark3 for live $%1 online charge...").arg(QString::number(cents / 100.0, 'f', 2)));
            lblAutoPullStatus->setStyleSheet("color: #00e5ff; font-weight: bold;");
            onAutoPullClicked();
        }
        return;
    }

    QString baseUrl = editGatewayUrl->text().trimmed();
    if (baseUrl.endsWith("/")) baseUrl.chop(1);
    QUrl url(baseUrl + "/api/tap-and-pay");

    QJsonObject payload;
    payload["amount_cents"] = cents;
    payload["currency"] = "USD";
    payload["port"] = "/dev/ttyACM0";
    if (!editCardCvc->text().trimmed().isEmpty()) {
        payload["cvc"] = editCardCvc->text().trimmed();
    }
    QString sk = editStripeKey->text().trimmed();
    payload["stripe_api_key"] = sk.isEmpty() ? "NONE" : sk;
    payload["stripe_publishable_key"] = editStripePk->text().trimmed();
    payload["webhook_url"] = editWebhookUrl->text().trimmed();

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    editGatewayLog->append(QString("\n[%1] >>> Polling Proxmark3 RF & Submitting Live $%2 USD Charge via %3...")
                           .arg(QTime::currentTime().toString("hh:mm:ss"))
                           .arg(QString::number(cents / 100.0, 'f', 2))
                           .arg(url.toString()));

    btnTapAndCharge->setEnabled(false);
    QNetworkReply *reply = netManager->post(req, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        btnTapAndCharge->setEnabled(true);
        QByteArray respBytes = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(respBytes);
        QString pretty = doc.isNull() ? QString::fromUtf8(respBytes) : QString::fromUtf8(doc.toJson(QJsonDocument::Indented));
        editGatewayLog->setPlainText(pretty);
        if (doc.isObject()) {
            QJsonObject obj = doc.object();
            if (obj.contains("approved")) {
                bool approved = obj["approved"].toBool();
                if (approved) {
                    lblAutoPullStatus->setText(tr("✅ TAP & PAY APPROVED: %1 | Auth: %2").arg(obj["amount_formatted"].toString(), obj["auth_code_de38"].toString()));
                    lblAutoPullStatus->setStyleSheet("color: #00e676; font-weight: 900;");
                } else {
                    lblAutoPullStatus->setText(tr("❌ TAP & PAY DECLINED: %1").arg(obj["response_message"].toString()));
                    lblAutoPullStatus->setStyleSheet("color: #ff5252; font-weight: bold;");
                }
            }
        }
        onRefreshGatewayLedger();
        subTabWidget->setCurrentIndex(2);
        reply->deleteLater();
    });
}
