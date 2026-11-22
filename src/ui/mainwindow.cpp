#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QJsonDocument>
#include <QDirIterator>

MainWindow::MainWindow(QWidget *parent):
    QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    mainSplitter = nullptr;
    consoleDrawer = nullptr;
    toggleConsoleBtn = nullptr;
    consoleCopyBtn = nullptr;
    consoleSaveBtn = nullptr;
    consoleAutoScrollBox = nullptr;
    consoleFilterEdit = nullptr;
    consoleCloseBtn = nullptr;
    consoleDrawerVisible = true;

    connectStatusBadge = nullptr;
    btnBrowseClient = nullptr;
    btnAutoDetectClient = nullptr;
    quickStopTopBtn = nullptr;
    quickPullEmvBtn = nullptr;

    hwTab = nullptr;
    lfVoltageLabel = nullptr;
    lfStatusBadge = nullptr;
    hfVoltageLabel = nullptr;
    hfStatusBadge = nullptr;
    hwTuneGroupBox = nullptr;
    hwDiagGroupBox = nullptr;
    hwCardGroupBox = nullptr;

    aiAskBtn = nullptr;
    aiExplainBtn = nullptr;
    genai = new GenAICopilot(this);

    myInfo = new QAction("wh201906", this);
    currVersion = new QAction(tr("Ver: ") + QApplication::applicationVersion().section('.', 0, -2), this);
    checkUpdate = new QAction(tr("Check Update"), this);
    connect(myInfo, &QAction::triggered, [ = ]()
    {
        QDesktopServices::openUrl(QUrl("https://github.com/wh201906"));
    });
    connect(checkUpdate, &QAction::triggered, [ = ]()
    {
        QDesktopServices::openUrl(QUrl("https://github.com/wh201906/Proxmark3GUI/releases"));
    });

    QString iniPath = QFile::exists("/home/kali/Proxmark3GUI/GUIsettings.ini")
                      ? "/home/kali/Proxmark3GUI/GUIsettings.ini"
                      : (QCoreApplication::applicationDirPath() + "/GUIsettings.ini");
    settings = new QSettings(iniPath, QSettings::IniFormat);
    settings->setIniCodec("UTF-8");
    genai->loadSettings(settings);
    connect(genai, &GenAICopilot::responseReady, this, &MainWindow::onAiResponseReady);
    connect(genai, &GenAICopilot::thinking, this, &MainWindow::onAiThinking);

    pm3Thread = new QThread(this);
    connect(QApplication::instance(), &QApplication::aboutToQuit, pm3Thread, &QThread::quit);
    pm3 = new PM3Process(pm3Thread);
    connect(pm3Thread, &QThread::finished, pm3, &PM3Process::deleteLater);
    pm3Thread->start();
    pm3state = false;
    clientWorkingDir = new QDir;

    util = new Util(this);
    Util::setUI(ui);
    Util::onGotoRawTab = [this]() {
        this->showConsoleDrawer();
    };

    mifare = new Mifare(ui, util, this);
    lf = new LF(ui, util, this);
    t55xxTab = new T55xxTab(util);
    connect(lf, &LF::LFfreqConfChanged, this, &MainWindow::onLFfreqConfChanged);
    connect(t55xxTab, &T55xxTab::setParentGUIState, this, &MainWindow::setState);

    int oldT55xxIdx = ui->funcTab->indexOf(ui->t55xxTab);
    if (oldT55xxIdx != -1) {
        ui->funcTab->removeTab(oldT55xxIdx);
    }

    emvTab = new EMVTab(util, this);
    ui->funcTab->insertTab(0, emvTab, tr("EMV Smartcard"));
    ui->funcTab->insertTab(3, t55xxTab, tr("T55xx"));

    keyEventFilter = new MyEventFilter(QEvent::KeyPress);
    resizeEventFilter = new MyEventFilter(QEvent::Resize);

    setupTopToolbar();
    setupConsoleDrawer();
    setupHardwareTab();

    portSearchTimer = new QTimer(this);
    portSearchTimer->setInterval(2000);
    connect(portSearchTimer, &QTimer::timeout, this, &MainWindow::on_portSearchTimer_timeout);
    portSearchTimer->start();

    contextMenu = new QMenu();
    QAction* toggleConsoleAct = new QAction(tr("Toggle Console (Ctrl+`)"), this);
    connect(toggleConsoleAct, &QAction::triggered, this, &MainWindow::toggleConsoleDrawer);
    contextMenu->addAction(toggleConsoleAct);
    contextMenu->addSeparator();
    contextMenu->addAction(myInfo);
    currVersion->setEnabled(false);
    contextMenu->addAction(currVersion);
    contextMenu->addAction(checkUpdate);
}

MainWindow::~MainWindow()
{
    emit killPM3();
    if(pm3Thread)
    {
        pm3Thread->quit();
        pm3Thread->wait(2000);
    }
    delete ui;
}

void MainWindow::loadConfig()
{
    QString filename = ui->Set_Client_configFileBox->currentData().toString();
    if(filename == "(ext)")
        filename = ui->Set_Client_configPathEdit->text();
    qDebug() << "config file:" << filename;
    QFile configList(filename);
    if(!configList.open(QFile::ReadOnly | QFile::Text))
    {
        QMessageBox::information(this, tr("Info"), tr("Failed to load config file"));
        return;
    }

    QByteArray configData = configList.readAll();
    QJsonDocument configJson(QJsonDocument::fromJson(configData));
    mifare->setConfigMap(configJson.object()["mifare classic"].toObject().toVariantMap());
    lf->setConfigMap(configJson.object()["lf"].toObject().toVariantMap());
    t55xxTab->setConfigMap(configJson.object()["t55xx"].toObject().toVariantMap());
}

void MainWindow::initUI() // will be called by main.app
{
    ui->retranslateUi(this);
    uiInit();
    signalInit();
    setState(false);
    dockInit();
    setupGenAISettings();
    ui->funcTab->setCurrentIndex(0);
}

// ******************** basic functions ********************

void MainWindow::on_portSearchTimer_timeout()
{
    QStringList newPortList; // for actural port name
    QStringList newPortNameList; // for display name
    const QString hint = " *";

    foreach(const QSerialPortInfo &info, QSerialPortInfo::availablePorts())
    {
//        qDebug() << info.isNull() << info.portName() << info.description() << info.serialNumber() << info.manufacturer();
        if(!info.isNull())
        {
            QString idString = (info.description() + info.serialNumber() + info.manufacturer()).toLower();
            QString portName = info.portName();

            newPortList << portName;
            if(info.hasVendorIdentifier() && info.hasProductIdentifier())
            {
                quint16 vid = info.vendorIdentifier();
                quint16 pid = info.productIdentifier();
                if(vid == 0x9AC4 && pid == 0x4B8F)
                    portName += hint;
                else if(vid == 0x2D2D && pid == 0x504D)
                    portName += hint;
            }
            else if(idString.contains("proxmark") || idString.contains("iceman"))
                portName += hint;
            newPortNameList << portName;
        }
    }
    if(newPortList != portList) // update PM3_portBox when available ports changed
    {
        portList = newPortList;
        ui->PM3_portBox->clear();
        int selectId = -1;
        for(int i = 0; i < portList.size(); i++)
        {
            ui->PM3_portBox->addItem(newPortNameList[i], newPortList[i]);
            if(selectId == -1 && newPortNameList[i].endsWith(hint))
                selectId = i;
        }
        if(selectId != -1)
            ui->PM3_portBox->setCurrentIndex(selectId);
    }
}

void MainWindow::on_PM3_connectButton_clicked()
{
    qDebug() << "Main:" << QThread::currentThread();

    const QComboBox* portBox = ui->PM3_portBox;
    QString port;
    if(portBox->currentText() == portBox->itemText(portBox->currentIndex()))
        // in the list
        port = portBox->currentData().toString();
    else
        // not in the list
        port = portBox->currentText();
    qDebug() << "port:" << port;
    QString startArgs = ui->Set_Client_startArgsEdit->text();
    QString clientPath = ui->PM3_pathBox->currentText();
    QFileInfo clientFile(clientPath);
    bool clientExist = false;

    QStringList extList = {""};
#ifdef Q_OS_WIN
    if(clientFile.suffix().isEmpty())
    {
        QString pathExt = QProcessEnvironment::systemEnvironment().value("pathext");
        extList += pathExt.split(";", Qt::SkipEmptyParts);
        if(extList.size() == 1)
            extList += ".exe";
    }
#endif
    for(const QString& ext : extList)
    {
        QFileInfo executable(clientFile.filePath() + ext);
        if(executable.isFile())
        {
            clientExist = true;
            break;
        }
    }

    if(!clientExist)
    {
        QMessageBox::information(this, tr("Info"), tr("The client path is invalid"), QMessageBox::Ok);
        return;
    }

    // on RRG repo, if no port is specified, the client will search the available port
    if(port == "" && startArgs.contains("<port>")) // has <port>, no port
    {
        QMessageBox::information(this, tr("Info"), tr("Plz choose a port first"), QMessageBox::Ok);
        return;
    }

    if(!startArgs.contains("<port>")) // no <port>
        port = ""; // a symbol

    QString fullPort = port;
#ifndef Q_OS_WIN
    if (!fullPort.isEmpty() && !fullPort.startsWith("/dev/") && !startArgs.contains("/dev/<port>")) {
        fullPort = "/dev/" + fullPort;
    }
#endif

    QStringList args = startArgs.replace("<port>", fullPort).split(' ');
    addClientPath(clientPath);

    QProcess envSetProcess;
    QString envScriptPath = ui->Set_Client_envScriptEdit->text();
    if(envScriptPath.contains("<client dir>"))
        envScriptPath.replace("<client dir>", clientFile.absoluteDir().absolutePath());

    QFileInfo envScript(envScriptPath);
    if(envScript.exists())
    {
        qDebug() << envScript.absoluteFilePath();
        // use the shell session to keep the environment then read it
#ifdef Q_OS_WIN
        // cmd /c "<path>">>nul && set
        envSetProcess.start("cmd", {}, QProcess::Unbuffered | QProcess::ReadWrite | QProcess::Text);
        envSetProcess.write(QString("\"" + envScript.absoluteFilePath() + "\">>nul\n").toLatin1());
        envSetProcess.waitForReadyRead(10000);
        envSetProcess.readAll();
        envSetProcess.write("set\n");
#else
        // need implementation(or test if space works)
        // sh -c '. "<path>">>/dev/null && env'
        envSetProcess.start("sh", QStringList() << "-c" << (". \"" + envScript.absoluteFilePath() + "\" >/dev/null 2>&1 && env"));
#endif
        envSetProcess.waitForReadyRead(10000);
        QString envSetResult = QString(envSetProcess.readAll());
#if (QT_VERSION <= QT_VERSION_CHECK(5,14,0))
        clientEnv = envSetResult.split("\n", QString::SkipEmptyParts);
#else
        clientEnv = envSetResult.split("\n", Qt::SkipEmptyParts);
#endif
        if(clientEnv.size() > 2) // the first element is "set" and the last element is the current path
        {
            clientEnv.removeFirst();
            clientEnv.removeLast();
            emit setProcEnv(&clientEnv);
        }
//      qDebug() << "Get Env List" << clientEnv;
    }
    else
        clientEnv.clear();

    clientWorkingDir->setPath(QApplication::applicationDirPath());
    qDebug() << clientWorkingDir->absolutePath();
    clientWorkingDir->mkpath(ui->Set_Client_workingDirEdit->text());
    qDebug() << clientWorkingDir->absolutePath();
    clientWorkingDir->cd(ui->Set_Client_workingDirEdit->text());
    qDebug() << clientWorkingDir->absolutePath();
    emit setWorkingDir(clientWorkingDir->absolutePath());

    loadConfig();
    emit connectPM3(clientPath, args);
    if(port != "" && !keepClientActive)
        emit setSerialListener(port, true);
    else if(!keepClientActive)
        emit setSerialListener(false);

    envSetProcess.kill();
}

void MainWindow::onPM3ErrorOccurred(QProcess::ProcessError error)
{
    qDebug() << "PM3 Error:" << error << pm3->errorString();
    if(error == QProcess::FailedToStart)
        QMessageBox::information(this, tr("Info"), tr("Failed to start the client") + "\n" + pm3->errorString());
}

void MainWindow::onPM3HWConnectFailed()
{
    QMessageBox::information(this, tr("Info"), tr("Failed to connect to the hardware"));
}

void MainWindow::onPM3StateChanged(bool st, const QString& info)
{
    pm3state = st;
    setState(st);
    updateConnectionBadge(st, info);
    if(st == true)
    {
        portSearchTimer->stop();
        setStatusBar(PM3VersionBar, info);
        setStatusBar(connectStatusBar, tr("Connected"));
        if (quickStopTopBtn) quickStopTopBtn->setEnabled(true);
        if (quickPullEmvBtn) quickPullEmvBtn->setEnabled(true);
        if (emvTab) emvTab->onPM3Connected();
    }
    else
    {
        portSearchTimer->start();
        setStatusBar(PM3VersionBar, "");
        setStatusBar(connectStatusBar, tr("Not Connected"));
        if (quickStopTopBtn) quickStopTopBtn->setEnabled(false);
        if (quickPullEmvBtn) quickPullEmvBtn->setEnabled(false);
    }
}

void MainWindow::on_PM3_disconnectButton_clicked()
{
    emit killPM3();
    emit setSerialListener(false);
}

void MainWindow::refreshOutput(const QString& output)
{
    static QRegularExpression lfTuneRegex("LF antenna:\\s*([0-9.]+)\\s*V(?:\\s*@\\s*([0-9.]+)\\s*kHz)?", QRegularExpression::CaseInsensitiveOption);
    static QRegularExpression hfTuneRegex("HF antenna:\\s*([0-9.]+)\\s*V(?:\\s*@\\s*([0-9.]+)\\s*MHz)?", QRegularExpression::CaseInsensitiveOption);

    QRegularExpressionMatch lfMatch = lfTuneRegex.match(output);
    if (lfMatch.hasMatch() && lfVoltageLabel != nullptr) {
        QString volt = lfMatch.captured(1);
        QString freq = lfMatch.captured(2);
        double v = volt.toDouble();
        lfVoltageLabel->setText(QString("<b style='font-size: 15pt; color: %1;'>%2 V</b> %3")
            .arg(v >= 20.0 ? "#00e676" : (v >= 10.0 ? "#ffb74d" : "#ff5252"))
            .arg(volt)
            .arg(freq.isEmpty() ? "@ 125 kHz" : "@ " + freq + " kHz"));
        lfStatusBadge->setText(v >= 20.0 ? tr("● Optimal Resonance") : (v >= 10.0 ? tr("● Weak Resonance") : tr("● Very Low / Detuned")));
        lfStatusBadge->setStyleSheet(v >= 20.0 ? "color: #00e676; font-weight: bold;" : (v >= 10.0 ? "color: #ffb74d; font-weight: bold;" : "color: #ff5252; font-weight: bold;"));
    }

    QRegularExpressionMatch hfMatch = hfTuneRegex.match(output);
    if (hfMatch.hasMatch() && hfVoltageLabel != nullptr) {
        QString volt = hfMatch.captured(1);
        QString freq = hfMatch.captured(2);
        double v = volt.toDouble();
        hfVoltageLabel->setText(QString("<b style='font-size: 15pt; color: %1;'>%2 V</b> %3")
            .arg(v >= 15.0 ? "#00e676" : (v >= 8.0 ? "#ffb74d" : "#ff5252"))
            .arg(volt)
            .arg(freq.isEmpty() ? "@ 13.56 MHz" : "@ " + freq + " MHz"));
        hfStatusBadge->setText(v >= 15.0 ? tr("● Optimal Resonance") : (v >= 8.0 ? tr("● Weak Resonance") : tr("● Very Low / Detuned")));
        hfStatusBadge->setStyleSheet(v >= 15.0 ? "color: #00e676; font-weight: bold;" : (v >= 8.0 ? "color: #ffb74d; font-weight: bold;" : "color: #ff5252; font-weight: bold;"));
    }

    outputBuffer.append(output);
    int lastNewline = outputBuffer.lastIndexOf('\n');
    if (lastNewline == -1) {
        if (outputBuffer.length() < 256) return;
        lastNewline = outputBuffer.length() - 1;
    }

    QString toProcess = outputBuffer.left(lastNewline + 1);
    outputBuffer = outputBuffer.mid(lastNewline + 1);

    static QRegularExpression ansiRegex("\x1B\\[[0-9;]*[a-zA-Z]");
    QStringList lines = toProcess.split('\n');

    QTextCursor cursor = ui->Raw_outputEdit->textCursor();
    cursor.movePosition(QTextCursor::End);

    for (int i = 0; i < lines.size(); ++i) {
        QString line = lines[i];
        if (i == lines.size() - 1 && line.isEmpty()) break;

        line.remove(ansiRegex);

        QTextCharFormat fmt;
        fmt.setFontFamily(ui->Raw_outputEdit->font().family());
        fmt.setFontPointSize(ui->Raw_outputEdit->font().pointSize());

        QString trimmed = line.trimmed();
        if (trimmed.startsWith("[+]")) {
            fmt.setForeground(QColor("#00E676"));
            fmt.setFontWeight(QFont::Bold);
        } else if (trimmed.startsWith("[!]")) {
            fmt.setForeground(QColor("#FF5252"));
            fmt.setFontWeight(QFont::Bold);
        } else if (trimmed.startsWith("[-]")) {
            fmt.setForeground(QColor("#FFB74D"));
            fmt.setFontWeight(QFont::DemiBold);
        } else if (trimmed.startsWith("[?]")) {
            fmt.setForeground(QColor("#40C4FF"));
            fmt.setFontWeight(QFont::DemiBold);
        } else if (trimmed.startsWith("[=]")) {
            fmt.setForeground(QColor("#80D8FF"));
            fmt.setFontWeight(QFont::Bold);
        } else if (trimmed.startsWith("[🤖 GenAI Copilot]") || trimmed.startsWith("[🤖")) {
            fmt.setForeground(QColor("#E040FB"));
            fmt.setFontWeight(QFont::Bold);
        } else if (trimmed.startsWith("[💡 Suggested Command]") || trimmed.startsWith("[💡")) {
            fmt.setForeground(QColor("#00E5FF"));
            fmt.setFontWeight(QFont::Bold);
        } else if (trimmed.startsWith("###")) {
            fmt.setForeground(QColor("#FFD54F"));
            fmt.setFontWeight(QFont::Bold);
        } else if (trimmed.startsWith("#db#")) {
            fmt.setForeground(QColor("#78909C"));
        } else if (trimmed.startsWith("pm3 -->") || trimmed.contains("pm3 -->")) {
            fmt.setForeground(QColor("#64FFDA"));
            fmt.setFontWeight(QFont::Bold);
        } else {
            fmt.setForeground(QColor("#ECEFF1"));
        }

        cursor.insertText(line + "\n", fmt);
    }

    if (consoleAutoScrollBox == nullptr || consoleAutoScrollBox->isChecked()) {
        ui->Raw_outputEdit->verticalScrollBar()->setValue(
            ui->Raw_outputEdit->verticalScrollBar()->maximum()
        );
    }
}

void MainWindow::on_stopButton_clicked()
{
    if(!pm3state)
        on_PM3_disconnectButton_clicked();
    else
    {
        on_PM3_disconnectButton_clicked();
        for(int i = 0; i < 10; i++)
        {
            util->delay(200);
            if(!pm3state)
                break;
        }
        emit reconnectPM3();
        emit setSerialListener(!keepClientActive);
    }
}
// *********************************************************

// ******************** raw command ********************

void MainWindow::on_Raw_CMDEdit_textChanged(const QString &arg1)
{
    stashedCMDEditText = arg1;
}

void MainWindow::on_Raw_sendCMDButton_clicked()
{
    QString cmd = ui->Raw_CMDEdit->text().trimmed();
    if(cmd.startsWith("?") || cmd.startsWith("ai ", Qt::CaseInsensitive) || cmd.startsWith("ai:", Qt::CaseInsensitive) || cmd.startsWith("genai ", Qt::CaseInsensitive))
    {
        QString query = cmd;
        if(query.startsWith("?")) query = query.mid(1).trimmed();
        else if(query.startsWith("ai ", Qt::CaseInsensitive)) query = query.mid(3).trimmed();
        else if(query.startsWith("ai:", Qt::CaseInsensitive)) query = query.mid(3).trimmed();
        else if(query.startsWith("genai ", Qt::CaseInsensitive)) query = query.mid(6).trimmed();

        refreshCMD(cmd);
        ui->Raw_CMDEdit->clear();

        QString promptDisplay = QString("\n[🤖 GenAI Copilot] %1\n").arg(query);
        refreshOutput(promptDisplay);

        QString context = ui->Raw_outputEdit->toPlainText().right(2000);
        genai->ask(query, context);
        return;
    }

    util->execCMD(ui->Raw_CMDEdit->text());
    refreshCMD(ui->Raw_CMDEdit->text());
}

void MainWindow::on_Raw_clearOutputButton_clicked()
{
    ui->Raw_outputEdit->clear();
}

void MainWindow::on_Raw_CMDHistoryBox_stateChanged(int arg1)
{
    if(arg1 == Qt::Checked)
    {
        ui->Raw_CMDHistoryWidget->setVisible(true);
        ui->Raw_clearHistoryButton->setVisible(true);
        ui->Raw_CMDHistoryBox->setText(tr("History:"));
    }
    else
    {
        ui->Raw_CMDHistoryWidget->setVisible(false);
        ui->Raw_clearHistoryButton->setVisible(false);
        ui->Raw_CMDHistoryBox->setText("");
    }
}

void MainWindow::on_Raw_clearHistoryButton_clicked()
{
    ui->Raw_CMDHistoryWidget->clear();
}

void MainWindow::on_Raw_CMDHistoryWidget_itemDoubleClicked(QListWidgetItem *item)
{
    ui->Raw_CMDEdit->setText(item->text());
    ui->Raw_CMDEdit->setFocus();
}

void MainWindow::sendMSG() // send command when pressing Enter
{
    if(ui->Raw_CMDEdit->hasFocus())
        on_Raw_sendCMDButton_clicked();
}


void MainWindow::refreshCMD(const QString& cmd)
{
    ui->Raw_CMDEdit->blockSignals(true);
    ui->Raw_CMDEdit->setText(cmd);
    if(cmd != "" && (ui->Raw_CMDHistoryWidget->count() == 0 || ui->Raw_CMDHistoryWidget->item(ui->Raw_CMDHistoryWidget->count() - 1)->text() != cmd))
        ui->Raw_CMDHistoryWidget->addItem(cmd);
    stashedCMDEditText = cmd;
    stashedIndex = -1;
    ui->Raw_CMDEdit->blockSignals(false);
}

void MainWindow::on_Raw_keyPressed(QObject* obj_addr, QEvent& event)
{
    if(event.type() == QEvent::KeyPress)
    {
        QKeyEvent& keyEvent = static_cast<QKeyEvent&>(event);
        if(obj_addr == ui->Raw_CMDEdit)
        {
            if(keyEvent.key() == Qt::Key_Up)
            {
                if(stashedIndex > 0)
                    stashedIndex--;
                else if(stashedIndex == -1)
                    stashedIndex = ui->Raw_CMDHistoryWidget->count() - 1;
            }
            else if(keyEvent.key() == Qt::Key_Down)
            {
                if(stashedIndex < ui->Raw_CMDHistoryWidget->count() - 1 && stashedIndex != -1)
                    stashedIndex++;
                else if(stashedIndex == ui->Raw_CMDHistoryWidget->count() - 1)
                    stashedIndex = -1;
            }
            if(keyEvent.key() == Qt::Key_Up || keyEvent.key() == Qt::Key_Down)
            {
                ui->Raw_CMDEdit->blockSignals(true);
                if(stashedIndex == -1)
                    ui->Raw_CMDEdit->setText(stashedCMDEditText);
                else
                    ui->Raw_CMDEdit->setText(ui->Raw_CMDHistoryWidget->item(stashedIndex)->text());
                ui->Raw_CMDEdit->blockSignals(false);
            }
        }
        else if(obj_addr == ui->Raw_outputEdit)
        {
            if(keyEvent.key() == Qt::Key_Up || keyEvent.key() == Qt::Key_Down)
                ui->Raw_CMDEdit->setFocus();
        }
    }
}
// *****************************************************

// ******************** mifare ********************
void MainWindow::on_MF_keyWidget_resized(QObject* obj_addr, QEvent& event)
{
    if(obj_addr == ui->MF_keyWidget && event.type() == QEvent::Resize)
    {
        QTableWidget* widget = (QTableWidget*)obj_addr;
        int keyItemWidth = widget->width();
        keyItemWidth -= widget->verticalScrollBar()->width();
        keyItemWidth -= 2 * widget->frameWidth();
        keyItemWidth -= widget->horizontalHeader()->sectionSize(0);
        widget->horizontalHeader()->resizeSection(1, keyItemWidth / 2);
        widget->horizontalHeader()->resizeSection(2, keyItemWidth / 2);
    }
}

void MainWindow::MF_onMFCardTypeChanged(int id, bool st)
{
    MFCardTypeBtnGroup->blockSignals(true);
    qDebug() << id << MFCardTypeBtnGroup->checkedId();
    if(!st)
    {
        int result;
        if(id > MFCardTypeBtnGroup->checkedId()) // id is specified in uiInit() with a proper order, so I can compare the size by id.
        {
            result = QMessageBox::question(this, tr("Info"), tr("Some of the data and key will be cleared.") + "\n" + tr("Continue?"), QMessageBox::Yes | QMessageBox::No);
        }
        else
        {
            result = QMessageBox::Yes;
        }
        if(result == QMessageBox::Yes)
        {
            qDebug() << "Yes";
            mifare->setCardType(MFCardTypeBtnGroup->checkedId());
            MF_widgetReset();
            mifare->data_syncWithDataWidget();
            mifare->data_syncWithKeyWidget();
        }
        else
        {
            qDebug() << "No";
            MFCardTypeBtnGroup->button(id)->setChecked(true);
        }
    }
    MFCardTypeBtnGroup->blockSignals(false);
}

void MainWindow::on_MF_selectAllBox_stateChanged(int arg1)
{
    ui->MF_dataWidget->blockSignals(true);
    ui->MF_selectAllBox->blockSignals(true);
    ui->MF_selectTrailerBox->blockSignals(true);
    if(arg1 == Qt::PartiallyChecked)
    {
        ui->MF_selectAllBox->setTristate(false);
        ui->MF_selectAllBox->setCheckState(Qt::Checked);
    }
    for(int i = 0; i < mifare->cardType.block_size; i++)
    {
        ui->MF_dataWidget->item(i, 1)->setCheckState(ui->MF_selectAllBox->checkState());
    }
    for(int i = 0; i < mifare->cardType.sector_size; i++)
    {
        ui->MF_dataWidget->item(mifare->cardType.blks[i], 0)->setCheckState(ui->MF_selectAllBox->checkState());
    }
    ui->MF_selectTrailerBox->setCheckState(ui->MF_selectAllBox->checkState());
    ui->MF_dataWidget->blockSignals(false);
    ui->MF_selectAllBox->blockSignals(false);
    ui->MF_selectTrailerBox->blockSignals(false);
}


void MainWindow::on_MF_selectTrailerBox_stateChanged(int arg1)
{
    int selectedSubBlocks = 0;

    ui->MF_dataWidget->blockSignals(true);
    ui->MF_selectAllBox->blockSignals(true);
    ui->MF_selectTrailerBox->blockSignals(true);
    if(arg1 == Qt::PartiallyChecked)
    {
        ui->MF_selectTrailerBox->setTristate(false);
        ui->MF_selectTrailerBox->setCheckState(Qt::Checked);
    }
    for(int i = 0; i < mifare->cardType.sector_size; i++)
    {
        ui->MF_dataWidget->item(mifare->cardType.blks[i] + mifare->cardType.blk[i] - 1, 1)->setCheckState(ui->MF_selectTrailerBox->checkState());
        selectedSubBlocks = 0;
        for(int j = 0; j < mifare->cardType.blk[i]; j++)
        {
            if(ui->MF_dataWidget->item(j + mifare->cardType.blks[i], 1)->checkState() == Qt::Checked)
                selectedSubBlocks++;
        }
        if(selectedSubBlocks == 0)
        {
            ui->MF_dataWidget->item(mifare->cardType.blks[i], 0)->setCheckState(Qt::Unchecked);
        }
        else if(selectedSubBlocks == mifare->cardType.blk[i])
        {
            ui->MF_dataWidget->item(mifare->cardType.blks[i], 0)->setCheckState(Qt::Checked);
        }
        else
        {
            ui->MF_dataWidget->item(mifare->cardType.blks[i], 0)->setCheckState(Qt::PartiallyChecked);
        }
    }

    ui->MF_dataWidget->blockSignals(false);
    ui->MF_selectAllBox->blockSignals(false);
    ui->MF_selectTrailerBox->blockSignals(false);
}


void MainWindow::on_MF_data2KeyButton_clicked()
{
    mifare->data_data2Key();
}

void MainWindow::on_MF_key2DataButton_clicked()
{
    mifare->data_key2Data();
}

void MainWindow::on_MF_fillKeysButton_clicked()
{
    mifare->data_fillKeys();
}

void MainWindow::on_MF_trailerDecoderButton_clicked()
{
    decDialog = new MF_trailerDecoderDialog(this);
    decDialog->show();
}

void MainWindow::on_MF_dataWidget_itemChanged(QTableWidgetItem *item)
{
    ui->MF_dataWidget->blockSignals(true);
    ui->MF_selectAllBox->blockSignals(true);
    ui->MF_selectTrailerBox->blockSignals(true);
    if(item->column() == 0)
    {
        int selectedSectors = 0;
        for(int i = 0; i < mifare->cardType.blk[Mifare::data_b2s(item->row())]; i++)
        {
            ui->MF_dataWidget->item(i + item->row(), 1)->setCheckState(item->checkState());
            qDebug() << i << mifare->cardType.blk[item->row()] << i + item->row() << ui->MF_dataWidget->item(i + item->row(), 1)->text();
        }
        for(int i = 0; i < mifare->cardType.sector_size; i++)
        {
            if(ui->MF_dataWidget->item(mifare->cardType.blks[i], 0)->checkState() == Qt::Checked)
            {
                selectedSectors++;
            }
        }
        if(selectedSectors == 0)
        {
            ui->MF_selectAllBox->setCheckState(Qt::Unchecked);
            ui->MF_selectTrailerBox->setCheckState(Qt::Unchecked);
        }
        else if(selectedSectors == mifare->cardType.sector_size)
        {
            ui->MF_selectAllBox->setCheckState(Qt::Checked);
            ui->MF_selectTrailerBox->setCheckState(Qt::Checked);
        }
        else
        {
            ui->MF_selectAllBox->setCheckState(Qt::PartiallyChecked);
            ui->MF_selectTrailerBox->setCheckState(Qt::PartiallyChecked);
        }
    }
    else if(item->column() == 1)
    {
        int selectedSubBlocks = 0;
        int selectedBlocks = 0;
        int selectedTrailers = 0;

        for(int i = 0; i < mifare->cardType.block_size; i++)
        {
            if(ui->MF_dataWidget->item(i, 1)->checkState() == Qt::Checked)
                selectedBlocks++;
        }
        for(int i = 0; i < mifare->cardType.blk[Mifare::data_b2s(item->row())]; i++)
        {
            if(ui->MF_dataWidget->item(i + mifare->cardType.blks[Mifare::data_b2s(item->row())], 1)->checkState() == Qt::Checked)
                selectedSubBlocks++;
        }
        for(int i = 0; i < mifare->cardType.sector_size; i++)
        {
            int targetBlock = mifare->cardType.blks[i] + mifare->cardType.blk[i] - 1;
            if(ui->MF_dataWidget->item(targetBlock, 1)->checkState() == Qt::Checked)
                selectedTrailers++;
        }
        if(selectedBlocks == 0)
        {
            ui->MF_selectAllBox->setCheckState(Qt::Unchecked);
        }
        else if(selectedBlocks == mifare->cardType.block_size)
        {
            ui->MF_selectAllBox->setCheckState(Qt::Checked);
        }
        else
        {
            ui->MF_selectAllBox->setCheckState(Qt::PartiallyChecked);
        }
        if(selectedSubBlocks == 0)
        {
            ui->MF_dataWidget->item(mifare->cardType.blks[Mifare::data_b2s(item->row())], 0)->setCheckState(Qt::Unchecked);
        }
        else if(selectedSubBlocks == mifare->cardType.blk[Mifare::data_b2s(item->row())])
        {
            ui->MF_dataWidget->item(mifare->cardType.blks[Mifare::data_b2s(item->row())], 0)->setCheckState(Qt::Checked);
        }
        else
        {
            ui->MF_dataWidget->item(mifare->cardType.blks[Mifare::data_b2s(item->row())], 0)->setCheckState(Qt::PartiallyChecked);
        }
        if(selectedTrailers == 0)
        {
            ui->MF_selectTrailerBox->setCheckState(Qt::Unchecked);
        }
        else if(selectedTrailers == mifare->cardType.sector_size)
        {
            ui->MF_selectTrailerBox->setCheckState(Qt::Checked);
        }
        else
        {
            ui->MF_selectTrailerBox->setCheckState(Qt::PartiallyChecked);
        }
    }
    else if(item->column() == 2)
    {
        QString data = item->text().remove(" ").toUpper();
        if(data == "" || mifare->data_isDataValid(data) == Mifare::DATA_NOSPACE)
        {
            mifare->data_setData(item->row(), data);
        }
        else
        {
            QMessageBox::information(this, tr("Info"), tr("Data must consists of 32 Hex symbols(Whitespace is allowed)"));
        }
        mifare->data_syncWithDataWidget(false, item->row());
    }
    ui->MF_dataWidget->blockSignals(false);
    ui->MF_selectAllBox->blockSignals(false);
    ui->MF_selectTrailerBox->blockSignals(false);
}

void MainWindow::on_MF_keyWidget_itemChanged(QTableWidgetItem *item)
{
    if(item->column() == 1)
    {
        QString key = item->text().remove(" ").toUpper();
        if(key == "" || mifare->data_isKeyValid(key))
        {
            mifare->data_setKey(item->row(), Mifare::KEY_A, key);
        }
        else
        {
            QMessageBox::information(this, tr("Info"), tr("Key must consists of 12 Hex symbols(Whitespace is allowed)"));
        }
        mifare->data_syncWithKeyWidget(false, item->row(), Mifare::KEY_A);
    }
    else if(item->column() == 2)
    {
        QString key = item->text().remove(" ").toUpper();
        if(key == "" || mifare->data_isKeyValid(key))
        {
            mifare->data_setKey(item->row(), Mifare::KEY_B, key);
        }
        else
        {
            QMessageBox::information(this, tr("Info"), tr("Key must consists of 12 Hex symbols(Whitespace is allowed)"));
        }
        mifare->data_syncWithKeyWidget(false, item->row(), Mifare::KEY_B);
    }
}

void MainWindow::on_MF_File_loadButton_clicked()
{
    QString title = "";
    QString filename = "";
    if(ui->MF_File_dataButton->isChecked())
    {
        title = tr("Plz select the data file:");
        filename = QFileDialog::getOpenFileName(this, title, "./", tr("Binary Data Files(*.bin *.dump)") + ";;" + tr("Text Data Files(*.txt *.eml)") + ";;" + tr("All Files(*.*)"));
        qDebug() << filename;
        if(filename != "")
        {
            if(!mifare->data_loadDataFile(filename))
            {
                QMessageBox::information(this, tr("Info"), tr("Failed to open") + "\n" + filename);
            }
        }
    }
    else if(ui->MF_File_keyButton->isChecked())
    {
        title = tr("Plz select the key file:");
        filename = QFileDialog::getOpenFileName(this, title, "./", tr("Binary Key Files(*.bin *.dump)") + ";;" + tr("All Files(*.*)"));
        qDebug() << filename;
        if(filename != "")
        {
            if(!mifare->data_loadKeyFile(filename))
            {
                QMessageBox::information(this, tr("Info"), tr("Failed to open") + "\n" + filename);
            }
        }
    }

}

void MainWindow::on_MF_File_saveButton_clicked()
{

    QString title = "";
    QString filename = "";
    QString selectedType = "";
    QString defaultName = mifare->data_getUID();
    if(defaultName != "")
        defaultName += "_";
    defaultName += QDateTime::currentDateTime().toString("yyyy-MM-dd-hh-mm-ss");

    if(ui->MF_File_dataButton->isChecked())
    {
        title = tr("Plz select the location to save data file:");
        filename = QFileDialog::getSaveFileName(this, title, "./data_" + defaultName, tr("Binary Data Files(*.bin *.dump)") + ";;" + tr("Text Data Files(*.txt *.eml)"), &selectedType);
        qDebug() << filename;
        if(filename != "")
        {
            if(!mifare->data_saveDataFile(filename, selectedType == tr("Binary Data Files(*.bin *.dump)")))
            {
                QMessageBox::information(this, tr("Info"), tr("Failed to save to") + "\n" + filename);
            }
        }
    }
    else if(ui->MF_File_keyButton->isChecked())
    {
        title = tr("Plz select the location to save key file:");
        filename = QFileDialog::getSaveFileName(this, title, "./key_" + defaultName, tr("Binary Key Files(*.bin *.dump)"), &selectedType);
        qDebug() << filename;
        if(filename != "")
        {
            if(!mifare->data_saveKeyFile(filename, selectedType == tr("Binary Key Files(*.bin *.dump)")))
            {
                QMessageBox::information(this, tr("Info"), tr("Failed to save to") + "\n" + filename);
            }
        }
    }
    qDebug() << filename << selectedType;
}

void MainWindow::on_MF_File_clearButton_clicked()
{
    if(ui->MF_File_keyButton->isChecked())
    {
        mifare->data_clearKey();
        mifare->data_syncWithKeyWidget();
    }
    else if(ui->MF_File_dataButton->isChecked())
    {
        mifare->data_clearData();
        mifare->data_syncWithDataWidget();
    }
}

void MainWindow::on_MF_Attack_infoButton_clicked()
{
    mifare->info();
}

void MainWindow::on_MF_Attack_chkButton_clicked()
{
    setState(false);
    mifare->chk();
    setState(true);
}

void MainWindow::on_MF_Attack_nestedButton_clicked()
{
    setState(false);
    mifare->nested();
    setState(true);
}

void MainWindow::on_MF_Attack_hardnestedButton_clicked()
{
    mifare->hardnested();
}

void MainWindow::on_MF_RW_readSelectedButton_clicked()
{
    setState(false);
    mifare->readSelected(Mifare::TARGET_MIFARE);
    setState(true);
}

void MainWindow::on_MF_RW_readBlockButton_clicked()
{
    setState(false);
    mifare->readOne(Mifare::TARGET_MIFARE);
    setState(true);
}

void MainWindow::on_MF_RW_writeBlockButton_clicked()
{
    setState(false);
    mifare->writeOne();
    setState(true);
}

void MainWindow::on_MF_RW_writeSelectedButton_clicked()
{
    setState(false);
    mifare->writeSelected(Mifare::TARGET_MIFARE);
    setState(true);
}

void MainWindow::on_MF_RW_dumpButton_clicked()
{
    mifare->dump();
}

void MainWindow::on_MF_RW_restoreButton_clicked()
{
    mifare->restore();
}

void MainWindow::on_MF_UID_readSelectedButton_clicked()
{
    setState(false);
    mifare->readSelected(Mifare::TARGET_UID);
    setState(true);
}

void MainWindow::on_MF_UID_readBlockButton_clicked()
{
    setState(false);
    mifare->readOne(Mifare::TARGET_UID);
    setState(true);
}

void MainWindow::on_MF_UID_writeSelectedButton_clicked()
{
    setState(false);
    mifare->writeSelected(Mifare::TARGET_UID);
    setState(true);
}

void MainWindow::on_MF_UID_writeBlockButton_clicked()
{
    setState(false);
    mifare->writeOne(Mifare::TARGET_UID);
    setState(true);
}

void MainWindow::on_MF_UID_wipeButton_clicked()
{
    mifare->wipeC();
}

void MainWindow::on_MF_UID_aboutUIDButton_clicked()
{
    QString msg;
    msg += tr("    Normally, the Block 0 of a typical Mifare card, which contains the UID, is locked during the manufacture. Users cannot write anything to Block 0 or set a new UID to a normal Mifare card.") + "\n";
    msg += tr("    Chinese Magic Cards(aka UID Cards) are some special cards whose Block 0 are writeable. And you can change UID by writing to it.") + "\n";
    msg += "\n";
    msg += tr("There are two versions of Chinese Magic Cards, the Gen1 and the Gen2.") + "\n";
    msg += tr("    Gen1:") + "\n" + tr("    also called UID card in China. It responses to some backdoor commands so you can access any blocks without password. The Proxmark3 has a bunch of related commands(csetblk, cgetblk, ...) to deal with this type of card, and my GUI also support these commands.") + "\n";
    msg += tr("    Gen2:") + "\n" + tr("    doesn't response to the backdoor commands, which means that a reader cannot detect whether it is a Chinese Magic Card or not by sending backdoor commands.") + "\n";
    msg += "\n";
    msg += tr("There are some types of Chinese Magic Card Gen2.") + "\n";
    msg += tr("    CUID Card:") + "\n" + tr("    the Block 0 is writeable, you can write to this block repeatedly by normal wrbl command.") + "\n";
    msg += tr("    (hf mf wrbl 0 A FFFFFFFFFFFF <the data you want to write>)") + "\n";
    msg += tr("    FUID Card:") + "\n" + tr("    you can only write to Block 0 once. After that, it seems like a typical Mifare card(Block 0 cannot be written to).") + "\n";
    msg += tr("    (some readers might try changing the Block 0, which could detect the CUID Card. In that case, you should use FUID card.)") + "\n";
    msg += tr("    UFUID Card:") + "\n" + tr("    It behaves like a CUID card(or UID card? I'm not sure) before you send some special command to lock it. Once it is locked, you cannot change its Block 0(just like a typical Mifare card).") + "\n";
    msg += "\n";
    msg += tr("    Seemingly, these Chinese Magic Cards are more easily to be compromised by Nested Attack(it takes little time to get an unknown key).") + "\n";
    QMessageBox::information(this, tr("About UID Card"), msg);
}

void MainWindow::on_MF_UID_setParaButton_clicked()
{
    setState(false);
    mifare->setParameterC();
    setState(true);
}

void MainWindow::on_MF_UID_lockButton_clicked()
{
    mifare->lockC();
}

void MainWindow::on_MF_Sim_readSelectedButton_clicked()
{
    setState(false);
    mifare->readSelected(Mifare::TARGET_EMULATOR);
    setState(true);
}

void MainWindow::on_MF_Sim_writeSelectedButton_clicked()
{
    setState(false);
    mifare->writeSelected(Mifare::TARGET_EMULATOR);
    setState(true);
}

void MainWindow::on_MF_Sim_clearButton_clicked()
{
    mifare->wipeE();
}

void MainWindow::on_MF_Sim_simButton_clicked()
{
    mifare->simulate();
}

void MainWindow::on_MF_Sniff_loadButton_clicked() // use a tmp file to support complicated path
{
    QString title = "";
    QString filename = "";
    QString defaultExtension;
    QDir clientTracePath;

    if(Util::getClientType() == Util::CLIENTTYPE_OFFICIAL)
        defaultExtension = ".trc";
    else if(Util::getClientType() == Util::CLIENTTYPE_ICEMAN)
        defaultExtension = ".trace";

    QString userTraceSavePath = mifare->getTraceSavePath();
    if(userTraceSavePath.isEmpty())
        clientTracePath = *clientWorkingDir;
    else
        clientTracePath = QDir(userTraceSavePath); // For v4.16717 and later

    title = tr("Plz select the trace file:");
    filename = QFileDialog::getOpenFileName(this, title, clientTracePath.absolutePath(), tr("Trace Files") + "(*" + defaultExtension + ")" + ";;" + tr("All Files(*.*)"));
    qDebug() << filename;
    if(filename != "")
    {
        QString tmpFile = "tmp" + QString::number(QDateTime::currentDateTimeUtc().toTime_t()) + defaultExtension;
        if(QFile::copy(filename, clientTracePath.absolutePath() + "/" + tmpFile))
        {
            mifare->loadSniff(tmpFile);
            util->delay(3000);
            QFile::remove(clientTracePath.absolutePath() + "/" + tmpFile);
        }
        else
        {
            QMessageBox::information(this, tr("Info"), tr("Failed to open") + "\n" + filename);
        }
    }
}

void MainWindow::on_MF_Sniff_saveButton_clicked()
{
    QString title = "";
    QString filename = "";
    QString defaultExtension;
    QDir clientTracePath;

    if(Util::getClientType() == Util::CLIENTTYPE_OFFICIAL)
        defaultExtension = ".trc";
    else if(Util::getClientType() == Util::CLIENTTYPE_ICEMAN)
        defaultExtension = ".trace";

    QString userTraceSavePath = mifare->getTraceSavePath();
    if(userTraceSavePath.isEmpty())
        clientTracePath = *clientWorkingDir;
    else
        clientTracePath = QDir(userTraceSavePath); // For v4.16717 and later

    title = tr("Plz select the location to save trace file:");
    filename = QFileDialog::getSaveFileName(this, title, clientTracePath.absolutePath(), tr("Trace Files") + "(*" + defaultExtension + ")");
    qDebug() << filename;
    if(filename != "")
    {
        QString tmpFile = "tmp" + QString::number(QDateTime::currentDateTimeUtc().toTime_t()) + defaultExtension;
        mifare->saveSniff(tmpFile);
        for(int i = 0; i < 100; i++)
        {
            util->delay(100);
            if(QFile::exists(clientTracePath.absolutePath() + "/" + tmpFile))
                break;
        }
        // filename is not empty -> the user has chosen to overwrite the existing file
        if(QFile::exists(filename))
            QFile::remove(filename);
        if(!QFile::copy(clientTracePath.absolutePath() + "/" + tmpFile, filename))
        {
            QMessageBox::information(this, tr("Info"), tr("Failed to save to") + "\n" + filename);
        }
        QFile::remove(clientTracePath.absolutePath() + "/" + tmpFile);
    }

}

void MainWindow::on_MF_Sniff_sniffButton_clicked()
{
    setState(false);
    mifare->sniff();
    setState(true);
}

void MainWindow::on_MF_14aSniff_snoopButton_clicked()
{
    setState(false);
    mifare->sniff14a();
    setState(true);
}

void MainWindow::on_MF_Sniff_listButton_clicked()
{
    mifare->list();
}

void MainWindow::MF_widgetReset()
{
    int secs = mifare->cardType.sector_size;
    int blks = mifare->cardType.block_size;
    ui->MF_RW_blockBox->clear();
    ui->MF_keyWidget->setRowCount(secs);
    ui->MF_dataWidget->setRowCount(blks);

    ui->MF_dataWidget->blockSignals(true);
    ui->MF_keyWidget->blockSignals(true);
    ui->MF_selectAllBox->blockSignals(true);
    ui->MF_selectTrailerBox->blockSignals(true);

    for(int i = 0; i < blks; i++)
    {
        setTableItem(ui->MF_dataWidget, i, 0, "");
        setTableItem(ui->MF_dataWidget, i, 1, QString::number(i));
        ui->MF_dataWidget->item(i, 1)->setCheckState(Qt::Checked);
        setTableItem(ui->MF_dataWidget, i, 2, "");
        ui->MF_RW_blockBox->addItem(QString::number(i));
    }

    QColor evenSecBg(22, 23, 29);
    QColor oddSecBg(28, 30, 38);
    QColor trailerBg(18, 42, 68);
    QColor trailerFg(64, 196, 255);
    QColor block0Bg(50, 36, 10);
    QColor block0Fg(255, 183, 77);

    for(int i = 0; i < secs; i++)
    {
        setTableItem(ui->MF_keyWidget, i, 0, QString::number(i));
        setTableItem(ui->MF_keyWidget, i, 1, "");
        setTableItem(ui->MF_keyWidget, i, 2, "");

        QColor secBg = (i % 2 == 0) ? evenSecBg : oddSecBg;
        for (int c = 0; c < 3; c++) {
            if (ui->MF_keyWidget->item(i, c)) {
                ui->MF_keyWidget->item(i, c)->setBackground(secBg);
            }
        }

        int startBlk = mifare->cardType.blks[i];
        int numBlks = mifare->cardType.blk[i];
        int trailerBlk = startBlk + numBlks - 1;

        setTableItem(ui->MF_dataWidget, startBlk, 0, QString::number(i));
        ui->MF_dataWidget->item(startBlk, 0)->setCheckState(Qt::Checked);

        for (int b = startBlk; b <= trailerBlk; b++) {
            for (int c = 0; c < 3; c++) {
                if (ui->MF_dataWidget->item(b, c)) {
                    ui->MF_dataWidget->item(b, c)->setBackground(secBg);
                }
            }
        }

        if (ui->MF_dataWidget->item(trailerBlk, 2)) {
            ui->MF_dataWidget->item(trailerBlk, 2)->setBackground(trailerBg);
            ui->MF_dataWidget->item(trailerBlk, 2)->setForeground(trailerFg);
            QFont f = ui->MF_dataWidget->item(trailerBlk, 2)->font();
            f.setBold(true);
            ui->MF_dataWidget->item(trailerBlk, 2)->setFont(f);
            ui->MF_dataWidget->item(trailerBlk, 2)->setToolTip(
                QString(tr("Sector %1 Trailer [Block %2]: Key A (6B) | Access Bits (4B) | Key B (6B)")).arg(i).arg(trailerBlk));
        }
    }

    if (ui->MF_dataWidget->item(0, 2)) {
        ui->MF_dataWidget->item(0, 2)->setBackground(block0Bg);
        ui->MF_dataWidget->item(0, 2)->setForeground(block0Fg);
        QFont f = ui->MF_dataWidget->item(0, 2)->font();
        f.setBold(true);
        ui->MF_dataWidget->item(0, 2)->setFont(f);
        ui->MF_dataWidget->item(0, 2)->setToolTip(tr("Block 0: Manufacturer Data & UID (Read-only on standard cards; writable on magic cards)"));
    }

    ui->MF_selectAllBox->setCheckState(Qt::Checked);
    ui->MF_selectTrailerBox->setCheckState(Qt::Checked);

    ui->MF_dataWidget->blockSignals(false);
    ui->MF_keyWidget->blockSignals(false);
    ui->MF_selectAllBox->blockSignals(false);
    ui->MF_selectTrailerBox->blockSignals(false);
}
// ************************************************


// ******************** other ********************

void MainWindow::uiInit()
{
    connect(ui->Raw_CMDEdit, &QLineEdit::returnPressed, this, &MainWindow::sendMSG);
    ui->Raw_CMDEdit->installEventFilter(keyEventFilter);
    connect(keyEventFilter, &MyEventFilter::eventHappened, this, &MainWindow::on_Raw_keyPressed);
    ui->MF_keyWidget->installEventFilter(resizeEventFilter);
    connect(resizeEventFilter, &MyEventFilter::eventHappened, this, &MainWindow::on_MF_keyWidget_resized);
    ui->Raw_outputEdit->installEventFilter(keyEventFilter);

    connectStatusBar = new QLabel(this);
    programStatusBar = new QLabel(this);
    PM3VersionBar = new QLabel(this);
    stopButton = new QPushButton(this);
    setStatusBar(connectStatusBar, tr("Not Connected"));
    setStatusBar(programStatusBar, tr("Idle"));
    setStatusBar(PM3VersionBar, "");
    stopButton->setText(tr("Stop"));
    ui->statusbar->addPermanentWidget(PM3VersionBar, 1);
    ui->statusbar->addPermanentWidget(connectStatusBar, 1);
    ui->statusbar->addPermanentWidget(programStatusBar, 1);
    ui->statusbar->addPermanentWidget(stopButton);

    ui->MF_dataWidget->setColumnWidth(0, 55);
    ui->MF_dataWidget->setColumnWidth(1, 55);

    ui->MF_keyWidget->setColumnWidth(0, 45);

    MF_widgetReset();
    MFCardTypeBtnGroup = new QButtonGroup(this);
    MFCardTypeBtnGroup->addButton(ui->MF_Type_miniButton, 0);
    MFCardTypeBtnGroup->addButton(ui->MF_Type_1kButton, 1);
    MFCardTypeBtnGroup->addButton(ui->MF_Type_2kButton, 2);
    MFCardTypeBtnGroup->addButton(ui->MF_Type_4kButton, 4);
    connect(MFCardTypeBtnGroup, &QButtonGroup::idToggled, this, &MainWindow::MF_onMFCardTypeChanged);

    ui->MF_keyWidget->installEventFilter(this);
    ui->MF_dataWidget->installEventFilter(this);

    ui->Set_UI_Theme_nameBox->addItem(tr("Modern Dark (Default)"), "modern_dark");
    ui->Set_UI_Theme_nameBox->addItem(tr("(None)"), "(none)");
    ui->Set_UI_Theme_nameBox->addItem(tr("Dark"), "qdss_dark");
    ui->Set_UI_Theme_nameBox->addItem(tr("Light"), "qdss_light");

    settings->beginGroup("UI_grpbox_preference");

    QStringList boxNames = settings->allKeys();
    QGroupBox * boxptr;
    foreach(QString name, boxNames)
    {
        boxptr = this->findChild<QGroupBox*>(name);
        if(boxptr == nullptr)
            continue;
        if(settings->value(name, true).toBool())
        {
            boxptr->setMaximumHeight(16777215);
            boxptr->setChecked(true);
        }
        else
        {
            boxptr->setMaximumHeight(20);
            boxptr->setChecked(false);
        }
    }
    settings->endGroup();

    loadClientPathList();

    ui->Set_Client_GUIWorkingDirLabel->setText(QDir::currentPath());

    settings->beginGroup("Client_Args");
#ifdef Q_OS_WIN
    ui->Set_Client_startArgsEdit->setText(settings->value("args", "<port> -f").toString());
#else
    ui->Set_Client_startArgsEdit->setText(settings->value("args", "/dev/<port> -f").toString());
#endif
    settings->endGroup();

    settings->beginGroup("Client_forceButtonsEnabled");
    keepButtonsEnabled = settings->value("state", false).toBool();
    settings->endGroup();
    ui->Set_Client_forceEnabledBox->setChecked(keepButtonsEnabled);

    // the disconnect detection doesn't work well on Linux/macOS
    // So it should be disabled on these platforms
    // https://github.com/wh201906/Proxmark3GUI/issues/22
    // #22, #26, #40, #41
    settings->beginGroup("Client_keepClientActive");
#ifdef Q_OS_WIN
    keepClientActive = settings->value("state", false).toBool();
#else
    keepClientActive = settings->value("state", true).toBool();
#endif
    settings->endGroup();
    ui->Set_Client_keepClientActiveBox->setChecked(keepClientActive);

    QDir configFiles(":/config/");
    configFiles.setSorting(QDir::Name);
    const QFileInfoList configFileList = configFiles.entryInfoList();
    ui->Set_Client_configFileBox->blockSignals(true);
    for(const auto& file : configFileList)
    {
        ui->Set_Client_configFileBox->addItem(file.fileName(), file.filePath());
    }

    // Use the last one as the default one
    ui->Set_Client_configFileBox->setCurrentIndex(ui->Set_Client_configFileBox->count() - 1);
    ui->Set_Client_configFileBox->addItem(tr("External file"), "(ext)");

    int configId = -1;
    settings->beginGroup("Client_Env");
    ui->Set_Client_envScriptEdit->setText(settings->value("scriptPath").toString());
    ui->Set_Client_workingDirEdit->setText(settings->value("workingDir", "../data").toString());
    configId = ui->Set_Client_configFileBox->findData(settings->value("configFile"));
    ui->Set_Client_configPathEdit->setText(settings->value("extConfigFilePath", "config.json").toString());
    settings->endGroup();
    if(configId != -1)
        ui->Set_Client_configFileBox->setCurrentIndex(configId);
    ui->Set_Client_configFileBox->blockSignals(false);
    on_Set_Client_configFileBox_currentIndexChanged(ui->Set_Client_configFileBox->currentIndex());

    // setValue() will trigger valueChanged()
    // setValue(settings->value()) will create a nested group
    // call endGroup() before apply the value
    settings->beginGroup("UI");
    int opacity = settings->value("Opacity", 100).toInt();
    int themeId = ui->Set_UI_Theme_nameBox->findData(settings->value("Theme_Name", "(none)").toString());
    settings->endGroup();
    ui->Set_UI_Opacity_Box->setValue(opacity);
    ui->Set_UI_Theme_nameBox->setCurrentIndex((themeId == -1) ? 0 : themeId);

    settings->beginGroup("UI");
    // QApplication::font() might return wrong result
    // If fonts are not specified in config file, don't touch them.
    QString tmpFontName;
    int tmpFontSize;
    bool fontValid = false, dataFontValid = false, CMDFontValid = false;
    tmpFontName = settings->value("Font_Name", "").toString();
    tmpFontSize = settings->value("Font_Size", -1).toInt();
    if(!tmpFontName.isEmpty() && tmpFontSize != -1 && tmpFontName == QFont(tmpFontName).family())
    {
        ui->Set_UI_Font_nameBox->setCurrentFont(QFont(tmpFontName));
        ui->Set_UI_Font_sizeBox->setValue(tmpFontSize);
        fontValid = true;
    }
    // The default font should be the same as MF_dataWidget's and MF_keyWidget's.
    tmpFontName = settings->value("DataFont_Name", "Consolas").toString();
    tmpFontSize = settings->value("DataFont_Size", 12).toInt();
    if(!tmpFontName.isEmpty() && tmpFontSize != -1 && tmpFontName == QFont(tmpFontName).family())
    {
        ui->Set_UI_DataFont_nameBox->setCurrentFont(QFont(tmpFontName));
        ui->Set_UI_DataFont_sizeBox->setValue(tmpFontSize);
        dataFontValid = true;
    }
    tmpFontName = settings->value("CMDFont_Name", "").toString();
    tmpFontSize = settings->value("CMDFont_Size", -1).toInt();
    if(!tmpFontName.isEmpty() && tmpFontSize != -1 && tmpFontName == QFont(tmpFontName).family())
    {
        ui->Set_UI_CMDFont_nameBox->setCurrentFont(QFont(tmpFontName));
        ui->Set_UI_CMDFont_sizeBox->setValue(tmpFontSize);
        CMDFontValid = true;
    }
    settings->endGroup();

    if(fontValid)
        on_Set_UI_Font_setButton_clicked();
    if(dataFontValid)
        on_Set_UI_DataFont_setButton_clicked();
    if(CMDFontValid)
        on_Set_UI_CMDFont_setButton_clicked();

    ui->MF_RW_keyTypeBox->addItem("A", Mifare::KEY_A);
    ui->MF_RW_keyTypeBox->addItem("B", Mifare::KEY_B);

    on_Raw_CMDHistoryBox_stateChanged(Qt::Unchecked);

}

void MainWindow::signalInit()
{
    connect(pm3, &PM3Process::newOutput, util, &Util::processOutput);
    connect(pm3, &PM3Process::changeClientType, util, &Util::setClientType);
    connect(util, &Util::refreshOutput, this, &MainWindow::refreshOutput);

    connect(this, &MainWindow::connectPM3, pm3, &PM3Process::connectPM3);
    connect(this, &MainWindow::reconnectPM3, pm3, &PM3Process::reconnectPM3);
    connect(pm3, &PM3Process::PM3StatedChanged, this, &MainWindow::onPM3StateChanged);
    connect(pm3, &PM3Process::PM3StatedChanged, util, &Util::setRunningState);
    connect(pm3, &PM3Process::errorOccurred, this, &MainWindow::onPM3ErrorOccurred);
    connect(pm3, &PM3Process::HWConnectFailed, this, &MainWindow::onPM3HWConnectFailed);
    connect(this, &MainWindow::killPM3, pm3, &PM3Process::killPM3);
    connect(this, &MainWindow::setProcEnv, pm3, &PM3Process::setProcEnv);
    connect(this, &MainWindow::setWorkingDir, pm3, &PM3Process::setWorkingDir);
    connect(this, QOverload<bool>::of(&MainWindow::setSerialListener), pm3, QOverload<bool>::of(&PM3Process::setSerialListener));
    connect(this, QOverload<const QString&, bool>::of(&MainWindow::setSerialListener), pm3, QOverload<const QString&, bool>::of(&PM3Process::setSerialListener));

    connect(util, &Util::write, pm3, &PM3Process::write);

    connect(ui->MF_typeGroupBox, &QGroupBox::clicked, this, &MainWindow::on_GroupBox_clicked);
    connect(ui->MF_fileGroupBox, &QGroupBox::clicked, this, &MainWindow::on_GroupBox_clicked);
    connect(ui->MF_RWGroupBox, &QGroupBox::clicked, this, &MainWindow::on_GroupBox_clicked);
    connect(ui->MF_normalGroupBox, &QGroupBox::clicked, this, &MainWindow::on_GroupBox_clicked);
    connect(ui->MF_UIDGroupBox, &QGroupBox::clicked, this, &MainWindow::on_GroupBox_clicked);
    connect(ui->MF_simGroupBox, &QGroupBox::clicked, this, &MainWindow::on_GroupBox_clicked);
    connect(ui->MF_sniffGroupBox, &QGroupBox::clicked, this, &MainWindow::on_GroupBox_clicked);

    connect(stopButton, &QPushButton::clicked, this, &MainWindow::on_stopButton_clicked);

    connect(ui->Set_UI_Opacity_slider, &QSlider::valueChanged, ui->Set_UI_Opacity_Box, &QSpinBox::setValue);
}

void MainWindow::setStatusBar(QLabel * target, const QString& text)
{
    if(target == PM3VersionBar)
        target->setText(tr("HW Version:") + text);
    else if(target == connectStatusBar)
        target->setText(tr("PM3:") + text);
    else if(target == programStatusBar)
        target->setText(tr("State:") + text);
}

void MainWindow::setTableItem(QTableWidget * widget, int row, int column, const QString& text)
{
    if(widget->item(row, column) == nullptr)
        widget->setItem(row, column, new QTableWidgetItem());
    widget->item(row, column)->setText(text);
}

bool MainWindow::eventFilter(QObject * watched, QEvent * event) // drag support
{
    if(event->type() == QEvent::DragEnter)
    {
        QDragEnterEvent* dragEvent = static_cast<QDragEnterEvent*>(event);
        dragEvent->acceptProposedAction();
        return true;
    }
    else if(event->type() == QEvent::Drop)
    {
        QDropEvent* dropEvent = static_cast<QDropEvent*>(event);
        if(watched == ui->MF_keyWidget)
        {
            const QMimeData* mime = dropEvent->mimeData();
            if(mime->hasUrls())
            {
                QList<QUrl> urls = mime->urls();
                if(urls.length() == 1)
                {
                    mifare->data_loadKeyFile(urls[0].toLocalFile());
                    return true;
                }
            }
        }
        else if(watched == ui->MF_dataWidget)
        {
            const QMimeData* mime = dropEvent->mimeData();
            if(mime->hasUrls())
            {
                QList<QUrl> urls = mime->urls();
                if(urls.length() == 1)
                {
                    mifare->data_loadDataFile(urls[0].toLocalFile());
                    return true;
                }
            }
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::setState(bool st)
{
    if(!st && pm3state)
    {
        setStatusBar(programStatusBar, tr("Running"));
    }
    else
    {
        setStatusBar(programStatusBar, tr("Idle"));
    }
    setButtonsEnabled(st || keepButtonsEnabled);
}

void MainWindow::setButtonsEnabled(bool st)
{
    ui->MF_attackGroupBox->setEnabled(st);
    ui->MF_normalGroupBox->setEnabled(st);
    ui->MF_UIDGroupBox->setEnabled(st);
    ui->MF_simGroupBox->setEnabled(st);
    ui->MF_sniffGroupBox->setEnabled(st);
    ui->Raw_CMDEdit->setEnabled(st);
    ui->Raw_sendCMDButton->setEnabled(st);
    ui->LF_LFconfigGroupBox->setEnabled(st);
    ui->LF_operationGroupBox->setEnabled(st);
    if (quickPullEmvBtn) quickPullEmvBtn->setEnabled(st);
    if (hwTuneGroupBox) hwTuneGroupBox->setEnabled(st);
    if (hwDiagGroupBox) hwDiagGroupBox->setEnabled(st);
    if (hwCardGroupBox) hwCardGroupBox->setEnabled(st);
}

void MainWindow::on_GroupBox_clicked(bool checked)
{
    QGroupBox* box = dynamic_cast<QGroupBox*>(sender());

    settings->beginGroup("UI_grpbox_preference");
    if(checked)
    {
        box->setMaximumHeight(16777215);
        settings->setValue(box->objectName(), true);
    }
    else
    {
        box->setMaximumHeight(20);
        settings->setValue(box->objectName(), false);
    }
    settings->endGroup();
}

void MainWindow::addClientPath(const QString& path)
{
    m_clientPathList.removeAll(path);
    m_clientPathList.prepend(path);
    while(m_clientPathList.size() > 32) // the maximum count of path items
        m_clientPathList.removeLast();
    // sync to the storage
    saveClientPathList();
    // sync to the UI
    loadClientPathList();
}

void MainWindow::loadClientPathList()
{
    m_clientPathList.clear();
    settings->beginGroup("Client_Path");
    int len = settings->beginReadArray("pathList");
    settings->endArray();
    if(settings->contains("path") && len == 0)
    {
        qDebug() << "Using old client path storage";
        m_clientPathList += settings->value("path", "proxmark3").toString();
    }
    else
    {
        int arrayLen = settings->beginReadArray("pathList");
        for(int i = 0; i < arrayLen; i++)
        {
            settings->setArrayIndex(i);
            QString path = settings->value("path").toString();
            if(!path.isEmpty())
                m_clientPathList += path;
        }
        settings->endArray();
    }
    settings->endGroup();

    ui->PM3_pathBox->clear();
    for(const QString& clientPath : qAsConst(m_clientPathList))
        ui->PM3_pathBox->addItem(clientPath);

    // Automatically detect and populate client binaries from system PATH and common dirs
    autoDetectClientPaths(false);
}

void MainWindow::autoDetectClientPaths(bool notifyUser)
{
    QStringList candidates;

    // 1. Search system PATH for proxmark3 and pm3 binaries
    QString fromPathPm3 = QStandardPaths::findExecutable("proxmark3");
    if (!fromPathPm3.isEmpty()) candidates << fromPathPm3;

    QString fromPathShort = QStandardPaths::findExecutable("pm3");
    if (!fromPathShort.isEmpty()) candidates << fromPathShort;

    // 2. Standard Linux / Kali / Unix locations
    QStringList knownLocations = {
        "/usr/bin/proxmark3",
        "/usr/local/bin/proxmark3",
        "/usr/bin/pm3",
        "/usr/local/bin/pm3",
        "/opt/proxmark3/client/proxmark3",
        "/opt/pm3/client/proxmark3",
        QDir::homePath() + "/proxmark3/client/proxmark3",
        QDir::homePath() + "/pm3/client/proxmark3",
        QDir::homePath() + "/.local/bin/proxmark3",
        QDir::homePath() + "/.local/bin/pm3",
        QDir::currentPath() + "/proxmark3",
        QDir::currentPath() + "/client/proxmark3"
    };

#ifdef Q_OS_WIN
    knownLocations << "C:/proxmark3/win64/proxmark3.exe"
                   << "C:/proxmark3/pm3.exe"
                   << "C:/pm3/proxmark3.exe"
                   << QDir::currentPath() + "/proxmark3.exe";
#endif

    candidates.append(knownLocations);

    int newlyAdded = 0;
    QString firstFound = "";

    for (const QString& candidate : candidates) {
        if (candidate.isEmpty()) continue;
        QFileInfo fi(candidate);
        if (fi.exists() && fi.isExecutable() && !fi.isDir()) {
            QString cleanPath = fi.canonicalFilePath();
            if (cleanPath.isEmpty()) cleanPath = fi.absoluteFilePath();

            if (firstFound.isEmpty()) {
                firstFound = cleanPath;
            }

            if (!m_clientPathList.contains(cleanPath)) {
                m_clientPathList.append(cleanPath);
                newlyAdded++;
            }
        }
    }

    if (newlyAdded > 0 || ui->PM3_pathBox->count() == 0) {
        saveClientPathList();
        ui->PM3_pathBox->blockSignals(true);
        ui->PM3_pathBox->clear();
        for (const QString& path : qAsConst(m_clientPathList)) {
            ui->PM3_pathBox->addItem(path);
        }
        if (!firstFound.isEmpty()) {
            int idx = ui->PM3_pathBox->findText(firstFound);
            if (idx != -1) {
                ui->PM3_pathBox->setCurrentIndex(idx);
            }
        }
        ui->PM3_pathBox->blockSignals(false);
    }

    if (notifyUser) {
        if (!firstFound.isEmpty()) {
            QMessageBox::information(
                this,
                tr("Client Path Detected"),
                tr("Proxmark3 client found:\n%1\n\nTotal paths configured: %2")
                    .arg(firstFound, QString::number(m_clientPathList.size()))
            );
        } else {
            QMessageBox::warning(
                this,
                tr("No Client Found"),
                tr("Could not find a valid Proxmark3 executable in system PATH or standard directories.\n\nPlease use the Browse (📁) button to select your proxmark3 binary.")
            );
        }
    }
}

void MainWindow::onBrowseClientClicked()
{
    QString initialDir = "/usr/bin";
    if (ui->PM3_pathBox->count() > 0) {
        QFileInfo fi(ui->PM3_pathBox->currentText());
        if (fi.exists()) initialDir = fi.absolutePath();
    }

    QString selected = QFileDialog::getOpenFileName(
        this,
        tr("Select Proxmark3 Client Executable"),
        initialDir,
#ifdef Q_OS_WIN
        tr("Executable (*.exe);;All Files (*)")
#else
        tr("Executable (proxmark3 pm3 *);;All Files (*)")
#endif
    );

    if (!selected.isEmpty()) {
        addClientPath(selected);
    }
}

void MainWindow::onAutoDetectClientClicked()
{
    autoDetectClientPaths(true);
}

void MainWindow::saveClientPathList()
{
    settings->beginGroup("Client_Path");
    if(settings->contains("path"))
    {
        qDebug() << "Upgrading client path storage";
        QString oldPath = settings->value("path").toString();
        if(!oldPath.isEmpty() && !m_clientPathList.contains(oldPath))
            m_clientPathList.append(oldPath);
        settings->remove("path");
    }

    settings->beginWriteArray("pathList");
    for(int i = 0; i < m_clientPathList.size(); i++)
    {
        settings->setArrayIndex(i);
        settings->setValue("path", m_clientPathList[i]);
    }
    settings->endArray();
    settings->endGroup();
}
// ***********************************************



void MainWindow::on_MF_Attack_darksideButton_clicked()
{
    setState(false);
    mifare->darkside();
    setState(true);
}

void MainWindow::on_Set_Client_startArgsEdit_editingFinished()
{
    settings->beginGroup("Client_Args");
    settings->setValue("args", ui->Set_Client_startArgsEdit->text());
    settings->endGroup();
}

void MainWindow::on_Set_Client_forceEnabledBox_stateChanged(int arg1)
{
    settings->beginGroup("Client_forceButtonsEnabled");
    keepButtonsEnabled = (arg1 == Qt::Checked);
    settings->setValue("state", keepButtonsEnabled);
    settings->endGroup();
    if(keepButtonsEnabled)
        setButtonsEnabled(true);
}

void MainWindow::on_Set_UI_setLanguageButton_clicked()
{
    Util::chooseLanguage(settings, this);
}

void MainWindow::on_PM3_refreshPortButton_clicked()
{
    on_portSearchTimer_timeout();
}

void MainWindow::on_Set_Client_envScriptEdit_editingFinished()
{
    settings->beginGroup("Client_Env");
    settings->setValue("scriptPath", ui->Set_Client_envScriptEdit->text());
    settings->endGroup();
}

void MainWindow::on_Set_Client_workingDirEdit_editingFinished()
{
    settings->beginGroup("Client_Env");
    settings->setValue("workingDir", ui->Set_Client_workingDirEdit->text());
    settings->endGroup();
}


void MainWindow::on_Set_Client_configPathEdit_editingFinished()
{
    settings->beginGroup("Client_Env");
    settings->setValue("extConfigFilePath", ui->Set_Client_configPathEdit->text());
    settings->endGroup();
}

void MainWindow::on_Set_Client_keepClientActiveBox_stateChanged(int arg1)
{
    settings->beginGroup("Client_keepClientActive");
    keepClientActive = (arg1 == Qt::Checked);
    settings->setValue("state", keepClientActive);
    settings->endGroup();
    emit setSerialListener(!keepClientActive);
}

void MainWindow::on_LF_LFConf_freqSlider_valueChanged(int value)
{
    onLFfreqConfChanged(value, true);
}

void MainWindow::onLFfreqConfChanged(int divisor, bool isCustomized)
{
    ui->LF_LFConf_freqDivisorBox->blockSignals(true);
    ui->LF_LFConf_freqSlider->blockSignals(true);

    if(isCustomized)
        ui->LF_LFConf_freqOtherButton->setChecked(true);
    else if(divisor == 95)
        ui->LF_LFConf_freq125kButton->setChecked(true);
    else if(divisor == 88)
        ui->LF_LFConf_freq134kButton->setChecked(true);
    ui->LF_LFConf_freqLabel->setText(tr("Actural Freq: ") + QString("%1kHz").arg(LF::divisor2Freq(divisor), 0, 'f', 3));
    ui->LF_LFConf_freqDivisorBox->setValue(divisor);
    ui->LF_LFConf_freqSlider->setValue(divisor);

    ui->LF_LFConf_freqDivisorBox->blockSignals(false);
    ui->LF_LFConf_freqSlider->blockSignals(false);
}

void MainWindow::on_LF_LFConf_freqDivisorBox_valueChanged(int arg1)
{
    onLFfreqConfChanged(arg1, true);
}

void MainWindow::on_LF_LFConf_freq125kButton_clicked()
{
    onLFfreqConfChanged(95, false);
}

void MainWindow::on_LF_LFConf_freq134kButton_clicked()
{
    onLFfreqConfChanged(88, false);
}

void MainWindow::on_LF_Op_searchButton_clicked()
{
    setState(false);
    lf->search();
    setState(true);
}

void MainWindow::on_LF_Op_readButton_clicked()
{
    setState(false);
    lf->read();
    setState(true);
}

void MainWindow::on_LF_Op_tuneButton_clicked()
{
    setState(false);
    lf->tune();
    setState(true);
}

void MainWindow::on_LF_Op_sniffButton_clicked()
{
    setState(false);
    lf->sniff();
    setState(true);
}

void MainWindow::dockInit()
{
    // Keeping funcTab as the clean modern tabbed interface with collapsible console drawer below.
}

void MainWindow::contextMenuEvent(QContextMenuEvent *event)
{
    contextMenu->exec(event->globalPos());
}

void MainWindow::on_LF_LFConf_getButton_clicked()
{
    setState(false);
    lf->getLFConfig();
    setState(true);
}

void MainWindow::on_LF_LFConf_setButton_clicked()
{
    LF::LFConfig config;
    setState(false);
    config.divisor = ui->LF_LFConf_freqDivisorBox->value();
    config.bitsPerSample = ui->LF_LFConf_bitsPerSampleBox->value();
    config.decimation = ui->LF_LFConf_decimationBox->value();
    config.averaging = ui->LF_LFConf_averagingBox->isChecked();
    config.triggerThreshold = ui->LF_LFConf_thresholdBox->value();
    config.samplesToSkip = ui->LF_LFConf_skipsBox->value();
    lf->setLFConfig(config);
    Util::gotoRawTab();
    setState(true);
}

void MainWindow::on_LF_LFConf_resetButton_clicked()
{
    setState(false);
    lf->resetLFConfig();
    setState(true);
}

void MainWindow::on_Set_Client_configFileBox_currentIndexChanged(int index)
{
    ui->Set_Client_configPathEdit->setVisible(ui->Set_Client_configFileBox->itemData(index).toString() == "(ext)");
    settings->beginGroup("Client_Env");
    settings->setValue("configFile", ui->Set_Client_configFileBox->currentData());
    settings->endGroup();
}


void MainWindow::on_Set_UI_Opacity_Box_valueChanged(int arg1)
{
    ui->Set_UI_Opacity_slider->blockSignals(true);
    ui->Set_UI_Opacity_slider->setValue(arg1);
    setWindowOpacity(arg1 / 100.0);
    settings->beginGroup("UI");
    settings->setValue("Opacity", ui->Set_UI_Opacity_Box->value());
    settings->endGroup();
    ui->Set_UI_Opacity_slider->blockSignals(false);
}


void MainWindow::on_Set_UI_Theme_setButton_clicked()
{
    QString themeName = ui->Set_UI_Theme_nameBox->currentData().toString();
    settings->beginGroup("UI");
    settings->setValue("Theme_Name", themeName);
    settings->endGroup();

    if (themeName == "modern_dark" || themeName.isEmpty()) {
        qApp->setStyleSheet(getModernDarkStyle());
    } else if (themeName == "qdss_dark") {
        QFile file(":/qdarkstyle/dark/darkstyle.qss");
        if (file.open(QFile::ReadOnly | QFile::Text)) {
            QTextStream ts(&file);
            qApp->setStyleSheet(ts.readAll());
        }
    } else if (themeName == "qdss_light") {
        QFile file(":/qdarkstyle/light/lightstyle.qss");
        if (file.open(QFile::ReadOnly | QFile::Text)) {
            QTextStream ts(&file);
            qApp->setStyleSheet(ts.readAll());
        }
    } else {
        qApp->setStyleSheet("");
    }
}


void MainWindow::on_Set_UI_Font_setButton_clicked()
{
    QFont font = ui->Set_UI_Font_nameBox->currentFont();
    font.setPointSize(ui->Set_UI_Font_sizeBox->value());
    QApplication::setFont(font, "QWidget");

    settings->beginGroup("UI");
    settings->setValue("Font_Name", ui->Set_UI_Font_nameBox->currentFont().family());
    settings->setValue("Font_Size", ui->Set_UI_Font_sizeBox->value());
    settings->endGroup();
}


void MainWindow::on_Set_UI_DataFont_setButton_clicked()
{
    QFont font = ui->Set_UI_DataFont_nameBox->currentFont();
    font.setPointSize(ui->Set_UI_DataFont_sizeBox->value());
    ui->MF_dataWidget->setFont(font);
    ui->MF_keyWidget->setFont(font);

    settings->beginGroup("UI");
    settings->setValue("DataFont_Name", ui->Set_UI_DataFont_nameBox->currentFont().family());
    settings->setValue("DataFont_Size", ui->Set_UI_DataFont_sizeBox->value());
    settings->endGroup();
}


void MainWindow::on_Set_UI_CMDFont_setButton_clicked()
{
    QFont font = ui->Set_UI_CMDFont_nameBox->currentFont();
    font.setPointSize(ui->Set_UI_CMDFont_sizeBox->value());
    ui->Raw_outputEdit->setFont(font);

    settings->beginGroup("UI");
    settings->setValue("CMDFont_Name", ui->Set_UI_CMDFont_nameBox->currentFont().family());
    settings->setValue("CMDFont_Size", ui->Set_UI_CMDFont_sizeBox->value());
    settings->endGroup();
}

void MainWindow::setupTopToolbar()
{
    connectStatusBadge = new QLabel(ui->centralwidget);
    connectStatusBadge->setObjectName("connectStatusBadge");
    connectStatusBadge->setMinimumHeight(24);
    updateConnectionBadge(false);
    ui->horizontalLayout->insertWidget(0, connectStatusBadge);

    // Client Path Browse & Auto-Detect buttons
    int pathIdx = ui->horizontalLayout->indexOf(ui->PM3_pathBox);
    btnBrowseClient = new QPushButton(tr("📁"), ui->centralwidget);
    btnBrowseClient->setObjectName("btnBrowseClient");
    btnBrowseClient->setToolTip(tr("Browse for Proxmark3 client executable..."));
    btnBrowseClient->setMaximumWidth(32);
    btnBrowseClient->setStyleSheet("padding: 3px; font-size: 10pt;");
    connect(btnBrowseClient, &QPushButton::clicked, this, &MainWindow::onBrowseClientClicked);

    btnAutoDetectClient = new QPushButton(tr("🔍 Auto"), ui->centralwidget);
    btnAutoDetectClient->setObjectName("btnAutoDetectClient");
    btnAutoDetectClient->setToolTip(tr("Automatically scan system PATH and common directories for Proxmark3 executable"));
    btnAutoDetectClient->setStyleSheet("font-weight: bold; padding: 3px 8px; font-size: 9pt;");
    connect(btnAutoDetectClient, &QPushButton::clicked, this, &MainWindow::onAutoDetectClientClicked);

    if (pathIdx != -1) {
        ui->horizontalLayout->insertWidget(pathIdx + 1, btnBrowseClient);
        ui->horizontalLayout->insertWidget(pathIdx + 2, btnAutoDetectClient);
    }

    quickStopTopBtn = new QPushButton(tr("🛑 STOP"), ui->centralwidget);
    quickStopTopBtn->setObjectName("quickStopTopBtn");
    quickStopTopBtn->setToolTip(tr("Abort current Proxmark3 command"));
    quickStopTopBtn->setEnabled(false);
    connect(quickStopTopBtn, &QPushButton::clicked, this, &MainWindow::on_stopButton_clicked);
    ui->horizontalLayout->addWidget(quickStopTopBtn);

    quickPullEmvBtn = new QPushButton(tr("⚡ Auto-Pull Card"), ui->centralwidget);
    quickPullEmvBtn->setObjectName("quickPullEmvBtn");
    quickPullEmvBtn->setToolTip(tr("Scan contactless smartcard and pull all EMV / payment data into the inspector"));
    quickPullEmvBtn->setStyleSheet("background-color: #00838f; color: #ffffff; font-weight: bold; padding: 4px 10px; border-radius: 4px; border: 1px solid #00e5ff;");
    quickPullEmvBtn->setEnabled(false);
    connect(quickPullEmvBtn, &QPushButton::clicked, [this]() {
        ui->funcTab->setCurrentWidget(emvTab);
        emvTab->onAutoPullClicked();
    });
    ui->horizontalLayout->addWidget(quickPullEmvBtn);

    toggleConsoleBtn = new QPushButton(tr("▼ Console"), ui->centralwidget);
    toggleConsoleBtn->setObjectName("toggleConsoleBtn");
    toggleConsoleBtn->setToolTip(tr("Toggle bottom console drawer (Ctrl+` or F12)"));
    toggleConsoleBtn->setShortcut(QKeySequence("Ctrl+`"));
    connect(toggleConsoleBtn, &QPushButton::clicked, this, &MainWindow::toggleConsoleDrawer);
    ui->horizontalLayout->addWidget(toggleConsoleBtn);
}

void MainWindow::setupConsoleDrawer()
{
    int rawIdx = ui->funcTab->indexOf(ui->rawTab);
    if (rawIdx != -1) {
        ui->funcTab->removeTab(rawIdx);
    }

    consoleDrawer = ui->rawTab;
    consoleDrawer->setParent(ui->centralwidget);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(6, 4, 6, 4);
    headerLayout->setSpacing(8);

    QLabel* title = new QLabel(tr("<b>📟 Proxmark3 Terminal & Console</b>"), consoleDrawer);
    title->setStyleSheet("color: #00e5ff; font-size: 10pt;");
    headerLayout->addWidget(title);

    headerLayout->addStretch(1);

    consoleFilterEdit = new QLineEdit(consoleDrawer);
    consoleFilterEdit->setPlaceholderText(tr("Search log..."));
    consoleFilterEdit->setClearButtonEnabled(true);
    consoleFilterEdit->setMaximumWidth(160);
    connect(consoleFilterEdit, &QLineEdit::textChanged, this, &MainWindow::onConsoleFilterChanged);
    headerLayout->addWidget(consoleFilterEdit);

    consoleAutoScrollBox = new QCheckBox(tr("Auto-scroll"), consoleDrawer);
    consoleAutoScrollBox->setChecked(true);
    headerLayout->addWidget(consoleAutoScrollBox);

    consoleCopyBtn = new QPushButton(tr("📋 Copy"), consoleDrawer);
    consoleCopyBtn->setToolTip(tr("Copy all output to clipboard"));
    connect(consoleCopyBtn, &QPushButton::clicked, this, &MainWindow::onConsoleCopyClicked);
    headerLayout->addWidget(consoleCopyBtn);

    consoleSaveBtn = new QPushButton(tr("💾 Save..."), consoleDrawer);
    consoleSaveBtn->setToolTip(tr("Save console log to file"));
    connect(consoleSaveBtn, &QPushButton::clicked, this, &MainWindow::onConsoleSaveClicked);
    headerLayout->addWidget(consoleSaveBtn);

    aiAskBtn = new QPushButton(tr("✨ Ask AI"), consoleDrawer);
    aiAskBtn->setToolTip(tr("Ask GenAI Copilot for RFID help or command suggestions"));
    aiAskBtn->setStyleSheet("background-color: #4a148c; border: 1px solid #aa00ff; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 4px 10px;");
    connect(aiAskBtn, &QPushButton::clicked, this, &MainWindow::onAiAskClicked);
    headerLayout->addWidget(aiAskBtn);

    aiExplainBtn = new QPushButton(tr("🤖 Explain Log"), consoleDrawer);
    aiExplainBtn->setToolTip(tr("Ask GenAI Copilot to analyze recent output and detect vulnerabilities"));
    aiExplainBtn->setStyleSheet("background-color: #311b92; border: 1px solid #7c4dff; color: #ffffff; font-weight: bold; border-radius: 4px; padding: 4px 10px;");
    connect(aiExplainBtn, &QPushButton::clicked, this, &MainWindow::onAiExplainClicked);
    headerLayout->addWidget(aiExplainBtn);

    ui->Raw_clearOutputButton->setText(tr("🗑️ Clear"));

    consoleCloseBtn = new QPushButton("✕", consoleDrawer);
    consoleCloseBtn->setToolTip(tr("Collapse console drawer (Ctrl+`)"));
    consoleCloseBtn->setMaximumWidth(28);
    connect(consoleCloseBtn, &QPushButton::clicked, this, &MainWindow::toggleConsoleDrawer);
    headerLayout->addWidget(consoleCloseBtn);

    QVBoxLayout* vLayout = qobject_cast<QVBoxLayout*>(ui->rawTab->layout());
    if (vLayout) {
        vLayout->insertLayout(0, headerLayout);
    }

    ui->Raw_CMDEdit->setPlaceholderText(tr("Type PM3 command, or ask AI with '? <question>' (e.g. ? clone em410x to t5577)..."));
    ui->Raw_sendCMDButton->setText(tr("Send ↵"));

    ui->verticalLayout_2->removeWidget(ui->funcTab);

    mainSplitter = new QSplitter(Qt::Vertical, ui->centralwidget);
    mainSplitter->setObjectName("mainSplitter");
    mainSplitter->setChildrenCollapsible(false);
    mainSplitter->addWidget(ui->funcTab);
    mainSplitter->addWidget(consoleDrawer);

    mainSplitter->setStretchFactor(0, 65);
    mainSplitter->setStretchFactor(1, 35);

    ui->verticalLayout_2->addWidget(mainSplitter, 1);
}

void MainWindow::setupHardwareTab()
{
    hwTab = new QWidget();
    hwTab->setObjectName("hwTab");

    QVBoxLayout* mainLayout = new QVBoxLayout(hwTab);
    mainLayout->setContentsMargins(8, 8, 8, 8);

    QScrollArea* scrollArea = new QScrollArea(hwTab);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* scrollContent = new QWidget();
    QVBoxLayout* contentLayout = new QVBoxLayout(scrollContent);
    contentLayout->setSpacing(12);

    // GroupBox 1: Antenna Resonance & Coil Voltages
    hwTuneGroupBox = new QGroupBox(tr("Antenna Tuning & Peak Voltages (hw tune)"), scrollContent);
    QVBoxLayout* tuneLayout = new QVBoxLayout(hwTuneGroupBox);

    QLabel* tuneDesc = new QLabel(tr("Antenna diagnostics measures LF (125 kHz) and HF (13.56 MHz) antenna resonance and coil peak voltages.<br>"
                                     "Optimal coupling requires adequate unloaded voltage (typically &gt;20V on LF, &gt;15V on HF)."), hwTuneGroupBox);
    tuneDesc->setWordWrap(true);
    tuneLayout->addWidget(tuneDesc);

    QHBoxLayout* voltageCardsLayout = new QHBoxLayout();

    // LF Card
    QFrame* lfCard = new QFrame(hwTuneGroupBox);
    lfCard->setFrameShape(QFrame::StyledPanel);
    lfCard->setStyleSheet("background-color: #1e2028; border: 1px solid #333646; border-radius: 6px; padding: 10px;");
    QVBoxLayout* lfCardLayout = new QVBoxLayout(lfCard);
    QLabel* lfTitle = new QLabel(tr("<b>Low Frequency (LF) Antenna</b>"), lfCard);
    lfTitle->setStyleSheet("color: #00e5ff; font-size: 11pt;");
    lfVoltageLabel = new QLabel(tr("<b style='font-size: 15pt; color: #888;'>-- V</b> @ 125 kHz"), lfCard);
    lfStatusBadge = new QLabel(tr("● Status: Ready to measure"), lfCard);
    lfStatusBadge->setStyleSheet("color: #a0a0b0;");
    QLabel* lfTarget = new QLabel(tr("Nominal unloaded: 20V – 65V"), lfCard);
    lfTarget->setStyleSheet("color: #707080; font-size: 9pt;");
    lfCardLayout->addWidget(lfTitle);
    lfCardLayout->addWidget(lfVoltageLabel);
    lfCardLayout->addWidget(lfStatusBadge);
    lfCardLayout->addWidget(lfTarget);
    voltageCardsLayout->addWidget(lfCard);

    // HF Card
    QFrame* hfCard = new QFrame(hwTuneGroupBox);
    hfCard->setFrameShape(QFrame::StyledPanel);
    hfCard->setStyleSheet("background-color: #1e2028; border: 1px solid #333646; border-radius: 6px; padding: 10px;");
    QVBoxLayout* hfCardLayout = new QVBoxLayout(hfCard);
    QLabel* hfTitle = new QLabel(tr("<b>High Frequency (HF) Antenna</b>"), hfCard);
    hfTitle->setStyleSheet("color: #00e5ff; font-size: 11pt;");
    hfVoltageLabel = new QLabel(tr("<b style='font-size: 15pt; color: #888;'>-- V</b> @ 13.56 MHz"), hfCard);
    hfStatusBadge = new QLabel(tr("● Status: Ready to measure"), hfCard);
    hfStatusBadge->setStyleSheet("color: #a0a0b0;");
    QLabel* hfTarget = new QLabel(tr("Nominal unloaded: 15V – 35V"), hfCard);
    hfTarget->setStyleSheet("color: #707080; font-size: 9pt;");
    hfCardLayout->addWidget(hfTitle);
    hfCardLayout->addWidget(hfVoltageLabel);
    hfCardLayout->addWidget(hfStatusBadge);
    hfCardLayout->addWidget(hfTarget);
    voltageCardsLayout->addWidget(hfCard);

    tuneLayout->addLayout(voltageCardsLayout);

    QPushButton* runTuneBtn = new QPushButton(tr("📡 Run Antenna Tune (hw tune)"), hwTuneGroupBox);
    runTuneBtn->setStyleSheet("padding: 8px 16px; font-weight: bold; background-color: #007791; color: white; border-radius: 4px;");
    connect(runTuneBtn, &QPushButton::clicked, this, &MainWindow::onQuickTuneClicked);
    tuneLayout->addWidget(runTuneBtn);

    contentLayout->addWidget(hwTuneGroupBox);

    // GroupBox 2: Device & Firmware Information
    hwDiagGroupBox = new QGroupBox(tr("Hardware & System Diagnostics"), scrollContent);
    QVBoxLayout* diagLayout = new QVBoxLayout(hwDiagGroupBox);

    QHBoxLayout* diagButtons = new QHBoxLayout();
    QPushButton* btnVersion = new QPushButton(tr("ℹ️ Hardware Version (hw version)"), hwDiagGroupBox);
    connect(btnVersion, &QPushButton::clicked, this, &MainWindow::onQuickVersionClicked);
    diagButtons->addWidget(btnVersion);

    QPushButton* btnStatus = new QPushButton(tr("⚡ Device Status (hw status)"), hwDiagGroupBox);
    connect(btnStatus, &QPushButton::clicked, this, &MainWindow::onQuickStatusClicked);
    diagButtons->addWidget(btnStatus);

    QPushButton* btnPing = new QPushButton(tr("📶 Ping Device (hw ping)"), hwDiagGroupBox);
    connect(btnPing, &QPushButton::clicked, [this]() {
        util->execCMD("hw ping");
        showConsoleDrawer();
    });
    diagButtons->addWidget(btnPing);
    diagLayout->addLayout(diagButtons);

    contentLayout->addWidget(hwDiagGroupBox);

    // GroupBox 3: Quick RFID Identification & Testing
    hwCardGroupBox = new QGroupBox(tr("Quick RFID Card Detection & Helper Tools"), scrollContent);
    QVBoxLayout* cardLayout = new QVBoxLayout(hwCardGroupBox);

    QHBoxLayout* hfButtons = new QHBoxLayout();
    QPushButton* btnHfSearch = new QPushButton(tr("🔍 Auto-Search HF Card (hf search)"), hwCardGroupBox);
    connect(btnHfSearch, &QPushButton::clicked, [this]() {
        util->execCMD("hf search");
        showConsoleDrawer();
    });
    hfButtons->addWidget(btnHfSearch);

    QPushButton* btn14aInfo = new QPushButton(tr("📋 Read 14A UID & Info (hf 14a info)"), hwCardGroupBox);
    connect(btn14aInfo, &QPushButton::clicked, [this]() {
        util->execCMD("hf 14a info");
        showConsoleDrawer();
    });
    hfButtons->addWidget(btn14aInfo);
    cardLayout->addLayout(hfButtons);

    QHBoxLayout* lfButtons = new QHBoxLayout();
    QPushButton* btnLfSearch = new QPushButton(tr("🔍 Auto-Search LF Tag (lf search)"), hwCardGroupBox);
    connect(btnLfSearch, &QPushButton::clicked, [this]() {
        util->execCMD("lf search");
        showConsoleDrawer();
    });
    lfButtons->addWidget(btnLfSearch);

    QPushButton* btnEmRead = new QPushButton(tr("📻 Read EM410x (lf em 410x reader)"), hwCardGroupBox);
    connect(btnEmRead, &QPushButton::clicked, [this]() {
        util->execCMD("lf em 410x reader");
        showConsoleDrawer();
    });
    lfButtons->addWidget(btnEmRead);

    QPushButton* btnHidRead = new QPushButton(tr("🏢 Read HID Prox (lf hid read)"), hwCardGroupBox);
    connect(btnHidRead, &QPushButton::clicked, [this]() {
        util->execCMD("lf hid read");
        showConsoleDrawer();
    });
    lfButtons->addWidget(btnHidRead);
    cardLayout->addLayout(lfButtons);

    contentLayout->addWidget(hwCardGroupBox);

    contentLayout->addStretch(1);
    scrollArea->setWidget(scrollContent);
    mainLayout->addWidget(scrollArea);

    ui->funcTab->insertTab(4, hwTab, tr("Hardware & Diagnostics"));
}

void MainWindow::updateConnectionBadge(bool connected, const QString& info)
{
    if (connectStatusBadge == nullptr) return;
    if (connected) {
        QString port = ui->PM3_portBox->currentText();
        QString desc = info.isEmpty() ? port : info;
        connectStatusBadge->setText(tr("● Connected: %1").arg(desc));
        connectStatusBadge->setStyleSheet("background-color: #1b5e20; color: #b9f6ca; border: 1px solid #00e676; border-radius: 4px; padding: 4px 10px; font-weight: bold; font-size: 10pt;");
    } else {
        connectStatusBadge->setText(tr("● Disconnected"));
        connectStatusBadge->setStyleSheet("background-color: #3e2723; color: #ff8a80; border: 1px solid #d32f2f; border-radius: 4px; padding: 4px 10px; font-weight: bold; font-size: 10pt;");
    }
}

void MainWindow::showConsoleDrawer()
{
    if (consoleDrawer != nullptr && !consoleDrawerVisible) {
        consoleDrawerVisible = true;
        consoleDrawer->setVisible(true);
        if (toggleConsoleBtn) toggleConsoleBtn->setText(tr("▼ Console"));
        if (mainSplitter) {
            mainSplitter->setSizes({height() * 65 / 100, height() * 35 / 100});
        }
    }
}

void MainWindow::toggleConsoleDrawer()
{
    if (consoleDrawer == nullptr) return;
    consoleDrawerVisible = !consoleDrawerVisible;
    consoleDrawer->setVisible(consoleDrawerVisible);
    if (toggleConsoleBtn) {
        toggleConsoleBtn->setText(consoleDrawerVisible ? tr("▼ Console") : tr("▲ Console"));
    }
    if (consoleDrawerVisible && mainSplitter) {
        QList<int> sizes = mainSplitter->sizes();
        if (sizes.size() >= 2 && sizes[1] < 80) {
            mainSplitter->setSizes({height() * 65 / 100, height() * 35 / 100});
        }
    }
}

void MainWindow::onConsoleCopyClicked()
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->Raw_outputEdit->toPlainText());
    setStatusBar(programStatusBar, tr("Console log copied to clipboard"));
}

void MainWindow::onConsoleSaveClicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Console Log"),
                                                    QDir::currentPath() + "/pm3_log.txt",
                                                    tr("Text Files (*.txt);;Log Files (*.log);;All Files (*)"));
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << ui->Raw_outputEdit->toPlainText();
            file.close();
            setStatusBar(programStatusBar, tr("Console log saved"));
        } else {
            QMessageBox::warning(this, tr("Error"), tr("Failed to save file: ") + file.errorString());
        }
    }
}

void MainWindow::onConsoleFilterChanged(const QString& text)
{
    if (text.isEmpty()) {
        return;
    }
    ui->Raw_outputEdit->find(text);
}

void MainWindow::onQuickTuneClicked()
{
    util->execCMD("hw tune");
    showConsoleDrawer();
}

void MainWindow::onQuickVersionClicked()
{
    util->execCMD("hw version");
    showConsoleDrawer();
}

void MainWindow::onQuickStatusClicked()
{
    util->execCMD("hw status");
    showConsoleDrawer();
}

QString MainWindow::getModernDarkStyle()
{
    return QString(
        "QMainWindow, QWidget {"
        "    background-color: #16171d;"
        "    color: #e4e4ec;"
        "    font-family: 'Segoe UI', 'Ubuntu', 'DejaVu Sans', sans-serif;"
        "}"
        "QTabWidget::pane {"
        "    border: 1px solid #282a36;"
        "    background-color: #1b1c24;"
        "    border-radius: 4px;"
        "}"
        "QTabBar::tab {"
        "    background: #14151b;"
        "    color: #8c8ea0;"
        "    padding: 7px 18px;"
        "    margin-right: 2px;"
        "    border-top-left-radius: 4px;"
        "    border-top-right-radius: 4px;"
        "    font-weight: 600;"
        "    font-size: 10pt;"
        "}"
        "QTabBar::tab:selected {"
        "    background: #1b1c24;"
        "    color: #00e5ff;"
        "    border-bottom: 2px solid #00e5ff;"
        "}"
        "QTabBar::tab:hover:!selected {"
        "    background: #20222e;"
        "    color: #ffffff;"
        "}"
        "QGroupBox {"
        "    border: 1px solid #2d2f3d;"
        "    border-radius: 6px;"
        "    margin-top: 14px;"
        "    padding: 12px 6px 6px 6px;"
        "    font-weight: bold;"
        "    background-color: #1a1b23;"
        "}"
        "QGroupBox::title {"
        "    subcontrol-origin: margin;"
        "    subcontrol-position: top left;"
        "    left: 10px;"
        "    padding: 0 5px;"
        "    color: #00e5ff;"
        "}"
        "QPushButton {"
        "    background-color: #262834;"
        "    border: 1px solid #36394c;"
        "    border-radius: 4px;"
        "    padding: 5px 12px;"
        "    color: #e4e4ec;"
        "    font-weight: 500;"
        "    min-height: 22px;"
        "}"
        "QPushButton:hover {"
        "    background-color: #313444;"
        "    border-color: #00b4d8;"
        "    color: #ffffff;"
        "}"
        "QPushButton:pressed {"
        "    background-color: #1c1d26;"
        "    border-color: #007791;"
        "}"
        "QPushButton:disabled {"
        "    background-color: #191a22;"
        "    border-color: #252632;"
        "    color: #555666;"
        "}"
        "#PM3_connectButton {"
        "    background-color: #1b5e20;"
        "    border: 1px solid #00e676;"
        "    color: #ffffff;"
        "    font-weight: bold;"
        "}"
        "#PM3_connectButton:hover {"
        "    background-color: #2e7d32;"
        "    border-color: #69f0ae;"
        "}"
        "#PM3_disconnectButton {"
        "    background-color: #4a1515;"
        "    border: 1px solid #e53935;"
        "    color: #ffcdd2;"
        "}"
        "#PM3_disconnectButton:hover {"
        "    background-color: #6a1b1b;"
        "    border-color: #ef5350;"
        "}"
        "#quickStopTopBtn {"
        "    background-color: #5c1818;"
        "    border: 1px solid #f44336;"
        "    color: #ffffff;"
        "    font-weight: bold;"
        "}"
        "#quickStopTopBtn:hover {"
        "    background-color: #832020;"
        "}"
        "QLineEdit, QSpinBox, QComboBox {"
        "    background-color: #14151a;"
        "    border: 1px solid #303342;"
        "    border-radius: 4px;"
        "    padding: 4px 8px;"
        "    color: #ffffff;"
        "}"
        "QLineEdit:focus, QSpinBox:focus, QComboBox:focus {"
        "    border: 1px solid #00b4d8;"
        "    background-color: #181920;"
        "}"
        "QTableWidget {"
        "    background-color: #131419;"
        "    alternate-background-color: #181920;"
        "    gridline-color: #242632;"
        "    border: 1px solid #282a36;"
        "    border-radius: 4px;"
        "    selection-background-color: rgba(0, 180, 216, 0.35);"
        "    selection-color: #ffffff;"
        "}"
        "QHeaderView::section {"
        "    background-color: #17181f;"
        "    color: #8c8ea0;"
        "    padding: 4px 6px;"
        "    border: 1px solid #242632;"
        "    font-weight: bold;"
        "}"
        "QPlainTextEdit#Raw_outputEdit {"
        "    background-color: #111216;"
        "    color: #e0e0e0;"
        "    border: 1px solid #252733;"
        "    border-radius: 4px;"
        "    font-family: 'DejaVu Sans Mono', 'Consolas', 'Courier New', monospace;"
        "}"
        "QSplitter::handle:vertical {"
        "    background-color: #252733;"
        "    height: 5px;"
        "}"
        "QSplitter::handle:vertical:hover {"
        "    background-color: #00e5ff;"
        "}"
        "QStatusBar {"
        "    background-color: #121318;"
        "    border-top: 1px solid #252733;"
        "    color: #8c8ea0;"
        "}"
        "QScrollBar:vertical {"
        "    background: #14151a;"
        "    width: 9px;"
        "    margin: 0px;"
        "}"
        "QScrollBar::handle:vertical {"
        "    background: #2c2e3d;"
        "    min-height: 20px;"
        "    border-radius: 4px;"
        "}"
        "QScrollBar::handle:vertical:hover {"
        "    background: #00b4d8;"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
        "    height: 0px;"
        "}"
    );
}

void MainWindow::onAiAskClicked()
{
    bool ok = false;
    QString query = QInputDialog::getText(this, tr("Ask GenAI Copilot"),
                                          tr("Enter your question or task for Proxmark3:\n(e.g., 'how to clone EM410x to T5577', 'crack keys with autopwn')"),
                                          QLineEdit::Normal, "", &ok);
    if (ok && !query.trimmed().isEmpty()) {
        showConsoleDrawer();
        refreshCMD("? " + query);
        QString promptDisplay = QString("\n[🤖 GenAI Copilot] %1\n").arg(query);
        refreshOutput(promptDisplay);
        QString context = ui->Raw_outputEdit->toPlainText().right(2000);
        genai->ask(query, context);
    }
}

void MainWindow::onAiExplainClicked()
{
    showConsoleDrawer();
    QString context = ui->Raw_outputEdit->toPlainText().right(2000);
    if (context.trimmed().isEmpty()) {
        refreshOutput("\n[🤖 GenAI Copilot] Console output is currently empty. Run a command like 'hf search', 'lf search', or 'hw tune' first!\n");
        return;
    }
    refreshOutput("\n[🤖 GenAI Copilot] Analyzing latest console output & detecting card vulnerabilities...\n");
    genai->explainOutput(context);
}

void MainWindow::onAiResponseReady(const QString &response, const QStringList &suggestedCommands)
{
    QString formatted = QString("[🤖 GenAI Copilot]\n%1\n").arg(response);
    refreshOutput(formatted);

    if (!suggestedCommands.isEmpty()) {
        for (const QString &c : suggestedCommands) {
            refreshOutput(QString("[💡 Suggested Command]: %1\n").arg(c));
        }
        ui->Raw_CMDEdit->setText(suggestedCommands.first());
        ui->Raw_CMDEdit->setFocus();
        ui->Raw_CMDEdit->selectAll();
    }
    setStatusBar(programStatusBar, tr("GenAI response complete"));
}

void MainWindow::onAiThinking(const QString &statusMsg)
{
    setStatusBar(programStatusBar, statusMsg);
}

void MainWindow::setupGenAISettings()
{
    QLayout* sLayout = ui->settingsTab->layout();
    if (!sLayout) return;

    QGroupBox* aiGroup = new QGroupBox(tr("🤖 GenAI Copilot Configuration"), ui->settingsTab);
    QVBoxLayout* gLayout = new QVBoxLayout(aiGroup);
    gLayout->setSpacing(8);

    QHBoxLayout* row1 = new QHBoxLayout();
    QLabel* lblBackend = new QLabel(tr("Backend Engine:"), aiGroup);
    QComboBox* comboBackend = new QComboBox(aiGroup);
    comboBackend->addItem(tr("Built-in Offline RFID Expert (Zero Config)"), static_cast<int>(GenAICopilot::BACKEND_BUILTIN));
    comboBackend->addItem(tr("Local Ollama (http://localhost:11434)"), static_cast<int>(GenAICopilot::BACKEND_OLLAMA));
    comboBackend->addItem(tr("Custom OpenAI / Gemini REST API"), static_cast<int>(GenAICopilot::BACKEND_OPENAI));
    comboBackend->setCurrentIndex(static_cast<int>(genai->backendType()));
    row1->addWidget(lblBackend);
    row1->addWidget(comboBackend, 1);
    gLayout->addLayout(row1);

    QHBoxLayout* row2 = new QHBoxLayout();
    QLabel* lblEndpoint = new QLabel(tr("API Endpoint:"), aiGroup);
    QLineEdit* editEndpoint = new QLineEdit(genai->endpointUrl(), aiGroup);
    row2->addWidget(lblEndpoint);
    row2->addWidget(editEndpoint, 1);
    gLayout->addLayout(row2);

    QHBoxLayout* row3 = new QHBoxLayout();
    QLabel* lblModel = new QLabel(tr("Model Name:"), aiGroup);
    QLineEdit* editModel = new QLineEdit(genai->modelName(), aiGroup);
    row3->addWidget(lblModel);
    row3->addWidget(editModel, 1);
    gLayout->addLayout(row3);

    QHBoxLayout* row4 = new QHBoxLayout();
    QLabel* lblKey = new QLabel(tr("API Key:"), aiGroup);
    QLineEdit* editKey = new QLineEdit(genai->apiKey(), aiGroup);
    editKey->setEchoMode(QLineEdit::Password);
    editKey->setPlaceholderText(tr("Optional for Local Ollama / Builtin"));
    row4->addWidget(lblKey);
    row4->addWidget(editKey, 1);
    gLayout->addLayout(row4);

    QHBoxLayout* row5 = new QHBoxLayout();
    QPushButton* btnSave = new QPushButton(tr("💾 Save AI Settings"), aiGroup);
    QPushButton* btnTest = new QPushButton(tr("⚡ Test Connection"), aiGroup);
    row5->addWidget(btnSave);
    row5->addWidget(btnTest);
    row5->addStretch(1);
    gLayout->addLayout(row5);

    connect(comboBackend, QOverload<int>::of(&QComboBox::currentIndexChanged), [=](int idx) {
        if (idx == GenAICopilot::BACKEND_BUILTIN) {
            editEndpoint->setEnabled(false);
            editModel->setEnabled(false);
            editKey->setEnabled(false);
        } else if (idx == GenAICopilot::BACKEND_OLLAMA) {
            editEndpoint->setEnabled(true);
            if (editEndpoint->text().isEmpty() || editEndpoint->text().contains("api.openai.com")) {
                editEndpoint->setText("http://localhost:11434/api/generate");
            }
            editModel->setEnabled(true);
            if (editModel->text().isEmpty()) editModel->setText("llama3.2");
            editKey->setEnabled(false);
        } else {
            editEndpoint->setEnabled(true);
            if (editEndpoint->text().isEmpty() || editEndpoint->text().contains("11434")) {
                editEndpoint->setText("https://api.openai.com/v1/chat/completions");
            }
            editModel->setEnabled(true);
            if (editModel->text().isEmpty()) editModel->setText("gpt-4o-mini");
            editKey->setEnabled(true);
        }
    });

    int initialBackend = static_cast<int>(genai->backendType());
    if (initialBackend == GenAICopilot::BACKEND_BUILTIN) {
        editEndpoint->setEnabled(false);
        editModel->setEnabled(false);
        editKey->setEnabled(false);
    }

    connect(btnSave, &QPushButton::clicked, [=]() {
        genai->setBackendType(static_cast<GenAICopilot::BackendType>(comboBackend->currentData().toInt()));
        genai->setEndpointUrl(editEndpoint->text().trimmed());
        genai->setModelName(editModel->text().trimmed());
        genai->setApiKey(editKey->text().trimmed());
        genai->saveSettings(settings);
        QMessageBox::information(this, tr("AI Settings"), tr("GenAI Copilot settings saved successfully!"));
    });

    connect(btnTest, &QPushButton::clicked, [=]() {
        genai->setBackendType(static_cast<GenAICopilot::BackendType>(comboBackend->currentData().toInt()));
        genai->setEndpointUrl(editEndpoint->text().trimmed());
        genai->setModelName(editModel->text().trimmed());
        genai->setApiKey(editKey->text().trimmed());
        genai->testConnection();
    });

    connect(genai, &GenAICopilot::testConnectionResult, this, [this](bool success, const QString& msg) {
        if (success) {
            QMessageBox::information(this, tr("AI Test Successful"), msg);
        } else {
            QMessageBox::warning(this, tr("AI Test Failed"), msg);
        }
    });

    sLayout->addWidget(aiGroup);
}

