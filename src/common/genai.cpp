#include "genai.h"
#include <QRegularExpression>
#include <QDebug>
#include <QUrl>

GenAICopilot::GenAICopilot(QObject *parent)
    : QObject(parent),
      m_backend(BACKEND_BUILTIN),
      m_endpoint("http://localhost:11434/api/generate"),
      m_model("llama3.2"),
      m_apiKey(""),
      m_isTestingConnection(false)
{
    m_netManager = new QNetworkAccessManager(this);
    connect(m_netManager, &QNetworkAccessManager::finished, this, &GenAICopilot::onNetworkReply);
}

GenAICopilot::~GenAICopilot()
{
}

void GenAICopilot::loadSettings(QSettings *settings)
{
    if (!settings) return;
    settings->beginGroup("GenAI");
    m_backend = static_cast<BackendType>(settings->value("backend", static_cast<int>(BACKEND_BUILTIN)).toInt());
    m_endpoint = settings->value("endpoint", "http://localhost:11434/api/generate").toString();
    m_model = settings->value("model", "llama3.2").toString();
    m_apiKey = settings->value("apiKey", "").toString();
    settings->endGroup();
}

void GenAICopilot::saveSettings(QSettings *settings)
{
    if (!settings) return;
    settings->beginGroup("GenAI");
    settings->setValue("backend", static_cast<int>(m_backend));
    settings->setValue("endpoint", m_endpoint);
    settings->setValue("model", m_model);
    settings->setValue("apiKey", m_apiKey);
    settings->endGroup();
}

void GenAICopilot::ask(const QString &userQuery, const QString &terminalContext)
{
    m_isTestingConnection = false;
    m_pendingQuery = userQuery;
    m_pendingContext = terminalContext;

    emit thinking(tr("GenAI Copilot is analyzing query..."));

    if (m_backend == BACKEND_OLLAMA) {
        sendOllamaRequest(userQuery, terminalContext);
    } else if (m_backend == BACKEND_OPENAI) {
        sendOpenAIRequest(userQuery, terminalContext);
    } else {
        QStringList cmds;
        QString answer = solveWithBuiltinEngine(userQuery, terminalContext, cmds);
        emit responseReady(answer, cmds);
    }
}

void GenAICopilot::explainOutput(const QString &terminalContext)
{
    QString query = tr("Explain the latest Proxmark3 terminal output, detect card vulnerabilities, and recommend the best next commands.");
    ask(query, terminalContext);
}

void GenAICopilot::testConnection()
{
    m_isTestingConnection = true;
    emit thinking(tr("Testing GenAI connection..."));

    if (m_backend == BACKEND_BUILTIN) {
        emit testConnectionResult(true, tr("Built-in Offline RFID Expert is ready and functional!"));
        return;
    }

    if (m_backend == BACKEND_OLLAMA) {
        QUrl url(m_endpoint.isEmpty() ? "http://localhost:11434/api/generate" : m_endpoint);
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

        QJsonObject json;
        json["model"] = m_model.isEmpty() ? "llama3.2" : m_model;
        json["prompt"] = "Respond with 'OK'";
        json["stream"] = false;

        m_netManager->post(req, QJsonDocument(json).toJson());
    } else if (m_backend == BACKEND_OPENAI) {
        QUrl url(m_endpoint.isEmpty() ? "https://api.openai.com/v1/chat/completions" : m_endpoint);
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        if (!m_apiKey.isEmpty()) {
            req.setRawHeader("Authorization", QString("Bearer " + m_apiKey).toUtf8());
        }

        QJsonObject json;
        json["model"] = m_model.isEmpty() ? "gpt-4o-mini" : m_model;
        QJsonArray messages;
        QJsonObject msg;
        msg["role"] = "user";
        msg["content"] = "Ping";
        messages.append(msg);
        json["messages"] = messages;

        m_netManager->post(req, QJsonDocument(json).toJson());
    }
}

void GenAICopilot::sendOllamaRequest(const QString &prompt, const QString &context)
{
    QUrl url(m_endpoint.isEmpty() ? "http://localhost:11434/api/generate" : m_endpoint);
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QString fullPrompt = QString(
        "You are an expert RFID/NFC security researcher and Proxmark3 assistant.\n"
        "Terminal Output Context:\n%1\n\n"
        "User Request:\n%2\n\n"
        "Provide a concise, helpful explanation and explicitly format any recommended Proxmark3 commands on lines starting with 'pm3> <command>'."
    ).arg(context.right(1500)).arg(prompt);

    QJsonObject json;
    json["model"] = m_model.isEmpty() ? "llama3.2" : m_model;
    json["prompt"] = fullPrompt;
    json["stream"] = false;

    m_netManager->post(req, QJsonDocument(json).toJson());
}

void GenAICopilot::sendOpenAIRequest(const QString &prompt, const QString &context)
{
    QUrl url(m_endpoint.isEmpty() ? "https://api.openai.com/v1/chat/completions" : m_endpoint);
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (!m_apiKey.isEmpty()) {
        req.setRawHeader("Authorization", QString("Bearer " + m_apiKey).toUtf8());
    }

    QJsonObject json;
    json["model"] = m_model.isEmpty() ? "gpt-4o-mini" : m_model;

    QJsonArray messages;
    QJsonObject sysMsg;
    sysMsg["role"] = "system";
    sysMsg["content"] = "You are an elite Proxmark3 and RFID security copilot. Answer concisely. Format actionable PM3 commands on lines starting with 'pm3> <command>'.";
    messages.append(sysMsg);

    QJsonObject userMsg;
    userMsg["role"] = "user";
    userMsg["content"] = QString("Recent Terminal Context:\n%1\n\nUser Question:\n%2").arg(context.right(1500)).arg(prompt);
    messages.append(userMsg);

    json["messages"] = messages;

    m_netManager->post(req, QJsonDocument(json).toJson());
}

void GenAICopilot::onNetworkReply(QNetworkReply *reply)
{
    reply->deleteLater();

    if (m_isTestingConnection) {
        m_isTestingConnection = false;
        if (reply->error() == QNetworkReply::NoError) {
            emit testConnectionResult(true, tr("Successfully connected to GenAI backend (%1)!").arg(m_model));
        } else {
            emit testConnectionResult(false, tr("Connection error: %1").arg(reply->errorString()));
        }
        return;
    }

    if (reply->error() != QNetworkReply::NoError) {
        // Fallback to built-in engine if remote model fails or is offline
        QStringList cmds;
        QString fallbackAnswer = solveWithBuiltinEngine(m_pendingQuery, m_pendingContext, cmds);
        QString errorNote = QString(tr("[⚠️ Note: Remote GenAI backend (%1) was unreachable. Falling back to Built-in RFID Expert Engine.]\n\n%2"))
            .arg(reply->errorString()).arg(fallbackAnswer);
        emit responseReady(errorNote, cmds);
        return;
    }

    QByteArray rawData = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(rawData);
    QString rawAnswer;

    if (m_backend == BACKEND_OLLAMA) {
        rawAnswer = doc.object()["response"].toString();
    } else if (m_backend == BACKEND_OPENAI) {
        QJsonArray choices = doc.object()["choices"].toArray();
        if (!choices.isEmpty()) {
            rawAnswer = choices[0].toObject()["message"].toObject()["content"].toString();
        }
    }

    if (rawAnswer.trimmed().isEmpty()) {
        QStringList cmds;
        rawAnswer = solveWithBuiltinEngine(m_pendingQuery, m_pendingContext, cmds);
        emit responseReady(rawAnswer, cmds);
        return;
    }

    QStringList extractedCmds;
    QString cleaned = extractSuggestedCommands(rawAnswer, extractedCmds);
    emit responseReady(cleaned, extractedCmds);
}

QString GenAICopilot::extractSuggestedCommands(const QString &text, QStringList &commands)
{
    QString cleaned = text;
    static QRegularExpression cmdRegex("(?:pm3\\s*>|pm3-->|run:)\\s*([a-zA-Z0-9_\\-\\s\\.\\:\\/]+)", QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator it = cmdRegex.globalMatch(text);
    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        QString cmd = match.captured(1).trimmed();
        if (!cmd.isEmpty() && !commands.contains(cmd)) {
            commands.append(cmd);
        }
    }
    return cleaned;
}

QString GenAICopilot::solveWithBuiltinEngine(const QString &query, const QString &terminalContext, QStringList &suggestedCommands)
{
    QString q = query.toLower().trimmed();
    QString res;

    // 1. UID / Magic Card operations
    if (q.contains("clone") && (q.contains("em410") || q.contains("em410x") || q.contains("125k"))) {
        QRegularExpression idRegex("(?:id|--id|hex|uid)?\\s*([0-9a-fA-F]{10})");
        QRegularExpressionMatch m = idRegex.match(query);
        QString id = m.hasMatch() ? m.captured(1) : "0102030405";
        suggestedCommands << QString("lf em 410x clone --id %1").arg(id);
        res = QString(
            "### 🏷️ EM410x RFID Tag Cloning\n"
            "To clone an EM410x tag onto a writable **T5577** (or compatible) chip, ensure the blank T5577 is on the antenna and run:\n"
            "```\npm3> lf em 410x clone --id %1\n```\n"
            "- Frequency: 125 kHz\n"
            "- Modulation: ASK, Manchester encoding"
        ).arg(id);
        return res;
    }

    if (q.contains("clone") && q.contains("hid")) {
        suggestedCommands << "lf hid read" << "lf hid clone -r <RAW_HEX>";
        res = "### 🏢 HID Prox Cloning\n"
              "1. First read the source HID card:\n"
              "   ```\n   pm3> lf hid read\n   ```\n"
              "2. Note the raw hex or ID, place a blank T5577 on the coil, then write:\n"
              "   ```\n   pm3> lf hid clone -r <RAW_HEX>\n   ```";
        return res;
    }

    if (q.contains("autopwn") || (q.contains("pwn") && q.contains("mifare")) || q.contains("crack all")) {
        suggestedCommands << "hf mf autopwn";
        res = "### ⚡ Mifare Classic Auto-Pwn\n"
              "The `hf mf autopwn` automated attack attempts:\n"
              "1. **Default key dictionary attack** (`chk`)\n"
              "2. **Nested attack** for non-hardened PRNG\n"
              "3. **Hardnested attack** for hardened EV1/crypto PRNG\n"
              "4. Automatic memory dump (`dump.bin` and `dump.json`)\n\n"
              "```\npm3> hf mf autopwn\n```";
        return res;
    }

    if (q.contains("dump") && q.contains("mifare")) {
        suggestedCommands << "hf mf dump --1k";
        res = "### 💾 Dump Mifare Classic Memory\n"
              "If sector keys are already known or verified in your session:\n"
              "```\npm3> hf mf dump --1k\n```\n"
              "Use `--4k` for 4KB cards, or `--mini` for 320-byte cards.";
        return res;
    }

    if (q.contains("tune") || q.contains("antenna") || q.contains("voltage")) {
        suggestedCommands << "hw tune";
        res = "### 📡 Antenna Tuning & Voltage Diagnostics\n"
              "To check the resonant frequency and coil coupling voltage of both antennas:\n"
              "```\npm3> hw tune\n```\n"
              "- **LF Peak (125 kHz)**: Should be ~20V - 60V unloaded\n"
              "- **HF Peak (13.56 MHz)**: Should be ~15V - 35V unloaded";
        return res;
    }

    if (q.contains("magic") || q.contains("gen1a") || q.contains("csetuid") || (q.contains("change") && q.contains("uid"))) {
        QRegularExpression uidRegex("([0-9a-fA-F]{8})");
        QRegularExpressionMatch m = uidRegex.match(query);
        QString uid = m.hasMatch() ? m.captured(1) : "01020304";
        suggestedCommands << QString("hf mf csetuid %1").arg(uid);
        res = QString(
            "### 🔮 Chinese Magic Card (Gen1a) UID Writing\n"
            "Chinese Magic Cards (Gen1a) support backdoor backdoor commands to write to Block 0 without keys:\n"
            "```\npm3> hf mf csetuid %1\n```\n"
            "For direct wipe: `hf mf cwipe`."
        ).arg(uid);
        return res;
    }

    // 2. Terminal Context Analysis / explainOutput
    if (q.contains("explain") || q.contains("diagnose") || terminalContext.length() > 50) {
        if (terminalContext.contains("EM410x", Qt::CaseInsensitive)) {
            QRegularExpression emRegex("ID\\s*:\\s*([0-9A-Fa-f]{10})");
            QRegularExpressionMatch emMatch = emRegex.match(terminalContext);
            QString id = emMatch.hasMatch() ? emMatch.captured(1) : "detected tag";
            suggestedCommands << QString("lf em 410x clone --id %1").arg(id);
            res = QString(
                "### 🔍 Log Analysis: EM410x Low Frequency Tag Detected\n"
                "- **Tag Type**: EM410x (125 kHz, 64-bit Manchester)\n"
                "- **Unique ID**: `%1`\n"
                "- **Next Step**: You can clone this ID directly onto a T5577 card with:\n"
                "```\npm3> lf em 410x clone --id %1\n```"
            ).arg(id);
            return res;
        }

        if (terminalContext.contains("MIFARE Classic", Qt::CaseInsensitive) || terminalContext.contains("SAK: 08", Qt::CaseInsensitive)) {
            suggestedCommands << "hf mf autopwn" << "hf mf chk --1k";
            res = "### 🔍 Log Analysis: Mifare Classic 1K Detected\n"
                  "- **Standard**: ISO 14443-A, 13.56 MHz (SAK 08 = Classic 1K)\n"
                  "- **Vulnerabilities**: Known PRNG weakness (Nested attack susceptible)\n"
                  "- **Next Step**: Run automated credential cracking and memory dump:\n"
                  "```\npm3> hf mf autopwn\n```";
            return res;
        }

        if (terminalContext.contains("HF antenna:", Qt::CaseInsensitive) || terminalContext.contains("LF antenna:", Qt::CaseInsensitive)) {
            res = "### 🔍 Log Analysis: Antenna Tuning Results\n"
                  "Your Proxmark3 measured coil resonance voltages. When a tag is placed closely on the coil, you will observe the voltage drop slightly due to electromagnetic induction load.";
            return res;
        }
    }

    // Default intelligent assistant guidance
    suggestedCommands << "hf search" << "lf search" << "hw tune";
    res = QString(
        "### 🤖 Proxmark3 Copilot Ready\n"
        "Here are key commands for your current session:\n"
        "- 🔍 **Scan HF Card**: `pm3> hf search`\n"
        "- 🔍 **Scan LF Tag**: `pm3> lf search`\n"
        "- ⚡ **Auto-Pwn Mifare**: `pm3> hf mf autopwn`\n"
        "- 📡 **Antenna Tune**: `pm3> hw tune`\n\n"
        "You can ask natural language questions anytime, e.g.:\n"
        "- *\"how do I clone an EM410x card?\"*\n"
        "- *\"change UID to 11223344 on magic card\"*\n"
        "- *\"explain the last output\"*"
    );
    return res;
}
