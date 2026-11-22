#ifndef GENAI_H
#define GENAI_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSettings>

class GenAICopilot : public QObject
{
    Q_OBJECT
public:
    enum BackendType {
        BACKEND_BUILTIN = 0,
        BACKEND_OLLAMA = 1,
        BACKEND_OPENAI = 2
    };

    explicit GenAICopilot(QObject *parent = nullptr);
    ~GenAICopilot();

    void loadSettings(QSettings *settings);
    void saveSettings(QSettings *settings);

    BackendType backendType() const { return m_backend; }
    void setBackendType(BackendType type) { m_backend = type; }

    QString endpointUrl() const { return m_endpoint; }
    void setEndpointUrl(const QString &url) { m_endpoint = url; }

    QString modelName() const { return m_model; }
    void setModelName(const QString &model) { m_model = model; }

    QString apiKey() const { return m_apiKey; }
    void setApiKey(const QString &key) { m_apiKey = key; }

public slots:
    void ask(const QString &userQuery, const QString &terminalContext = "");
    void explainOutput(const QString &terminalContext);
    void testConnection();

signals:
    void responseReady(const QString &response, const QStringList &suggestedCommands);
    void thinking(const QString &statusMsg);
    void errorOccurred(const QString &error);
    void testConnectionResult(bool success, const QString &message);

private slots:
    void onNetworkReply(QNetworkReply *reply);

private:
    BackendType m_backend;
    QString m_endpoint;
    QString m_model;
    QString m_apiKey;

    QNetworkAccessManager *m_netManager;

    QString solveWithBuiltinEngine(const QString &query, const QString &terminalContext, QStringList &suggestedCommands);
    QString extractSuggestedCommands(const QString &text, QStringList &commands);
    void sendOllamaRequest(const QString &prompt, const QString &context);
    void sendOpenAIRequest(const QString &prompt, const QString &context);

    bool m_isTestingConnection;
    QString m_pendingQuery;
    QString m_pendingContext;
};

#endif // GENAI_H
