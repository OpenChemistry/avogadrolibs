/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CALCULATIONWATCHER_H
#define AVOGADRO_QTPLUGINS_CALCULATIONWATCHER_H

#include <QSharedPointer>
#include <QVariantMap>

class QNetworkAccessManager;
class QNetworkReply;

namespace Avogadro {
namespace QtPlugins {

class CalculationWatcher : public QObject
{
  Q_OBJECT

public:
  explicit CalculationWatcher(QSharedPointer<QNetworkAccessManager> manager,
                              const QString& girderUrl,
                              const QString& girderToken,
                              const QString& pendingCalculationId,
                              QObject* parent);
  ~CalculationWatcher() override;

  void start();

signals:
  void finished(const QByteArray& cjson);
  void error(const QString& errorMessage, QNetworkReply* error = nullptr);

private slots:
  void checkCalculation();
  void finishCheckCalculation(const QVariant& results);

  void handleError(const QString& msg, QNetworkReply* networkReply);

private:
  QString m_girderUrl = "http://localhost:8080/api/v1";
  QString m_girderToken;

  // These should be set before starting
  QString m_pendingCalculationId;

  QSharedPointer<QNetworkAccessManager> m_networkManager;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CALCULATIONWATCHER_H
