/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

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
