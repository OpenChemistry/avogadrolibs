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

#include "calculationwatcher.h"

#include "girderrequest.h"

#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>

#include <QDebug>

namespace Avogadro {
namespace QtPlugins {

static void deleteRequestWhenFinished(GirderRequest* r)
{
  QObject::connect(r, &GirderRequest::result, r, &GirderRequest::deleteLater);
  QObject::connect(r, &GirderRequest::error, r, &GirderRequest::deleteLater);
}

CalculationWatcher::CalculationWatcher(
  QSharedPointer<QNetworkAccessManager> manager, const QString& girderUrl,
  const QString& girderToken, const QString& pendingCalculationId,
  QObject* parent)
  : QObject(parent), m_girderUrl(girderUrl), m_girderToken(girderToken),
    m_pendingCalculationId(pendingCalculationId), m_networkManager(manager)
{}

CalculationWatcher::~CalculationWatcher() = default;

void CalculationWatcher::start()
{
  checkCalculation();
}

void CalculationWatcher::checkCalculation()
{
  QString url = (m_girderUrl + "/calculations/%1").arg(m_pendingCalculationId);

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->get();

  qDebug() << "Checking calculation status...";

  connect(request, &GirderRequest::result, this,
          &CalculationWatcher::finishCheckCalculation);
  connect(request, &GirderRequest::error, this,
          &CalculationWatcher::handleError);
  deleteRequestWhenFinished(request);
}

void CalculationWatcher::finishCheckCalculation(const QVariant& results)
{
  // Perform a couple of sanity checks
  QString calculationId = results.toMap()["_id"].toString();
  if (calculationId.isEmpty()) {
    emit error("In calculation watcher, calculation id not found!");
    return;
  }

  if (calculationId != m_pendingCalculationId) {
    emit error("In calculation watcher, calculationId does not match!");
    return;
  }

  // We assume the calculation is done when the cjson is present
  QVariantMap cjson = results.toMap()["cjson"].toMap();
  if (cjson.isEmpty()) {
    qDebug() << "Calculation still running. Trying again in 5 seconds...";
    // No results yet. Try again in 5 seconds.
    QTimer::singleShot(5000, this, &CalculationWatcher::checkCalculation);
    return;
  }

  qDebug() << "Calculation is complete!";

  QByteArray cjsonData =
    QJsonDocument::fromVariant(cjson).toJson(QJsonDocument::Compact);
  emit finished(cjsonData);
}

void CalculationWatcher::handleError(const QString& msg,
                                     QNetworkReply* networkReply)
{
  QString message = msg;
  if (!msg.startsWith("Girder error:"))
    message.prepend("Girder error:");

  emit error(message, networkReply);
}

} // namespace QtPlugins
} // namespace Avogadro
