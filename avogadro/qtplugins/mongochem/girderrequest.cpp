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

#include "girderrequest.h"

#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrlQuery>

#include <memory>

namespace Avogadro {

namespace QtPlugins {

// Some function declarations
static QString handleGirderError(QNetworkReply* reply, const QByteArray& bytes);

GirderRequest::GirderRequest(QNetworkAccessManager* networkManager,
                             const QString& girderUrl,
                             const QString& girderToken,
                             const QVariantMap& options, QObject* parent)
  : QObject(parent), m_girderUrl(girderUrl), m_girderToken(girderToken),
    m_options(options), m_networkManager(networkManager)
{}

// We will use this for our unique_ptrs
struct QObjectLaterDeleter
{
  void operator()(QObject* obj) { obj->deleteLater(); }
};
template <typename T>
using unique_ptr_delete_later = std::unique_ptr<T, QObjectLaterDeleter>;

void GirderRequest::finished()
{
  unique_ptr_delete_later<QNetworkReply> reply(
    qobject_cast<QNetworkReply*>(this->sender()));
  QByteArray bytes = reply->readAll();
  if (reply->error()) {
    emit error(handleGirderError(reply.get(), bytes), reply.get());
  } else {
    QJsonDocument jsonResponse = QJsonDocument::fromJson(bytes.constData());
    emit result(jsonResponse.toVariant().toMap());
  }
}

void GetMoleculesRequest::send()
{
  QString limit = m_options.value("limit", QVariant("25")).toString();

  QUrlQuery urlQuery;
  urlQuery.addQueryItem("limit", limit);

  QUrl url(QString("%1/molecules").arg(m_girderUrl));
  url.setQuery(urlQuery); // reconstructs the query string from the QUrlQuery

  QNetworkRequest request(url);

  // Only set the girder token if there is one
  if (!m_girderToken.isEmpty())
    request.setRawHeader(QByteArray("Girder-Token"), m_girderToken.toUtf8());

  auto reply = m_networkManager->get(request);
  connect(reply, &QNetworkReply::finished, this,
          &GetMoleculesRequest::finished);
}

static QString handleGirderError(QNetworkReply* reply, const QByteArray& bytes)
{
  QJsonDocument jsonResponse = QJsonDocument::fromJson(bytes.constData());

  QString errorMessage;

  if (!jsonResponse.isObject()) {
    errorMessage = reply->errorString();
  } else {
    const QJsonObject& object = jsonResponse.object();
    QString message = object.value("message").toString();
    if (!message.isEmpty())
      errorMessage = QString("Girder error: %1").arg(message);
    else
      errorMessage = QString(bytes);
  }

  return errorMessage;
}

} // namespace QtPlugins
} // namespace Avogadro
