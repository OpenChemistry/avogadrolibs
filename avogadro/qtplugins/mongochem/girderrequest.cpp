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

namespace Avogadro {

namespace QtPlugins {

// Some function declarations
static QString handleGirderError(QNetworkReply* reply, const QByteArray& bytes);

GirderRequest::GirderRequest(QNetworkAccessManager* networkManager,
                             const QString& girderUrl,
                             const QString& girderToken, QObject* parent)
  : QObject(parent), m_girderUrl(girderUrl), m_girderToken(girderToken),
    m_networkManager(networkManager)
{}

void GirderRequest::get()
{
  QUrl url(m_girderUrl);

  if (!m_urlQueries.isEmpty()) {
    // For Qt>=5.13, we can initialize QUrlQuery with m_urlQueries
    QUrlQuery query;
    query.setQueryItems(m_urlQueries);
    url.setQuery(query);
  }

  QNetworkRequest request(url);

  // Only set the girder token if there is one
  if (!m_girderToken.isEmpty())
    request.setRawHeader(QByteArray("Girder-Token"), m_girderToken.toUtf8());

  for (auto key : m_headers.keys())
    request.setHeader(key, m_headers[key]);

  auto reply = m_networkManager->get(request);
  connect(reply, &QNetworkReply::finished, this, &GirderRequest::onFinished);

  // Delete it after all the connected slots have been called
  connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

void GirderRequest::post(const QByteArray& data)
{
  QUrl url(m_girderUrl);

  if (!m_urlQueries.isEmpty()) {
    // For Qt>=5.13, we can initialize QUrlQuery with m_urlQueries
    QUrlQuery query;
    query.setQueryItems(m_urlQueries);
    url.setQuery(query);
  }

  QNetworkRequest request(url);

  if (!m_girderToken.isEmpty())
    request.setRawHeader(QByteArray("Girder-Token"), m_girderToken.toUtf8());

  for (auto key : m_headers.keys())
    request.setHeader(key, m_headers[key]);

  auto reply = m_networkManager->post(request, data);

  connect(reply, &QNetworkReply::finished, this, &GirderRequest::onFinished);

  // Delete it after all the connected slots have been called
  connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

void GirderRequest::put(const QByteArray& data)
{
  QUrl url(m_girderUrl);

  if (!m_urlQueries.isEmpty()) {
    // For Qt>=5.13, we can initialize QUrlQuery with m_urlQueries
    QUrlQuery query;
    query.setQueryItems(m_urlQueries);
    url.setQuery(query);
  }

  QNetworkRequest request(url);

  if (!m_girderToken.isEmpty())
    request.setRawHeader(QByteArray("Girder-Token"), m_girderToken.toUtf8());

  for (auto key : m_headers.keys())
    request.setHeader(key, m_headers[key]);

  auto reply = m_networkManager->put(request, data);

  connect(reply, &QNetworkReply::finished, this, &GirderRequest::onFinished);

  // Delete it after all the connected slots have been called
  connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

void GirderRequest::onFinished()
{
  auto* reply = qobject_cast<QNetworkReply*>(this->sender());
  QByteArray bytes = reply->readAll();
  if (reply->error()) {
    emit error(handleGirderError(reply, bytes), reply);
  } else {
    QJsonDocument jsonResponse = QJsonDocument::fromJson(bytes.constData());
    emit result(jsonResponse.toVariant());
  }
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
