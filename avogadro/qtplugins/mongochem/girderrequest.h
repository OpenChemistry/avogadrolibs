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

#ifndef AVOGADRO_QTPLUGINS_GIRDERREQUEST_H
#define AVOGADRO_QTPLUGINS_GIRDERREQUEST_H

#include <QString>
#include <QVariantMap>

class QNetworkAccessManager;
class QNetworkReply;

namespace Avogadro {

namespace QtPlugins {

class GirderRequest : public QObject
{
  Q_OBJECT

public:
  GirderRequest(QNetworkAccessManager* networkManager, const QString& girderUrl,
                const QString& girderToken,
                const QVariantMap& options = QVariantMap(),
                QObject* parent = nullptr);
  virtual ~GirderRequest() = default;

  void virtual send() = 0;

signals:
  // Emitted when there is an error
  void error(const QString& msg, QNetworkReply* networkReply = nullptr);
  // Emitted when there are results
  void result(const QVariantMap& results);

protected slots:
  void finished();

protected:
  QString m_girderUrl;
  QString m_girderToken;
  QVariantMap m_options;
  QNetworkAccessManager* m_networkManager;
};

class GetMoleculesRequest : public GirderRequest
{
  Q_OBJECT

public:
  GetMoleculesRequest(QNetworkAccessManager* networkManager,
                      const QString& girderUrl, const QString& girderToken,
                      const QVariantMap& options = QVariantMap(),
                      QObject* parent = nullptr)
    : GirderRequest(networkManager, girderUrl, girderToken, options, parent)
  {}

  void send();
};

} // namespace QtPlugins
} // namespace Avogadro

#endif
