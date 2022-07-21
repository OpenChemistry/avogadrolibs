/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_GIRDERREQUEST_H
#define AVOGADRO_QTPLUGINS_GIRDERREQUEST_H

#include <QList>
#include <QNetworkRequest>
#include <QPair>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;

namespace Avogadro {

namespace QtPlugins {

class GirderRequest : public QObject
{
  Q_OBJECT

public:
  GirderRequest(QNetworkAccessManager* networkManager, const QString& girderUrl,
                const QString& girderToken = "", QObject* parent = nullptr);

  // Calls the respective HTTP method on the girder url
  void get();
  void post(const QByteArray& data);
  void put(const QByteArray& data);

  void setUrlQueries(const QList<QPair<QString, QString>>& queries)
  {
    m_urlQueries = queries;
  }

  void setHeader(QNetworkRequest::KnownHeaders header, const QVariant& value)
  {
    m_headers[header] = value;
  }

signals:
  // Emitted when there is an error
  void error(const QString& msg, QNetworkReply* networkReply = nullptr);
  // Emitted when there are results
  void result(const QVariant& results);

protected slots:
  void onFinished();

protected:
  QString m_girderUrl;
  QString m_girderToken;
  QNetworkAccessManager* m_networkManager;
  QList<QPair<QString, QString>> m_urlQueries;
  QMap<QNetworkRequest::KnownHeaders, QVariant> m_headers;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif
