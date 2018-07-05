/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2017 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_DOWNLOADERWIDGET_H
#define AVOGADRO_DOWNLOADERWIDGET_H

#include <QtCore/QList>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

#include <QtWidgets/QDialog>

#include <json/json.h>

class QNetworkAccessManager;
class QNetworkReply;

namespace Ui {
class DownloaderWidget;
}

namespace Avogadro {

namespace QtPlugins {

class DownloaderWidget : public QDialog
{
  Q_OBJECT

public:
  DownloaderWidget(QWidget* parent = 0);
  ~DownloaderWidget() override;

public slots:
  void showREADME();
  void downloadREADME(int, int);
  void updateRepoData();
  void getCheckedRepos();
  void handleRedirect();
  void unzipPlugin();

private:
  struct repo
  {
    QString name;
    QString description;
    QString releaseVersion;
    QString type;
    QString updatedAt;
    QString zipballUrl;
    QString readmeUrl;
    bool hasRelease;
  };

  struct downloadEntry
  {
    QString url;
    QString name;
    QString type;
  };

  void downloadNextPlugin();
  void getRepoData();
  void downloadNext();
  bool checkSHA1(QByteArray);

  struct repo* m_repoList;
  Ui::DownloaderWidget* m_ui;
  QNetworkAccessManager* m_NetworkAccessManager;
  QNetworkReply* m_reply;
  /** Jsoncpp reader to read JSON results */
  Json::Reader* m_read;
  /** Holds a node of JSON results */
  Json::Value m_root;
  /** Used to parse JSON results */
  QVariantMap m_jsonResult;

  QString m_filePath;

  QList<downloadEntry> m_downloadList;
  int m_numRepos;
};
}
}
#endif // AVOGADRO_DOWNLOADERWIDGET_H
