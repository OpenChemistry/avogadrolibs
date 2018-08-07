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

#ifndef AVOGADRO_QTPLUGINS_PLUGINDOWNLOADER_H
#define AVOGADRO_QTPLUGINS_PLUGINDOWNLOADER_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QString>

class QNetworkAccessManager;
class QNetworkReply;
class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Downlaods Github repos and extracts their contents into a Avogadro
 * folder for plugins, molecule data, etc..
 */

class PluginDownloader : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit PluginDownloader(QObject* parent = 0);
  ~PluginDownloader() override;

  QString name() const override { return tr("Plugin Downloader"); }

  QString description() const override
  {
    return tr("Downloader plugins from Github repositories.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void showDialog();
  void replyFinished(QNetworkReply*);

private:
  QAction* m_action;
  QtGui::Molecule* m_molecule;
  QNetworkAccessManager* m_network;
  QString m_moleculeName;
};
}
}

#endif // AVOGADRO_QTPLUGINS_PLUGINDOWNLOADER_H
