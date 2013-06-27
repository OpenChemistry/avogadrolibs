/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2009 Marcus D. Hanwell
  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef NETWORKDATABASES_H
#define NETWORKDATABASES_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QString>

class QNetworkAccessManager;
class QNetworkReply;
class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {

class NetworkDatabases : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit NetworkDatabases(QObject *parent = 0);
  ~NetworkDatabases() AVO_OVERRIDE;

  QString name() const AVO_OVERRIDE { return tr("Network Databases"); }

  QString description() const AVO_OVERRIDE
  {
    return tr("Interact with online databases, query structures etc.");
  }

  QList<QAction *> actions() const AVO_OVERRIDE;

  QStringList menuPath(QAction *) const AVO_OVERRIDE;

public slots:
  void setMolecule(QtGui::Molecule *mol);
  bool readMolecule(QtGui::Molecule &mol);

private slots:
  void showDialog();
  void replyFinished(QNetworkReply*);

private:
  QAction *m_action;
  QtGui::Molecule *m_molecule;
  QNetworkAccessManager *m_network;
  QString m_moleculeName;
  QByteArray m_moleculeData;
  QProgressDialog *m_progressDialog;
};

}
}

#endif // NETWORKDATABASES_H
