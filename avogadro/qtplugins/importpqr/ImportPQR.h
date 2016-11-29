/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_IMPORTPQR_H
#define AVOGADRO_QTPLUGINS_IMPORTPQR_H

#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;

namespace MoleQueue {
class JobObject;
}

namespace Avogadro {
namespace Io {
class FileFormat;
}

namespace QtPlugins {

class PQRWidget;

class ImportPQR : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ImportPQR(QObject *parent = 0);
  ~ImportPQR();

  QString name() const { return tr("Import From PQR"); }

  QString description() const { return tr("Download a molecule from PQR."); }

  QList<QAction *> actions() const;

  QStringList menuPath(QAction *) const;

  void setMolecule(QtGui::Molecule *mol);

public slots:
  /**
   * Emitted when the user requests that a job's output be loaded in Avogadro.
   */
  void openJobOutput(const MoleQueue::JobObject &job);

  bool readMolecule(QtGui::Molecule &mol);

private slots:
  void menuActivated();

private:
  QAction *m_action;
  QtGui::Molecule *m_molecule;
  PQRWidget *m_dialog;
  const Io::FileFormat *m_outputFormat;
  QString m_outputFileName;
};

}
}

#endif // AVOGADRO_QTPLUGINS_IMPORTPQR_H
