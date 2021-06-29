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

#include <avogadro/core/avogadrocore.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtNetwork/QNetworkReply>

#include <QtCore/QString>

class QAction;
class QDialog;

namespace Avogadro {

namespace QtPlugins {

class PQRWidget;

class ImportPQR : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ImportPQR(QObject* parent = nullptr);
  ~ImportPQR() override;

  QString name() const override { return tr("Import From PQR"); }

  QString description() const override
  {
    return tr("Download a molecule from PQR.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMoleculeData(QByteArray& molData, QString name);

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void menuActivated();

private:
  QAction* m_action;
  QtGui::Molecule* m_molecule;
  PQRWidget* m_dialog;
  const Io::FileFormat* m_outputFormat;
  QString m_moleculeName;
  QString m_moleculePath;
  QByteArray m_moleculeData;
};
}
}

#endif // AVOGADRO_QTPLUGINS_IMPORTPQR_H
