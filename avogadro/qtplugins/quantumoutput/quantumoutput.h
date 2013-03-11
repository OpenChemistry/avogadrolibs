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

#ifndef AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H
#define AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H

#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;
class QProgressDialog;

namespace Avogadro {

namespace QtGui {
class Cube;
class Mesh;
class MeshGenerator;
}
namespace Quantum {
class BasisSet;
}

namespace QtPlugins {

class QuantumOutput : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit QuantumOutput(QObject *parent = 0);
  ~QuantumOutput();

  QString name() const { return tr("Quantum output"); }

  QString description() const { return tr("Read output from quantum codes."); }

  QList<QAction *> actions() const;

  QStringList menuPath(QAction *) const;

  void setMolecule(QtGui::Molecule *mol);

  bool readMolecule(QtGui::Molecule &mol);

private slots:
  void loadMoleculeActivated();
  void homoActivated();
  void lumoActivated();
  void calculateFinished();
  void meshFinished();

private:
  QList<QAction *>    m_actions;
  QProgressDialog    *m_progressDialog;

  QtGui::Molecule    *m_molecule;
  Quantum::BasisSet  *m_basis;

  QtGui::Cube        *m_cube;
  QtGui::Mesh        *m_mesh1;
  QtGui::Mesh        *m_mesh2;
  QtGui::MeshGenerator *m_meshGenerator;
  QtGui::MeshGenerator *m_meshGenerator2;

  void openFile(const QString &fileName);
  void calculateMolecularOrbital(int number);
};

}
}

#endif // AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H
