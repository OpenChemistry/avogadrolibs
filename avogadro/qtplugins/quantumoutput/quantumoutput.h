/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2013 Kitware, Inc.

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
namespace Core {
class BasisSet;
}

namespace QtPlugins {

class GaussianSetConcurrent;
class SlaterSetConcurrent;
class SurfaceDialog;

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

private slots:
  void homoActivated();
  void lumoActivated();
  void surfacesActivated();
  void calculateFinished();
  void meshFinished();
  void calculateMolecularOrbital(int molecularOrbital, float isoValue,
                                 float stepSize);
  void calculateElectronDensity(float isoValue, float stepSize);

private:
  QList<QAction *>    m_actions;
  QProgressDialog    *m_progressDialog;

  QtGui::Molecule    *m_molecule;
  Core::BasisSet     *m_basis;

  GaussianSetConcurrent *m_concurrent;
  SlaterSetConcurrent *m_concurrent2;

  QtGui::Cube        *m_cube;
  QtGui::Mesh        *m_mesh1;
  QtGui::Mesh        *m_mesh2;
  QtGui::MeshGenerator *m_meshGenerator1;
  QtGui::MeshGenerator *m_meshGenerator2;

  float m_isoValue;

  SurfaceDialog *m_dialog;
};

}
}

#endif // AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H
