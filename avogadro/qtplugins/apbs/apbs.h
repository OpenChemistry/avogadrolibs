/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_APBS_APBS_H
#define AVOGADRO_QTPLUGINS_APBS_APBS_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {
class ApbsDialog;

/**
 * @brief The Apbs class provides integration with the APBS package, primarily
 * reading the OpenDX output files produced by it at this point.
 */

class Apbs : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Apbs(QObject* parent_ = nullptr);
  ~Apbs() override;

  QString name() const override { return tr("APBS"); }
  QString description() const override
  {
    return tr("Interact with APBS utilities.");
  }
  QList<QAction*> actions() const override { return m_actions; }
  QStringList menuPath(QAction*) const override;
  void setMolecule(QtGui::Molecule*) override;
  bool readMolecule(QtGui::Molecule&) override;

private slots:
  void onOpenOutputFile();
  void onMeshGeneratorProgress(int value);
  void meshGeneratorFinished();
  void onRunApbs();

private:
  /**
   * Loads the cube from the OpenDX file and adds the meshes to the molecule.
   */
  bool loadOpenDxFile(const QString& fileName, QtGui::Molecule& molecule);

private:
  QtGui::Molecule* m_molecule;
  QList<QAction*> m_actions;
  QProgressDialog* m_progressDialog;
  ApbsDialog* m_dialog;
  QString m_pqrFileName;
  QString m_cubeFileName;
};
}
}

#endif // AVOGADRO_QTPLUGINS_APBS_APBS_H
