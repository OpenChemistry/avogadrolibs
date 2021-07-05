/*******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CRYSTAL_H
#define AVOGADRO_QTPLUGINS_CRYSTAL_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {
class UnitCellDialog;

/**
 * @brief Tools for crystal-specific editing/analysis.
 */
class Crystal : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Crystal(QObject* parent_ = nullptr);
  ~Crystal() override;

  QString name() const override { return tr("Crystal"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void importCrystalClipboard();
  void editUnitCell();
  void buildSupercell();
  void niggliReduce();
  void scaleVolume();
  void standardOrientation();
  void toggleUnitCell();
  void wrapAtomsToCell();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  UnitCellDialog* m_unitCellDialog;

  QAction* m_importCrystalClipboardAction;
  QAction* m_editUnitCellAction;
  QAction* m_buildSupercellAction;
  QAction* m_niggliReduceAction;
  QAction* m_scaleVolumeAction;
  QAction* m_standardOrientationAction;
  QAction* m_toggleUnitCellAction;
  QAction* m_wrapAtomsToCellAction;
};

inline QString Crystal::description() const
{
  return tr("Tools for crystal-specific editing/analysis.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CRYSTAL_H
