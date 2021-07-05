/*******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SPACEGROUP_H
#define AVOGADRO_QTPLUGINS_SPACEGROUP_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Space group features for crystals.
 */
class SpaceGroup : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit SpaceGroup(QObject* parent_ = nullptr);
  ~SpaceGroup();

  QString name() const { return tr("SpaceGroup"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction*) const;

public slots:
  void setMolecule(QtGui::Molecule* mol);

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void perceiveSpaceGroup();
  void reduceToPrimitive();
  void conventionalizeCell();
  void symmetrize();
  void fillUnitCell();
  void reduceToAsymmetricUnit();
  void setTolerance();

private:
  // Pop up a dialog box and ask the user to select a space group.
  // Returns the hall number for the selected space group.
  // Returns 0 if the user canceled.
  unsigned short selectSpaceGroup();
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  double m_spgTol;

  QAction* m_perceiveSpaceGroupAction;
  QAction* m_reduceToPrimitiveAction;
  QAction* m_conventionalizeCellAction;
  QAction* m_symmetrizeAction;
  QAction* m_fillUnitCellAction;
  QAction* m_reduceToAsymmetricUnitAction;
  QAction* m_setToleranceAction;
};

inline QString SpaceGroup::description() const
{
  return tr("Space group features for crystals.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SPACEGROUP_H
