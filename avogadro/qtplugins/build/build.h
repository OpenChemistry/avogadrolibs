/*******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Albert DeFusco

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_BUILD_H
#define AVOGADRO_QTPLUGINS_BUILD_H

#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro {
namespace QtPlugins {
  class SuperCellDialog;
  class SlabDialog;

/**
 * @brief Tools for molecule editing/analysis.
 */
class Build : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Build(QObject *parent_ = 0);
  ~Build();

  QString name() const { return tr("Build"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction *) const;

public slots:
  void setMolecule(QtGui::Molecule *mol);

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void buildSuperCell();
  void buildSlab();

private:
  QList<QAction *> m_actions;
  QtGui::Molecule *m_molecule;

  SuperCellDialog *m_superCellDialog;
  SlabDialog *m_slabDialog;

  QAction *m_buildSuperCellAction;
  QAction *m_buildSlabAction;
};

inline QString Build::description() const
{
  return tr("Tools for molecule editing.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_BUILD_H
