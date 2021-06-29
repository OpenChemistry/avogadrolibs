/*******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SYMMETRY_H
#define AVOGADRO_QTPLUGINS_SYMMETRY_H

#include <avogadro/qtgui/extensionplugin.h>

#include "symmetrywidget.h"

namespace msym {
extern "C"
{
#include <libmsym/msym.h>
}
}

namespace Avogadro {
namespace QtPlugins {
class SymmetryWidget;

/**
 * @brief symmetry functionality.
 */
class Symmetry : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Symmetry(QObject* parent_ = nullptr);
  ~Symmetry() override;

  QString name() const override { return tr("Symmetry"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void viewSymmetry();

  void detectSymmetry();

  void symmetrizeMolecule();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  SymmetryWidget* m_symmetryWidget;

  QAction* m_viewSymmetryAction;

  msym::msym_context m_ctx;

  bool m_dirty = true;
};

inline QString Symmetry::description() const
{
  return tr("Provide symmetry functionality.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SYMMETRY_H
