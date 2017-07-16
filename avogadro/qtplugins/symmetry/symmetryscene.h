/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SYMMETRYSCENE_H
#define AVOGADRO_QTPLUGINS_SYMMETRYSCENE_H

#include <avogadro/qtgui/sceneplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render the symmetry elements
 */
class SymmetryScene : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit SymmetryScene(QObject* parent = 0);
  ~SymmetryScene() override;

  void process(const Core::Molecule& molecule,
               Rendering::GroupNode& node) override;

  void processEditable(const QtGui::RWMolecule& molecule,
                       Rendering::GroupNode& node) override;

  QString name() const { return tr("Symmetry Elements"); }

  QString description() const { return tr("Render symmetry elements."); }

  bool isEnabled() const;

  void setEnabled(bool enable);

private:
  bool m_enabled;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SYMMETRYSCENE_H
