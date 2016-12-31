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

#ifndef AVOGADRO_QTPLUGINS_MESHES_H
#define AVOGADRO_QTPLUGINS_MESHES_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render one or more triangular meshes.
 * @author Marcus D. Hanwell
 */
class Meshes : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Meshes(QObject *parent = 0);
  ~Meshes();

  void process(const Core::Molecule &molecule,
               Rendering::GroupNode &node) override;

  QString name() const { return tr("Meshes"); }

  QString description() const { return tr("Render triangle meshes."); }

  bool isEnabled() const;

  void setEnabled(bool enable);

private:
  bool m_enabled;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MESHES_H
