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

#ifndef AVOGADRO_QTPLUGINS_BALLANDSTICK_H
#define AVOGADRO_QTPLUGINS_BALLANDSTICK_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render a molecule in the ball and stick style.
 * @author David C. Lonie
 */
class BallAndStick : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit BallAndStick(QObject *parent = 0);
  ~BallAndStick();

  void process(const Core::Molecule &molecule,
               Rendering::GroupNode &node) AVO_OVERRIDE;

  QString name() const { return tr("Ball and Stick"); }

  QString description() const { return tr("Render atoms as spheres and bonds "
                                          "as cylinders."); }

  bool isEnabled() const;

  void setEnabled(bool enable);

private:
  bool m_enabled;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_BALLANDSTICK_H
