/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLAYERTOOL_H
#define AVOGADRO_QTPLUGINS_PLAYERTOOL_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QTimer>

class QLabel;
class QSpinBox;
class QCheckBox;
class QGLWidget;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief PlayerTool enables playback of trajectories.
 */
class PlayerTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit PlayerTool(QObject* p = nullptr);
  ~PlayerTool();

  QString name() const override { return tr("Player tool"); }
  QString description() const override { return tr("Play back trajectories"); }
  unsigned char priority() const override { return 80; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;

public slots:
  void setMolecule(QtGui::Molecule*) override;
  void setGLRenderer(Rendering::GLRenderer* renderer) override;
  void setActiveWidget(QWidget* widget) override;

protected slots:
  void back();
  void forward();
  void play();
  void stop();
  void animate(int advance = 1);

  void recordMovie();

private:
  QAction* m_activateAction;
  QtGui::Molecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  int m_currentFrame;
  mutable QWidget* m_toolWidget;
  QTimer m_timer;
  mutable QLabel* m_info;
  mutable QSpinBox* m_animationFPS;
  mutable QCheckBox* m_dynamicBonding;
  mutable QGLWidget* m_glWidget;
};

inline void PlayerTool::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule != mol) {
    m_molecule = mol;
    m_currentFrame = 0;
  }
}

inline void PlayerTool::setGLRenderer(Rendering::GLRenderer* renderer)
{
  m_renderer = renderer;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLAYERTOOL_H
