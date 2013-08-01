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

#ifndef AVOGADRO_QTPLUGINS_BONDCENTRICTOOL_H
#define AVOGADRO_QTPLUGINS_BONDCENTRICTOOL_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/rendering/primitive.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QVector>

namespace Avogadro {
namespace QtPlugins {

/**
 * @class BondCentricTool bondcentrictool.h
 * <avogadro/qtplugins/measuretool/bondcentrictool.h>
 * @brief BondCentricTool manipulates molecular geometry by adjusting bond
 * angles/lengths.
 *
 * @note This class is inspired by the class of the same name in Avogadro 1.x,
 * written by Shahzad Ali, Ross Braithwaite, and James Bunt.
 */
class BondCentricTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit BondCentricTool(QObject *parent_ = NULL);
  ~BondCentricTool();

  QString name() const AVO_OVERRIDE;
  QString description() const AVO_OVERRIDE;
  QAction * activateAction() const AVO_OVERRIDE { return m_activateAction; }
  QWidget * toolWidget() const AVO_OVERRIDE;

  void setMolecule(QtGui::Molecule *) AVO_OVERRIDE;
  void setGLWidget(QtOpenGL::GLWidget *widget) AVO_OVERRIDE;

  QUndoCommand * mousePressEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseMoveEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseReleaseEvent(QMouseEvent *e) AVO_OVERRIDE;

  void draw(Rendering::GroupNode &node) AVO_OVERRIDE;

private:
  QAction *m_activateAction;
  QtGui::Molecule *m_molecule;
  QtOpenGL::GLWidget *m_glWidget;
  QVector<Rendering::Identifier> m_atoms;

  // Use to hold private convenience drawable subclasses.
  class DrawablePIMPL;
  DrawablePIMPL *m_drawables;
};

inline QString BondCentricTool::name() const
{
  return tr("Bond centric manipulation tool.");
}

inline QString BondCentricTool::description() const
{
  return tr("Tool used to edit molecular geometry by changing bond lengths and "
            "angles.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_BONDCENTRICTOOL_H
