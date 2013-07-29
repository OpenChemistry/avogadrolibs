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

#ifndef AVOGADRO_QTPLUGINS_MEASURETOOL_H
#define AVOGADRO_QTPLUGINS_MEASURETOOL_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/rendering/primitive.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QVector>

namespace Avogadro {
namespace QtPlugins {

/**
 * @class MeasureTool measuretool.h
 * <avogadro/qtplugins/measuretool/measuretool.h>
 * @brief MeasureTool displays distances and angles between selected atoms.
 */
class MeasureTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit MeasureTool(QObject *parent_ = NULL);
  ~MeasureTool();

  QString name() const AVO_OVERRIDE { return tr("Measure tool"); }
  QString description() const AVO_OVERRIDE { return tr("Measure tool"); }
  QAction * activateAction() const AVO_OVERRIDE { return m_activateAction; }
  QWidget * toolWidget() const AVO_OVERRIDE;

  void setMolecule(QtGui::Molecule *) AVO_OVERRIDE { m_atoms.clear(); }
  void setGLWidget(QtOpenGL::GLWidget *widget) AVO_OVERRIDE;

  QUndoCommand * mousePressEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseReleaseEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseDoubleClickEvent(QMouseEvent *e) AVO_OVERRIDE;

  void draw(Rendering::GroupNode &node) AVO_OVERRIDE;

private:
  Vector3ub contrastingColor(const Vector3ub &rgb) const;
  // for four atoms a,b,c,d, b1 = b-a, b2 = c-b, b3 = d-c. Returns degrees.
  float dihedralAngle(const Vector3 &b1, const Vector3 &b2,
                      const Vector3 &b3) const;
  bool toggleAtom(const Rendering::Identifier &atom);
  QAction *m_activateAction;
  QtOpenGL::GLWidget *m_glWidget;
  QVector<Rendering::Identifier> m_atoms;
};

inline void MeasureTool::setGLWidget(QtOpenGL::GLWidget *widget)
{
  m_glWidget = widget;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MEASURETOOL_H
