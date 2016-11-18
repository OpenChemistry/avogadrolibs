/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  Adapted from Avogadro 1.x with the following authors' permission:
  Copyright 2007 Donald Ephraim Curtis
  Copyright 2008 Marcus D. Hanwell

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
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/core/avogadrocore.h>

#include <QtCore/QVector>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief MeasureTool displays distances and angles between selected atoms.
 *
 * Based on the Avogadro 1.x implementation by Donald Ephraim Curtis and Marcus
 * D. Hanwell.
 */
class MeasureTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit MeasureTool(QObject *parent_ = NULL);
  ~MeasureTool();

  QString name() const AVO_OVERRIDE { return tr("Measure tool"); }
  QString description() const AVO_OVERRIDE { return tr("Measure tool"); }
  unsigned char priority() const AVO_OVERRIDE { return 60; }
  QAction * activateAction() const AVO_OVERRIDE { return m_activateAction; }
  QWidget * toolWidget() const AVO_OVERRIDE;

  void setMolecule(QtGui::Molecule *) AVO_OVERRIDE;
  void setEditMolecule(QtGui::RWMolecule *) AVO_OVERRIDE;
  void setGLRenderer(Rendering::GLRenderer *renderer) AVO_OVERRIDE;

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
  template<typename T> void createLabels(T *mol, Rendering::GeometryNode *geo,
                                         QVector<Vector3> &positions);

  QAction *m_activateAction;
  QtGui::Molecule *m_molecule;
  QtGui::RWMolecule *m_rwMolecule;
  Rendering::GLRenderer *m_renderer;
  QVector<Rendering::Identifier> m_atoms;
};

inline void MeasureTool::setMolecule(QtGui::Molecule *mol)
{
  if (m_molecule != mol) {
    m_atoms.clear();
    m_molecule = mol;
    m_rwMolecule = NULL;
  }
}

inline void MeasureTool::setEditMolecule(QtGui::RWMolecule *mol)
{
  if (m_rwMolecule != mol) {
    m_atoms.clear();
    m_rwMolecule = mol;
    m_molecule = NULL;
  }
}

inline void MeasureTool::setGLRenderer(Rendering::GLRenderer *renderer)
{
  m_renderer = renderer;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MEASURETOOL_H
