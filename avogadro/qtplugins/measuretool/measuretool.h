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

#include <avogadro/core/avogadrocore.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/primitive.h>

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
  explicit MeasureTool(QObject* parent_ = nullptr);
  ~MeasureTool() override;

  QString name() const override { return tr("Measure tool"); }
  QString description() const override { return tr("Measure tool"); }
  unsigned char priority() const override { return 60; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  void setMolecule(QtGui::Molecule*) override;
  void setEditMolecule(QtGui::RWMolecule*) override;
  void setGLRenderer(Rendering::GLRenderer* renderer) override;

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

private:
  Vector3ub contrastingColor(const Vector3ub& rgb) const;
  bool toggleAtom(const Rendering::Identifier& atom);
  template<typename T>
  void createLabels(T* mol, Rendering::GeometryNode* geo,
                    QVector<Vector3>& positions);

  QAction* m_activateAction;
  QtGui::Molecule* m_molecule;
  QtGui::RWMolecule* m_rwMolecule;
  Rendering::GLRenderer* m_renderer;
  QVector<Rendering::Identifier> m_atoms;
};

inline void MeasureTool::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule != mol) {
    m_atoms.clear();
    m_molecule = mol;
    m_rwMolecule = nullptr;
  }
}

inline void MeasureTool::setEditMolecule(QtGui::RWMolecule* mol)
{
  if (m_rwMolecule != mol) {
    m_atoms.clear();
    m_rwMolecule = mol;
    m_molecule = nullptr;
  }
}

inline void MeasureTool::setGLRenderer(Rendering::GLRenderer* renderer)
{
  m_renderer = renderer;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MEASURETOOL_H
