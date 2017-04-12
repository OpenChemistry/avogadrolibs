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

#include "selectiontool.h"

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/scene.h>

#include <avogadro/core/array.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QtGui/QIcon>
#include <QtGui/QMouseEvent>
#include <QtWidgets/QAction>

using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

SelectionTool::SelectionTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_renderer(nullptr), m_drawSelectionBox(false)
{
  m_activateAction->setText(tr("Selection"));
  m_activateAction->setIcon(QIcon(":/icons/selectiontool.png"));
}

SelectionTool::~SelectionTool()
{
}

QWidget* SelectionTool::toolWidget() const
{
  return nullptr;
}

QUndoCommand* SelectionTool::mousePressEvent(QMouseEvent* e)
{
  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  m_drawSelectionBox = false;
  m_start = Vector2(e->pos().x(), e->pos().y());
  m_end = m_start;
  Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());

  // If an atom is clicked, accept the event, but don't add it to the atom list
  // until the button is released (this way the user can cancel the click by
  // moving off the atom, and the click won't get passed to the default tool).
  if (hit.type == Rendering::AtomType)
    e->accept();

  // Remove the global accept to prevent the rectangle selection area from being
  // rendered as the selection code is not yet in place for the scene.
  // e->accept();

  return nullptr;
}

QUndoCommand* SelectionTool::mouseReleaseEvent(QMouseEvent* e)
{
  // If the click is released on an atom, add it to the list
  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  m_drawSelectionBox = false;
  m_start = Vector2(e->pos().x(), e->pos().y());
  m_end = m_start;
  Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());

  // Now add the atom on release.
  if (hit.type == Rendering::AtomType) {
    if (addAtom(hit))
      emit drawablesChanged();
    e->accept();
  }

// Disable this code until rectange selection is ready.
#if 0
  emit drawablesChanged();
  e->accept();
#endif

  return nullptr;
}

QUndoCommand* SelectionTool::mouseDoubleClickEvent(QMouseEvent* e)
{
  // Reset the atom list
  if (e->button() == Qt::LeftButton && !m_atoms.isEmpty()) {
    m_atoms.clear();
    emit drawablesChanged();
    e->accept();
  }
  return nullptr;
}

QUndoCommand* SelectionTool::mouseMoveEvent(QMouseEvent*)
{
// Disable this code until rectange selection is ready.
#if 0
  m_drawSelectionBox = true;
  m_end = Vector2(e->pos().x(), e->pos().y());
  emit drawablesChanged();

  e->accept();
#endif
  return nullptr;
}

QUndoCommand* SelectionTool::keyPressEvent(QKeyEvent* e)
{
  return nullptr;
}

void SelectionTool::draw(Rendering::GroupNode& node)
{
  if (!m_drawSelectionBox) {
    node.clear();
    return;
  }

  GeometryNode* geo = new GeometryNode;
  node.addChild(geo);
  MeshGeometry* mesh = new MeshGeometry;

  mesh->setRenderPass(Rendering::Overlay2DPass);

  Array<Vector3f> verts(4);
  Vector3f start(m_start.x() < m_end.x() ? m_start.x() : m_end.x(),
                 m_start.y() < m_end.y() ? m_start.y() : m_end.y(), 0.0f);
  Vector3f end(m_start.x() > m_end.x() ? m_start.x() : m_end.x(),
               m_start.y() > m_end.y() ? m_start.y() : m_end.y(), 0.0f);
  start.y() = m_renderer->overlayCamera().height() - start.y();
  end.y() = m_renderer->overlayCamera().height() - end.y();

  verts[0] = Vector3f(start.x(), end.y(), 0.0f);
  verts[1] = Vector3f(end.x(), end.y(), 0.0f);
  verts[2] = Vector3f(start.x(), start.y(), 0.0f);
  verts[3] = Vector3f(end.x(), start.y(), 0.0f);

  const Vector3f normal = verts[0].cross(verts[1]).normalized();
  Array<Vector3f> norms(4, normal);

  Array<unsigned int> indices(6);
  indices[0] = 0;
  indices[1] = 1;
  indices[2] = 2;
  indices[3] = 2;
  indices[4] = 1;
  indices[5] = 3;

  mesh->setColor(Vector3ub(200, 200, 0));
  mesh->setOpacity(180);
  mesh->addVertices(verts, norms);
  mesh->addTriangles(indices);

  geo->addDrawable(mesh);
}

bool SelectionTool::addAtom(const Rendering::Identifier& atom)
{
  int idx = m_atoms.indexOf(atom);
  if (idx >= 0) {
    m_atoms.removeAt(idx);
    m_molecule->atom(atom.index).setSelected(false);
    return true;
  } else {
    m_atoms.push_back(atom);
    m_molecule->atom(atom.index).setSelected(true);
    return true;
  }
  m_molecule->emitChanged(Molecule::Atoms);
}

} // namespace QtPlugins
} // namespace Avogadro
