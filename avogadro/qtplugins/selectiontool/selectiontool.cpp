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

#include "selectiontoolwidget.h"

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
using Avogadro::QtGui::Molecule;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::MeshGeometry;

namespace Avogadro {
namespace QtPlugins {

SelectionTool::SelectionTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_renderer(nullptr),
    m_toolWidget(new SelectionToolWidget(qobject_cast<QWidget*>(parent_))),
    m_drawSelectionBox(false)
{
  m_activateAction->setText(tr("Selection"));
  m_activateAction->setIcon(QIcon(":/icons/selectiontool.png"));

  connect(m_toolWidget, SIGNAL(colorApplied(Vector3ub)), this,
          SLOT(applyColor(Vector3ub)));
}

SelectionTool::~SelectionTool() {}

QWidget* SelectionTool::toolWidget() const
{
  return m_toolWidget;
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
  e->accept();

  return nullptr;
}

QUndoCommand* SelectionTool::mouseReleaseEvent(QMouseEvent* e)
{
  // If the click is released on an atom, add it to the list
  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  // Assess whether the selection box is big enough to use, or a mis-click.
  bool bigEnough = false;
  m_end = Vector2(e->pos().x(), e->pos().y());
  if (fabs(m_start.x() - m_end.x()) > 2 && fabs(m_start.y() - m_end.y()) > 2)
    bigEnough = true;

  if (m_drawSelectionBox && bigEnough) {
    auto hits =
      m_renderer->hits(m_start.x(), m_start.y(), m_end.x(), m_end.y());

    // Toggle the selection if the Ctrl modifier is pressed.
    if (e->modifiers() & Qt::ControlModifier) {
      for (auto it = hits.begin(); it != hits.end(); ++it) {
        toggleAtom(*it);
      }
    } else {
      // If the shift modifier is not pressed clear the previous selection.
      if (!(e->modifiers() & Qt::ShiftModifier)) {
        clearAtoms();
      }
      for (auto it = hits.begin(); it != hits.end(); ++it) {
        addAtom(*it);
      }
    }
  } else {
    // Single click
    m_start = Vector2(e->pos().x(), e->pos().y());
    m_end = m_start;
    Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());

    // Now add the atom on release.
    if (hit.type == Rendering::AtomType) {
      toggleAtom(hit);
    }
  }

  m_drawSelectionBox = false;

  // Disable this code until rectangle selection is ready.
  emit drawablesChanged();
  e->accept();

  return nullptr;
}

QUndoCommand* SelectionTool::mouseDoubleClickEvent(QMouseEvent* e)
{
  // Reset the atom list
  if (e->button() == Qt::LeftButton) {
    clearAtoms();
    emit drawablesChanged();
    e->accept();
  }
  return nullptr;
}

QUndoCommand* SelectionTool::mouseMoveEvent(QMouseEvent* e)
{
  // Disable this code until rectangle selection is ready.
  m_drawSelectionBox = true;
  m_end = Vector2(e->pos().x(), e->pos().y());
  emit drawablesChanged();

  e->accept();
  return nullptr;
}

QUndoCommand* SelectionTool::keyPressEvent(QKeyEvent*)
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

void SelectionTool::applyColor(Vector3ub color)
{
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    auto a = m_molecule->atom(i);
    if (a.selected())
      a.setColor(color);
  }
  m_molecule->emitChanged(Molecule::Atoms);
}

void SelectionTool::clearAtoms()
{
  for (Index i = 0; i < m_molecule->atomCount(); ++i)
    m_molecule->atom(i).setSelected(false);
}

bool SelectionTool::addAtom(const Rendering::Identifier& atom)
{
  m_molecule->atom(atom.index).setSelected(true);
  return true;
}

bool SelectionTool::removeAtom(const Rendering::Identifier& atom)
{
  m_molecule->atom(atom.index).setSelected(false);
  return true;
}

bool SelectionTool::toggleAtom(const Rendering::Identifier& atom)
{
  Atom a = m_molecule->atom(atom.index);
  a.setSelected(!a.selected());
  return true;
}

} // namespace QtPlugins
} // namespace Avogadro
