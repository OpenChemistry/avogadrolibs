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
#include <avogadro/qtgui/rwlayermanager.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QDebug>
#include <QtGui/QIcon>
#include <QtGui/QMouseEvent>
#include <QtWidgets/QAction>

#include <queue>
#include <set>

using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::PluginLayerManager;
using Avogadro::QtGui::RWMolecule;
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
    m_drawSelectionBox(false), m_doubleClick(false), m_initSelectionBox(false),
    m_layerManager("Selection Tool")
{
  m_activateAction->setText(tr("Selection"));
  m_activateAction->setIcon(QIcon(":/icons/selectiontool.png"));
  m_activateAction->setToolTip(
    tr("Selection Tool\n\n"
       "Left Mouse: \tClick to pick individual atoms, residues, or fragments\n"
       "\tDrag to select a range of atoms\n"
       "Right Mouse: \tClick outside the molecule to clear selection\n"
       "Use Ctrl to toggle the selection and shift to add to the selection.\n"
       "Double-Click: \tSelect an entire fragment."));

  connect(m_toolWidget, SIGNAL(colorApplied(Vector3ub)), this,
          SLOT(applyColor(Vector3ub)));
  connect(m_toolWidget, SIGNAL(changeLayer(int)), this, SLOT(applyLayer(int)));
}

SelectionTool::~SelectionTool() {}

QWidget* SelectionTool::toolWidget() const
{
  return m_toolWidget;
}

QUndoCommand* SelectionTool::mousePressEvent(QMouseEvent* e)
{
  if (e->button() != Qt::LeftButton || !m_renderer) {
    m_initSelectionBox = false;
    return nullptr;
  }

  m_drawSelectionBox = false;
  m_initSelectionBox = true;
  m_start = Vector2(e->pos().x(), e->pos().y());
  m_end = m_start;
  e->accept();
  return nullptr;
}

QUndoCommand* SelectionTool::mouseReleaseEvent(QMouseEvent* e)
{
  // If the click is released on an atom, add it to the list
  if (e->button() != Qt::LeftButton || !m_renderer || m_doubleClick) {
    m_doubleClick = false;
    return nullptr;
  }
  // Assess whether the selection box is big enough to use, or a mis-click.
  m_end = Vector2(e->pos().x(), e->pos().y());
  Vector2f start(m_start.x() < m_end.x() ? m_start.x() : m_end.x(),
                 m_start.y() < m_end.y() ? m_start.y() : m_end.y());
  Vector2f end(m_start.x() > m_end.x() ? m_start.x() : m_end.x(),
               m_start.y() > m_end.y() ? m_start.y() : m_end.y());
  bool bigEnough =
    fabs(start.x() - end.x()) > 2 && fabs(start.y() - end.y()) > 2;

  bool anySelect = false;
  Index selectedIndex = MaxIndex;
  if (m_drawSelectionBox && bigEnough) {
    shouldClean(e);
    m_initSelectionBox = false;
    auto hits = m_renderer->hits(start.x(), start.y(), end.x(), end.y());
    for (const auto& hit : hits) {
      if (hit.type == Rendering::AtomType) {
        anySelect = selectAtom(e, hit.index) || anySelect;
        selectedIndex = hit.index;
      }
    }
  } else {
    // Single click
    m_start = Vector2(e->pos().x(), e->pos().y());
    m_end = m_start;
    Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());
    // Now add the atom on release.
    if (hit.type == Rendering::AtomType) {
      // store the result in case it's a toggle
      bool selected = selectAtom(e, hit.index);
      shouldClean(e);
      if (selected) {
        anySelect = addAtom(hit.index);
        selectedIndex = hit.index;
      } else {
        anySelect = removeAtom(hit.index);
        selectedIndex = hit.index;
      }
    }
  }
  if (anySelect) {
    m_toolWidget->setDropDown(m_layerManager.getLayerID(selectedIndex),
                              m_layerManager.layerCount());
  }
  m_drawSelectionBox = false;
  // Disable this code until rectangle selection is ready.
  emit drawablesChanged();
  e->accept();
  return nullptr;
}

QUndoCommand* SelectionTool::mouseDoubleClickEvent(QMouseEvent* e)
{
  if (e->button() == Qt::LeftButton) {
    m_doubleClick = true;
    m_initSelectionBox = false;
    Vector2 select = Vector2(e->pos().x(), e->pos().y());
    Identifier hit = m_renderer->hit(select.x(), select.y());
    // Reset the atom list
    if (!hit.isValid()) {
      clearAtoms();
    } else {
      shouldClean(e);
      m_drawSelectionBox = false;
      // resync the select from simple click only on control
      if (e->modifiers() & Qt::ControlModifier) {
        toggleAtom(hit.index);
      }
      selectLinkedMolecule(e, hit.index);
      emit drawablesChanged();
      e->accept();
    }
  }
  return nullptr;
} // namespace QtPlugins

QUndoCommand* SelectionTool::mouseMoveEvent(QMouseEvent* e)
{
  // Disable this code until rectangle selection is ready.
  if (m_initSelectionBox) {
    m_drawSelectionBox = true;
    m_end = Vector2(e->pos().x(), e->pos().y());
    emit drawablesChanged();
    e->accept();
  }
  return nullptr;
}

QUndoCommand* SelectionTool::keyPressEvent(QKeyEvent*)
{
  return nullptr;
}

void SelectionTool::draw(Rendering::GroupNode& node)
{
  if (!m_drawSelectionBox || !m_initSelectionBox) {
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
  RWMolecule* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Paint Atoms"));
  for (Index i = 0; i < rwmol->atomCount(); ++i) {
    auto a = rwmol->atom(i);
    if (a.selected())
      a.setColor(color);
  }
  rwmol->endMergeMode();
  rwmol->emitChanged(Molecule::Atoms | Molecule::Modified);
}

void SelectionTool::applyLayer(int layer)
{
  if (layer < 0) {
    return;
  }
  RWMolecule* rwmol = m_molecule->undoMolecule();
  rwmol->beginMergeMode(tr("Change Layer"));
  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;

  // qDebug() << "SelectionTool::applyLayer" << layer << " layerCount " << m_layerManager.layerCount();
  if (layer >= m_layerManager.layerCount()) {
    // add a new layer
    auto& layerInfo = Core::LayerManager::getMoleculeInfo(m_molecule)->layer;
    const auto activeLayer = layerInfo.activeLayer();
    QtGui::RWLayerManager rwLayerManager;
    rwLayerManager.addLayer(rwmol);
    layer = layerInfo.maxLayer();

    // check to enable the same rendering in this new layer
    // qDebug() << "SelectionTool::applyLayer: " << activeLayer << " " << layer;
    auto moleculeInfo = Core::LayerManager::getMoleculeInfo(m_molecule);
    for (const auto& names : moleculeInfo->enable) {
      auto values = names.second;
      bool value = values[activeLayer];
      values.push_back(value);

      moleculeInfo->enable[names.first] = values;
    }

    // update the menu too
    m_toolWidget->setDropDown(layer, m_layerManager.layerCount());
    changes |= Molecule::Layers | Molecule::Added;
  }

  for (Index i = 0; i < rwmol->atomCount(); ++i) {
    auto a = rwmol->atom(i);
    if (a.selected()) {
      a.setLayer(layer);
    }
  }
  rwmol->endMergeMode();
  rwmol->emitChanged(changes);
}

void SelectionTool::selectLinkedMolecule(QMouseEvent* e, Index atom)
{
  auto connectedAtoms = m_molecule->graph().connectedComponent(atom);
  for (auto a : connectedAtoms) {
    selectAtom(e, a);
  }
}

void SelectionTool::clearAtoms()
{
  for (Index i = 0; i < m_molecule->atomCount(); ++i)
    m_molecule->atom(i).setSelected(false);
}

bool SelectionTool::addAtom(const Index& atom)
{
  m_molecule->atom(atom).setSelected(true);
  return true;
}

bool SelectionTool::removeAtom(const Index& atom)
{
  m_molecule->atom(atom).setSelected(false);
  return true;
}

bool SelectionTool::toggleAtom(const Index& atom)
{
  Atom a = m_molecule->atom(atom);
  a.setSelected(!a.selected());
  return a.selected();
}

bool SelectionTool::shouldClean(QMouseEvent* e)
{
  // acumulate the selection if shift or ctrl are presset
  if (!(e->modifiers() & Qt::ControlModifier) &&
      !(e->modifiers() & Qt::ShiftModifier)) {
    clearAtoms();
    return true;
  }
  return false;
}

bool SelectionTool::selectAtom(QMouseEvent* e, const Index& index)
{
  if (m_layerManager.atomLocked(index)) {
    return false;
  }
  // control toggles the selection
  if (e->modifiers() & Qt::ControlModifier) {
    return toggleAtom(index);
  }
  // shift and default selection adds
  else if (e->modifiers() & Qt::ShiftModifier || m_drawSelectionBox) {
    return addAtom(index);
  }
  // default toggle
  else {
    return toggleAtom(index);
  }
}

} // namespace QtPlugins
} // namespace Avogadro
