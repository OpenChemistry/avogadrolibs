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

#include "bondcentrictool.h"

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <QtGui/QAction>
#include <QtGui/QIcon>
#include <QtGui/QMouseEvent>

#include <cmath>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

using Avogadro::Core::Atom;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::Identifier;

namespace {
const float RAD_TO_DEG_F = 180.f / static_cast<float>(M_PI);

// Convenience quad drawable:
class Quad : public MeshGeometry
{
public:
  Quad()
  {
    m_vertices.resize(6);
    m_indices.resize(6);
    m_indices[0] = 0; // bottom left
    m_indices[1] = 1; // top left
    m_indices[2] = 2; // top right
    m_indices[3] = 3; // bottom left
    m_indices[4] = 4; // top right
    m_indices[5] = 5; // bottom right
  }
  ~Quad() {}

  void setBottomLeft()
};

// Convenience arc sector drawable:

}

namespace Avogadro {
namespace QtPlugins {

// Private drawables container
class BondCentricTool::DrawablePIMPL
{
public:
};

BondCentricTool::BondCentricTool(QObject *parent_)
  : QtGui::ToolPlugin(parent_),
    m_activateAction(new QAction(this)),
    m_molecule(NULL),
    m_glWidget(NULL),
    m_drawables(new DrawablePIMPL)
{
  m_activateAction->setText(tr("Bond-centric manipulation"));
  m_activateAction->setIcon(QIcon(":/icons/bondcentrictool.png"));
}

BondCentricTool::~BondCentricTool()
{
}

QWidget * BondCentricTool::toolWidget() const
{
  return NULL;
}

void BondCentricTool::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
}

void BondCentricTool::setGLWidget(QtOpenGL::GLWidget *widget)
{
  m_glWidget = widget;
}

QUndoCommand * BondCentricTool::mousePressEvent(QMouseEvent *e)
{
  return NULL;
}

QUndoCommand *BondCentricTool::mouseMoveEvent(QMouseEvent *e)
{
  return NULL;
}

QUndoCommand * BondCentricTool::mouseReleaseEvent(QMouseEvent *e)
{
  return NULL;
}

void BondCentricTool::draw(Rendering::GroupNode &node)
{
}

} // namespace QtPlugins
} // namespace Avogadro
