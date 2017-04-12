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

#include "crystalscene.h"

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/linestripgeometry.h>

namespace Avogadro {
namespace QtPlugins {

using Core::Array;
using Core::Molecule;
using Core::UnitCell;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::LineStripGeometry;

CrystalScene::CrystalScene(QObject* p) : ScenePlugin(p), m_enabled(true)
{
}

CrystalScene::~CrystalScene()
{
}

void CrystalScene::process(const Molecule& molecule, GroupNode& node)
{
  if (const UnitCell* cell = molecule.unitCell()) {
    GeometryNode* geometry = new GeometryNode;
    node.addChild(geometry);
    LineStripGeometry* lines = new LineStripGeometry;
    geometry->addDrawable(lines);

    lines->setColor(Vector3ub(255, 255, 255));

    float width = 2.0;

    Vector3f a = cell->aVector().cast<float>();
    Vector3f b = cell->bVector().cast<float>();
    Vector3f c = cell->cVector().cast<float>();

    Vector3f vertex(Vector3f::Zero());

    Array<Vector3f> strip;
    strip.reserve(5);
    strip.push_back(vertex);
    strip.push_back(vertex += a);
    strip.push_back(vertex += b);
    strip.push_back(vertex -= a);
    strip.push_back(vertex -= b);
    lines->addLineStrip(strip, width);

    for (Array<Vector3f>::iterator it = strip.begin(), itEnd = strip.end();
         it != itEnd; ++it) {
      *it += c;
    }
    lines->addLineStrip(strip, width);

    strip.resize(2);
    strip[0] = Vector3f::Zero();
    strip[1] = c;
    lines->addLineStrip(strip, width);

    strip[0] += a;
    strip[1] += a;
    lines->addLineStrip(strip, width);

    strip[0] += b;
    strip[1] += b;
    lines->addLineStrip(strip, width);

    strip[0] -= a;
    strip[1] -= a;
    lines->addLineStrip(strip, width);
  }
}

bool CrystalScene::isEnabled() const
{
  return m_enabled;
}

void CrystalScene::setEnabled(bool enable)
{
  m_enabled = enable;
}
}
}
