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
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/core/spacegroups.h>


namespace Avogadro {
namespace QtPlugins {

using Core::Array;
using Core::Molecule;
using Core::UnitCell;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::LineStripGeometry;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;

CrystalScene::CrystalScene(QObject *p) : ScenePlugin(p), m_enabled(true)
{
}

CrystalScene::~CrystalScene()
{
}

void CrystalScene::process(const Molecule &molecule, GroupNode &node)
{
  if (const UnitCell *cell = molecule.unitCell()) {
    GeometryNode *geometry = new GeometryNode;
    node.addChild(geometry);
    LineStripGeometry *lines = new LineStripGeometry;
    geometry->addDrawable(lines);

    lines->setColor(Vector3ub(255, 255, 255));

    float width = 2.0;

    Vector3f a;
    Vector3f b;
    Vector3f c;
    /*if(cell->showPrim())
    {
      Matrix3 primCell = cell->primitiveCell();
      a = primCell.col(0).cast<float>();
      b = primCell.col(1).cast<float>();
      c = primCell.col(2).cast<float>();
    }
    else
    {*/
      a = cell->aVector().cast<float>();
      b = cell->bVector().cast<float>();
      c = cell->cVector().cast<float>();
    //}


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

    //space group
    int hallNumber = cell->getSpaceGroup();
    if(hallNumber == 0)
      return;

    QString overlayText;
    QString hallLabel = tr("Hall Symbol:");
    QString intLabel  = tr("Space Group:");
    int labelWidth = -std::max(hallLabel.size(),intLabel.size());


    std::string intSymb = SpaceGroups::getInternational(hallNumber);
    if(intSymb.size())
    {
      overlayText += QString("%1 %2\n")
        .arg(tr("SpaceGroup Symbol:"),intLabel.size())
        .arg(tr(intSymb.c_str()),intSymb.size());
    }
    std::string hallSymb = SpaceGroups::getHallSymbol(hallNumber);
    if(hallSymb.size())
    {
      overlayText += QString("%1 %2\n")
        .arg(tr("Hall Symbol:"),hallLabel.size())
        .arg(tr(hallSymb.c_str()),hallSymb.size());
    }

    TextProperties overlayTProp;
    overlayTProp.setFontFamily(TextProperties::Mono);
    overlayTProp.setColorRgb(255,255,255);
    overlayTProp.setAlign(TextProperties::HLeft,TextProperties::VTop);

    TextLabel2D *label = new TextLabel2D;
    label->setText(overlayText.toStdString());
    label->setTextProperties(overlayTProp);
    label->setRenderPass(Rendering::Overlay2DPass);
    label->setAnchor(Vector2i(10,500));

    geometry->addDrawable(label);
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
