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

#include "atomlabels.h"

#include <avogadro/rendering/absolutequadstrategy.h>
#include <avogadro/rendering/avogadrorendering.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/textlabel.h>
#include <avogadro/rendering/textproperties.h>
#include <avogadro/rendering/overlayquadstrategy.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using Core::Molecule;
using Rendering::AbsoluteQuadStrategy;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::TextLabel;
using Rendering::TextProperties;
using Rendering::BillboardQuadStrategy;
using Rendering::OverlayQuadStrategy;

AtomLabels::AtomLabels(QObject *p)
  : ScenePlugin(p),
    m_enabled(false)
{
}

AtomLabels::~AtomLabels()
{
}

void AtomLabels::process(const Molecule &molecule,
                         Rendering::GroupNode &node)
{
  // Add a geometry node to contain all of the labels.
  GeometryNode *geometry = new GeometryNode;
  node.addChild(geometry);

  TextProperties tprop;
  tprop.setFontFamily(TextProperties::Serif);
  tprop.setPointSize(32);
  tprop.setColorRgb(200, 128, 32);

  // Overlay testing...
  OverlayQuadStrategy *overlayStrategy = new OverlayQuadStrategy;
  overlayStrategy->setAnchor(Vector2f(0, 0));
  overlayStrategy->setHAlign(OverlayQuadStrategy::HLeft);
  overlayStrategy->setVAlign(OverlayQuadStrategy::VBottom);

  TextLabel *overlabel = new TextLabel;
  overlabel->setString("Overlay Quad Test");
  overlabel->setTextProperties(tprop);
  overlabel->setQuadPlacementStrategy(overlayStrategy);
  overlabel->setRenderPass(Rendering::OverlayPass);

  geometry->addDrawable(overlabel);

  // Absolute testing...
  AbsoluteQuadStrategy *absoluteStrategy = new AbsoluteQuadStrategy;
  absoluteStrategy->setAnchor(Vector3f(0, 0, 0));
  absoluteStrategy->setHAlign(OverlayQuadStrategy::HCenter);
  absoluteStrategy->setVAlign(OverlayQuadStrategy::VCenter);

  TextLabel *absoluteLabel = new TextLabel;
  absoluteLabel->setString("Absolute Quad Test");
  tprop.setColorRgb(32, 64, 230);
  absoluteLabel->setTextProperties(tprop);
  absoluteLabel->setQuadPlacementStrategy(absoluteStrategy);
  absoluteLabel->setRenderPass(Rendering::TranslucentPass);

  geometry->addDrawable(absoluteLabel);

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    unsigned char atomicNumber = atom.atomicNumber();
    const unsigned char *c = Elements::color(atomicNumber);
    const char *elementName = Elements::name(atomicNumber);
    float radius = Elements::radiusCovalent(atomicNumber);

    tprop.setColorRgb((c[0] / 2) + 32, (c[1] / 2) + 64, (c[2] / 2) + 128);

    BillboardQuadStrategy *quad = new BillboardQuadStrategy;
    quad->setHAlign(BillboardQuadStrategy::HCenter);
    quad->setVAlign(BillboardQuadStrategy::VCenter);
    quad->setAnchor(atom.position3d().cast<float>());
    quad->setRadius(radius);

    TextLabel *label = new TextLabel();
    label->identifier().molecule = &molecule;
    label->identifier().type = Rendering::AtomType;
    label->identifier().index = atom.index();
    label->setString(elementName);
    label->setTextProperties(tprop);
    label->setQuadPlacementStrategy(quad);
    label->setRenderPass(Rendering::TranslucentPass);

    geometry->addDrawable(label);
  }
}

bool AtomLabels::isEnabled() const
{
  return m_enabled;
}

void AtomLabels::setEnabled(bool enable)
{
  m_enabled = enable;
}

}
}
