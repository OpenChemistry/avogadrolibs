/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "labels.h"

#include <unordered_map>

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::QtGui::RWAtom;
using Avogadro::QtGui::RWBond;
using Avogadro::QtGui::RWMolecule;
using Core::Elements;
using Core::Molecule;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;
using Rendering::CylinderGeometry;

typedef Avogadro::Core::Array<Molecule::BondType> NeighborListType;

using namespace std;

Labels::Labels(QObject* p)
  : ScenePlugin(p), m_enabled(false), m_group(nullptr), m_setupWidget(nullptr),
    m_multiBonds(true), m_showHydrogens(true)
{
}

Labels::~Labels()
{
  if (m_setupWidget)
    m_setupWidget->deleteLater();
}

void Labels::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  Index hydrogenCount = 1;

  m_group = &node;
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  std::unordered_map<unsigned char, Index>
    countMap; // Dictionary of atomic number and number of atoms

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    unsigned char atomicNumber = atom.atomicNumber();
    if (atomicNumber == 1)
      continue; // Do not process Hydrogens separately

    std::unordered_map<unsigned char, Index>::const_iterator lookUp;
    lookUp = countMap.find(atomicNumber);

    if (lookUp == countMap.end())
      countMap[atomicNumber] = 1; // For first occurrence of atom

    else
      countMap[atomicNumber] += 1; // For other occurrences of atom

    if (!m_showHydrogens)
      continue;

    Rendering::TextLabel3D* atomLabel = new Rendering::TextLabel3D;

    //  Label non Hydrogen atoms
    atomLabel->setText(
      Elements::symbol(atomicNumber) +
      QString::number(countMap[atomicNumber], 'f', 0).toStdString());

    atomLabel->setRenderPass(Rendering::Overlay3DPass);
    const Vector3f a1(atom.position3d().cast<float>());
    const Vector3f& textPos(a1);
    atomLabel->setAnchor(textPos);
    geometry->addDrawable(atomLabel);

    Rendering::TextProperties tprop;
    tprop.setAlign(Rendering::TextProperties::HCenter,
                   Rendering::TextProperties::VCenter);
    tprop.setFontFamily(Rendering::TextProperties::SansSerif);
    tprop.setColorRgb(255, 255, 255);
    atomLabel->setTextProperties(tprop);

    //  Label Hydrogen atoms
    const NeighborListType bonds =
      (const_cast<Molecule&>(molecule))
        .bonds(atom); // const_cast because bonds() accepts non const objects
    for (NeighborListType::const_iterator it = bonds.begin(),
                                          itEnd = bonds.end();
         it != itEnd; ++it) {
      const Core::Atom otherAtom =
        it->atom1().index() != atom.index() ? it->atom1() : it->atom2();
      if (otherAtom.atomicNumber() == 1) {
        Rendering::TextLabel3D* hAtomLabel = new Rendering::TextLabel3D;
        hAtomLabel->setText(
          "H" + QString::number(hydrogenCount, 'f', 0).toStdString());

        hAtomLabel->setRenderPass(Rendering::Overlay3DPass);
        const Vector3f a1(otherAtom.position3d().cast<float>());
        const Vector3f& textPos(a1);
        hAtomLabel->setAnchor(textPos);
        geometry->addDrawable(hAtomLabel);

        hAtomLabel->setTextProperties(tprop);
        hydrogenCount++;
      }
    }
  }
}

bool Labels::isEnabled() const
{
  return m_enabled;
}

void Labels::setEnabled(bool enable)
{
  m_enabled = enable;
}

QWidget* Labels::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    QVBoxLayout* v = new QVBoxLayout;
    QCheckBox* check = new QCheckBox(tr("Show multiple bonds?"));
    check->setChecked(m_multiBonds);
    connect(check, SIGNAL(clicked(bool)), SLOT(multiBonds(bool)));
    v->addWidget(check);
    check = new QCheckBox(tr("Show hydrogens?"));
    check->setChecked(m_showHydrogens);
    connect(check, SIGNAL(toggled(bool)), SLOT(showHydrogens(bool)));
    v->addWidget(check);
    m_setupWidget->setLayout(v);
  }
  return m_setupWidget;
}

void Labels::multiBonds(bool show)
{
  if (show != m_multiBonds) {
    m_multiBonds = show;
    emit drawablesChanged();
  }
}

void Labels::showHydrogens(bool show)
{
  if (show != m_showHydrogens) {
    m_showHydrogens = show;
    emit drawablesChanged();
  }
}

} // namespace QtPlugins
} // namespace Avogadro