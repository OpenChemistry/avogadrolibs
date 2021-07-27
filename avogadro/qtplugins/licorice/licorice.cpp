/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "licorice.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using Core::Molecule;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;

Licorice::Licorice(QObject* p) : ScenePlugin(p), m_enabled(false) {}

Licorice::~Licorice() {}

void Licorice::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  // Use a common radius for all spheres and cylinders.
  float radius(0.2f);
  float selectedRadius(radius * 1.5f);

  // Add a sphere node to contain all of the spheres.
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);
  SphereGeometry* spheres = new SphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;
  auto selectedSpheres = new SphereGeometry;
  selectedSpheres->setOpacity(0.42);
  geometry->addDrawable(spheres);
  geometry->addDrawable(selectedSpheres);

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    Vector3ub color = atom.color();
    spheres->addSphere(atom.position3d().cast<float>(), color, radius);

    if (atom.selected()) {
      color = Vector3ub(0, 0, 255);
      selectedSpheres->addSphere(atom.position3d().cast<float>(), color,
                                 selectedRadius);
    }
  }

  CylinderGeometry* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);
  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3ub color1 = bond.atom1().color();
    Vector3ub color2 = bond.atom2().color();
    Vector3f bondVector = pos2 - pos1;
    float bondLength = bondVector.norm();
    bondVector /= bondLength;

    cylinders->addCylinder(pos1, pos2, radius, color1, color2, i);
  }
}

bool Licorice::isEnabled() const
{
  return m_enabled;
}

void Licorice::setEnabled(bool enable)
{
  m_enabled = enable;
}
} // namespace QtPlugins
} // namespace Avogadro
