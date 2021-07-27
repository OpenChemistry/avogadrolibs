/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vanderwaals.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;

VanDerWaals::VanDerWaals(QObject* p) : ScenePlugin(p), m_enabled(false) {}

VanDerWaals::~VanDerWaals() {}

void VanDerWaals::process(const Core::Molecule& molecule,
                          Rendering::GroupNode& node)
{
  // Add a sphere node to contain all of the VdW spheres.
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
    unsigned char atomicNumber = atom.atomicNumber();

    Vector3ub color = atom.color();
    float radius = static_cast<float>(Elements::radiusVDW(atomicNumber));
    spheres->addSphere(atom.position3d().cast<float>(), color, radius);
    if (atom.selected()) {
      color = Vector3ub(0, 0, 255);
      radius += 0.3f;
      selectedSpheres->addSphere(atom.position3d().cast<float>(), color,
                                 radius);
    }
  }
}

bool VanDerWaals::isEnabled() const
{
  return m_enabled;
}

void VanDerWaals::setEnabled(bool enable)
{
  m_enabled = enable;
}
} // namespace QtPlugins
} // namespace Avogadro
