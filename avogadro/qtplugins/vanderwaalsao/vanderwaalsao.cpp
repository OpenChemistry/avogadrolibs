/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vanderwaalsao.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/ambientocclusionspheregeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

namespace Avogadro::QtPlugins {

using Core::Elements;
using QtGui::PluginLayerManager;
using Rendering::AmbientOcclusionSphereGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

VanDerWaalsAO::VanDerWaalsAO(QObject* p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);
}

VanDerWaalsAO::~VanDerWaalsAO() {}

void VanDerWaalsAO::process(const QtGui::Molecule& molecule,
                            Rendering::GroupNode& node)
{
  // Add a sphere node to contain all of the VdW spheres.
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  auto* spheres = new AmbientOcclusionSphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();
    const unsigned char* c = Elements::color(atomicNumber);
    Vector3ub color(c[0], c[1], c[2]);
    spheres->addSphere(atom.position3d().cast<float>(), color,
                       static_cast<float>(Elements::radiusVDW(atomicNumber)),
                       i);
  }
}

} // namespace Avogadro
