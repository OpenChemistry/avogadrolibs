/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "force.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro::QtPlugins {

using QtGui::Molecule;
using Rendering::ArrowGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

Force::Force(QObject* p) : ScenePlugin(p)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);
}

Force::~Force() {}

void Force::process(const QtGui::Molecule& molecule, Rendering::GroupNode& node)
{
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  auto* arrows = new ArrowGeometry;
  arrows->identifier().molecule = &molecule;
  geometry->addDrawable(arrows);
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    if (!m_layerManager.atomEnabled(i))
      continue; // ignore hidden atoms

    Core::Atom atom1 = molecule.atom(i);
    Vector3f pos1 = atom1.position3d().cast<float>();
    Vector3f forceVector = atom1.forceVector().cast<float>();
    arrows->addSingleArrow(pos1, pos1 + forceVector);
  }
}

} // namespace Avogadro::QtPlugins
