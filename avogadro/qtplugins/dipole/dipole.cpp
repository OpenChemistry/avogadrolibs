/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dipole.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QDebug>
#include <QTimer>
#include <QtWidgets/QWidget>

namespace Avogadro::QtPlugins {

using QtGui::Molecule;
using Rendering::ArrowGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

Dipole::Dipole(QObject* p) : ScenePlugin(p)
{
  m_layerManager = QtGui::PluginLayerManager(m_name);
}

Dipole::~Dipole() {}

void Dipole::process(const QtGui::Molecule& molecule,
                     Rendering::GroupNode& node)
{
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  auto* arrow = new ArrowGeometry;
  arrow->identifier().molecule = &molecule;

  arrow->setColor(Vector3ub(255, 0, 0));
  geometry->addDrawable(arrow);

  Vector3f origin = Vector3f::Zero();

  // check if the molecule has the dipole set
  if (!m_customDipole) {
    if (molecule.hasData("dipoleMoment")) {
      m_dipoleVector = molecule.data("dipoleMoment").toVector3();
    } else {
      if (!molecule.isInteractive()) {
        m_dipoleVector =
          Calc::ChargeManager::instance().dipoleMoment(m_type, molecule);
      }
    }
  }

  arrow->addSingleArrow(m_dipoleVector.cast<float>(), origin);
}

QWidget* Dipole::setupWidget()
{
  return nullptr;
}

} // namespace Avogadro::QtPlugins
