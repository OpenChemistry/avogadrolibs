/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "symmetryscene.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/rendering/arcsector.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QDebug>
#include <QtCore/QVariant>

#include <QVector3D>

using namespace Avogadro;

namespace Avogadro::QtPlugins {

using Core::Array;
using Rendering::ArcSector;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::MeshGeometry;
using Rendering::SphereGeometry;

SymmetryScene::SymmetryScene(QObject* p)
  : QtGui::ScenePlugin(p), m_enabled(true)
{
}

SymmetryScene::~SymmetryScene() {}

void SymmetryScene::process(const QtGui::Molecule& molecule,
                            Rendering::GroupNode& node)
{
  QVariant origo = molecule.property("SymmetryOrigo");
  QVariant radius = molecule.property("SymmetryRadius");
  QVariant inversion = molecule.property("SymmetryInversion");
  QVariant properRotation =
    molecule.property("SymmetryProperRotationVariantList");
  QVariant improperRotation =
    molecule.property("SymmetryImproperRotationVariantList");
  QVariant reflection = molecule.property("SymmetryReflectionVariantList");
  if (!origo.isValid() || !radius.isValid()) {
    return;
  }

  auto qorigo = origo.value<QVector3D>();
  Vector3f forigo = Vector3f(qorigo.x(), qorigo.y(), qorigo.z());
  float fradius = radius.toFloat();

  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  auto* spheres = new SphereGeometry;
  spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  auto* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);

  if (inversion.isValid()) {
    Vector3ub color(0, 0, 255);
    auto qvec = inversion.value<QVector3D>();
    Vector3f fvec = Vector3f(qvec.x(), qvec.y(), qvec.z());
    spheres->addSphere(fvec, color, 0.3f);
  }

  if (properRotation.isValid()) {
    Vector3ub color(255, 0, 0);
    QVariantList properRotationVariantList = properRotation.toList();
    foreach (QVariant qv, properRotationVariantList) {
      auto qvec = qv.value<QVector3D>();
      Vector3f fvec = Vector3f(qvec.x(), qvec.y(), qvec.z());
      cylinders->addCylinder(forigo, forigo + 1.1 * fradius * fvec, 0.05f,
                             color);
    }
  }

  if (improperRotation.isValid()) {
    QVariantList improperRotationVariantList = improperRotation.toList();
  }

  if (reflection.isValid()) {
    Vector3ub color(255, 255, 0);
    QVariantList reflectionVariantList = reflection.toList();

    foreach (QVariant qv, reflectionVariantList) {
      auto qvec = qv.value<QVector3D>();
      // normal to the mirror plane
      Vector3f vecNormal = Vector3f(qvec.x(), qvec.y(), qvec.z());

      // get an arbitrary vector in the plane, scaled by fradius
      Vector3f vecPlane;
      if (qvec.z() < qvec.x())
        vecPlane = Vector3f(-qvec.y(), qvec.x(), 0);
      else
        vecPlane = Vector3f(0, -qvec.z(), qvec.y());

      vecPlane = vecPlane.normalized() * fradius;

      auto* sect = new ArcSector;
      geometry->addDrawable(sect);
      sect->setColor(Vector3ub(color));
      sect->setOpacity(127); // 50%
      sect->setRenderPass(Rendering::TranslucentPass);
      sect->setArcSector(forigo, vecPlane, vecNormal, 360.0f, 5.f);

      //      cylinders->addCylinder(forigo - fvec * 0.025f, forigo + fvec *
      //      0.025f, fradius, color);
    }
  }
}

void SymmetryScene::processEditable(const QtGui::RWMolecule& molecule,
                                    Rendering::GroupNode& node)
{
  process(molecule.molecule(), node);
}

bool SymmetryScene::isEnabled() const
{
  return m_enabled;
}

bool SymmetryScene::isActiveLayerEnabled() const
{
  return m_enabled;
}

void SymmetryScene::setEnabled(bool enable)
{
  m_enabled = enable;
}
} // namespace Avogadro::QtPlugins
