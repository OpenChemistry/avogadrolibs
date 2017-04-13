/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "symmetryscene.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QDebug>

#include <QVector3D>

using namespace Avogadro;

namespace Avogadro {
namespace QtPlugins {

using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;
using Rendering::CylinderGeometry;

SymmetryScene::SymmetryScene(QObject* p)
  : QtGui::ScenePlugin(p), m_enabled(true)
{
  qDebug() << "SymmetryScene constructor";
}

SymmetryScene::~SymmetryScene()
{
}

void SymmetryScene::process(const Core::Molecule& coreMolecule,
                            Rendering::GroupNode& node)
{
  qDebug() << "SymmetryScene::process";

  const QtGui::Molecule* molecule =
    dynamic_cast<const QtGui::Molecule*>(&coreMolecule);
  if (!molecule)
    return;

  QVariant origo = molecule->property("SymmetryOrigo");
  QVariant radius = molecule->property("SymmetryRadius");
  QVariant inversion = molecule->property("SymmetryInversion");
  QVariant properRotation =
    molecule->property("SymmetryProperRotationVariantList");
  QVariant improperRotation =
    molecule->property("SymmetryImproperRotationVariantList");
  QVariant reflection = molecule->property("SymmetryReflectionVariantList");
  if (!origo.isValid() || !radius.isValid()) {
    qDebug() << "Missing origo or radius";
    return;
  }

  QVector3D qorigo = origo.value<QVector3D>();
  Vector3f forigo = Vector3f(qorigo.x(), qorigo.y(), qorigo.z());
  float fradius = radius.toFloat();

  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  SphereGeometry* spheres = new SphereGeometry;
  spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  CylinderGeometry* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);

  if (inversion.isValid()) {
    Vector3ub color(0, 0, 255);
    qDebug() << "Have inversion";
    QVector3D qvec = inversion.value<QVector3D>();
    Vector3f fvec = Vector3f(qvec.x(), qvec.y(), qvec.z());
    spheres->addSphere(fvec, color, 0.3f);
  }

  if (properRotation.isValid()) {
    Vector3ub color(255, 0, 0);
    QVariantList properRotationVariantList = properRotation.toList();
    qDebug() << "Have proper rotation " << properRotationVariantList.size();
    foreach (QVariant qv, properRotationVariantList) {
      QVector3D qvec = qv.value<QVector3D>();
      Vector3f fvec = Vector3f(qvec.x(), qvec.y(), qvec.z());
      cylinders->addCylinder(forigo, forigo + 1.1 * fradius * fvec, 0.05f,
                             color);
    }
  }

  if (improperRotation.isValid()) {
    QVariantList improperRotationVariantList = improperRotation.toList();

    qDebug() << "Have improper rotation " << improperRotationVariantList.size();
  }

  if (reflection.isValid()) {
    Vector3ub color(255, 255, 0);
    QVariantList reflectionVariantList = reflection.toList();
    qDebug() << "Have reflection " << reflectionVariantList.size();

    foreach (QVariant qv, reflectionVariantList) {
      QVector3D qvec = qv.value<QVector3D>();
      Vector3f fvec = Vector3f(qvec.x(), qvec.y(), qvec.z());
      cylinders->addCylinder(forigo - fvec * 0.025f, forigo + fvec * 0.025f,
                             fradius, color);
    }
  }

  qDebug() << "SymmetryScene::process do stuff " << qorigo;
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

void SymmetryScene::setEnabled(bool enable)
{
  m_enabled = enable;
}
}
}
