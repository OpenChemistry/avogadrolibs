/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "noncovalent.h"

#include <avogadro/core/array.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/atomutilities.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/neighborperceiver.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/dashedlinegeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QtCore/QSettings>
#include <QtGui/QColor>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

#include <cmath>

#define M_TETRAHED 1.910633236
#define M_TRI 2.094395102

namespace Avogadro {
namespace QtPlugins {

using Core::Array;
using Core::AtomHybridization;
using Core::AtomUtilities;
using Core::Bond;
using Core::NeighborPerceiver;
using QtGui::Molecule;
using QtGui::PluginLayerManager;
using Rendering::DashedLineGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

NonCovalent::NonCovalent(QObject *p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);
  
  QSettings settings;
  m_angleToleranceDegrees = settings.value("nonCovalent/angleTolerance", 30.0).toDouble();
  m_maximumDistance = settings.value("nonCovalent/maximumDistance", 2.0).toDouble();
  QColor hydrogenBColor = settings.value("nonCovalent/lineColor0", QColor(64, 192, 255)).value<QColor>();
  m_lineColors = {
    Vector3ub(hydrogenBColor.red(), hydrogenBColor.green(), hydrogenBColor.blue())
  };
  m_lineWidths = {
    settings.value("nonCovalent/lineWidth0", 2).toInt()
  };
}

NonCovalent::~NonCovalent() {}

enum InteractionTypes {
  NONE = -1,
  HYDROGEN_BOND = 0
};

static enum InteractionTypes getInteractionType(const Molecule &molecule, Index i)
{
  unsigned char inum = molecule.atomicNumber(i);
  switch (inum) {
    case 1: // hydrogen bond
      for (const Bond *b : molecule.bonds(i)) {
        Index j = b->getOtherAtom(i).index();
        unsigned char jnum = molecule.atomicNumber(j);
        switch (jnum) {
          case 7: case 8: case 9: // F, O, N
            return HYDROGEN_BOND;
        }
      }
      break;
  }
  return NONE;
}

static bool checkPairDonorIsValid(const Molecule &molecule, Index n, int interactionType)
{
  unsigned char nnum = molecule.atomicNumber(n);
  switch (interactionType) {
    case HYDROGEN_BOND:
      switch (nnum) {
        case 7: case 8: case 9: // F, O, N
          return true;
      }
      break;
  }
  return false;
}

static bool checkAtomPairNotBonded(const Molecule &molecule, Index i, Index n)
{
  Array<const Bond *> bonds = molecule.bonds(i);
  /* Return true if all of the bonds from i are to atoms other than n */
  return std::all_of(bonds.begin(), bonds.end(), [i, n](const Bond *b) {
    return b->getOtherAtom(i).index() != n;
  });
}

static float computeAngle(Vector3 a, Vector3 b)
{
  return acos(a.normalized().dot(b.normalized()));
}

static bool checkHoleVector(
    const Molecule &molecule, Index i, Vector3 in, float angleTolerance
) {
  Array<const Bond *> bonds = molecule.bonds(i);
  Vector3 pos = molecule.atomPosition3d(i);
  /* Return true if any of the bonds to i forms a small enough angle
   * with 'in' at the opposite side of atom 'i' */
  return std::any_of(bonds.begin(), bonds.end(),
    [molecule, i, in, angleTolerance, pos](const Bond *b) {
      Index n = b->getOtherAtom(i).index();
      Vector3 npos = molecule.atomPosition3d(n);
      float oppositeAngle = M_PI - computeAngle(
        in, npos - pos
      );
      return oppositeAngle <= angleTolerance;
    }
  );
}

static bool checkPairVector(
    const Molecule &molecule, Index n, Vector3 in, float angleTolerance
) {
  AtomHybridization hybridization = AtomUtilities::perceiveHybridization(molecule.atom(n));
  Array<const Bond *> bonds = molecule.bonds(n);
  size_t bondCount = bonds.size();
  std::vector<Vector3> bondVectors(bondCount);
  Vector3 pos = molecule.atomPosition3d(n);
  std::transform(bonds.begin(), bonds.end(), bondVectors.begin(), [molecule, n, pos](const Bond *b) {
    return molecule.atomPosition3d(b->getOtherAtom(n).index());
  });
  float pairAngle;
  switch (hybridization) {
    case Core::SP3:
      switch (bondCount) {
        case 0:
          pairAngle = 0.0f;
          break;
        case 1:
          pairAngle = abs(computeAngle(bondVectors[0], in) - M_TETRAHED);
          break;
        case 2: {
          Vector3 pairVector = AtomUtilities::generateNewBondVector(
            molecule.atom(n), bondVectors, hybridization
          );
          pairAngle = computeAngle(pairVector, in);
          bondVectors.push_back(pairVector);
          pairVector = AtomUtilities::generateNewBondVector(
            molecule.atom(n), bondVectors, hybridization
          );
          pairAngle = std::min(pairAngle, computeAngle(pairVector, in));
          break;
        }
        case 3: {
          Vector3 pairVector = AtomUtilities::generateNewBondVector(
            molecule.atom(n), bondVectors, hybridization
          );
          pairAngle = computeAngle(pairVector, in);
          break;
        }
        default:
          return false;
      }
      break;
    case Core::SP2:
      switch (bondCount) {
        case 0:
          pairAngle = 0.0f;
          break;
        case 1:
          pairAngle = abs(computeAngle(bondVectors[0], -in) - M_TRI);
          break;
        case 2: {
          Vector3 pairVector = AtomUtilities::generateNewBondVector(
            molecule.atom(n), bondVectors, hybridization
          );
          pairAngle = computeAngle(pairVector, in);
          break;
        }
        default:
          return false;
      }
      break;
    case Core::SP:
      switch (bondCount) {
        case 0:
          pairAngle = 0.0f;
          break;
        case 1: {
          pairAngle = abs(computeAngle(bondVectors[0], in) - M_PI);
          break;
        }
        default:
          return false;
      }
    default:
      return true;
  }
  return pairAngle <= angleTolerance;
}

void NonCovalent::process(const Molecule &molecule, Rendering::GroupNode &node)
{
  Vector3ub color(64, 192, 255);

  NeighborPerceiver perceiver(molecule.atomPositions3d(), m_maximumDistance);
  std::vector<bool> isAtomEnabled(molecule.atomCount());
  for (Index i = 0; i < molecule.atomCount(); ++i)
    isAtomEnabled[i] = m_layerManager.atomEnabled(i);

  GeometryNode *geometry = new GeometryNode;
  node.addChild(geometry);
  DashedLineGeometry *lines = new DashedLineGeometry;
  lines->identifier().molecule = &molecule;
  lines->identifier().type = Rendering::BondType;
  lines->setLineWidth(m_lineWidths[0]);
  geometry->addDrawable(lines);
  Array<Index> neighbors;
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    if (!isAtomEnabled[i])
      continue;
    enum InteractionTypes interactionType = getInteractionType(molecule, i);
    if (interactionType == NONE)
      continue;
    Vector3 pos = molecule.atomPosition3d(i);
    perceiver.getNeighborsInclusiveInPlace(neighbors, pos);
    for (Index n : neighbors) {
      if (!isAtomEnabled[n])
        continue;
      if (!checkPairDonorIsValid(molecule, n, interactionType))
        continue;

      Vector3 npos = molecule.atomPosition3d(n);
      Vector3 distance_vector = npos - pos;

      if (distance_vector.norm() > m_maximumDistance)
        continue;
      if (!checkAtomPairNotBonded(molecule, i, n))
        continue;

      float angleTolerance = m_angleToleranceDegrees * M_PI / 180.0;
      if (!checkHoleVector(molecule, i, distance_vector, angleTolerance))
        continue;
      if (!checkPairVector(molecule, n, -distance_vector, angleTolerance))
        continue;

      lines->addDashedLine(pos.cast<float>(), npos.cast<float>(), color, 8);
    }
  }
}

QWidget *NonCovalent::setupWidget()
{
  QWidget *widget = new QWidget(qobject_cast<QWidget *>(this->parent()));
  QVBoxLayout *v = new QVBoxLayout;

  // angle tolerance
  QDoubleSpinBox *angle_spin = new QDoubleSpinBox;
  angle_spin->setRange(0.0, 180.0);
  angle_spin->setSingleStep(1.0);
  angle_spin->setDecimals(0);
  angle_spin->setSuffix(tr(" °"));
  angle_spin->setValue(m_angleToleranceDegrees);
  QObject::connect(angle_spin, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this, &NonCovalent::setAngleTolerance);
  
  // maximum distance
  QDoubleSpinBox *distance_spin = new QDoubleSpinBox;
  distance_spin->setRange(1.0, 10.0);
  distance_spin->setSingleStep(0.1);
  distance_spin->setDecimals(1);
  distance_spin->setSuffix(tr(" Å"));
  distance_spin->setValue(m_angleToleranceDegrees);
  QObject::connect(distance_spin, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this, &NonCovalent::setMaximumDistance);
  
  QFormLayout *form = new QFormLayout;
  form->addRow(QObject::tr("Angle tolerance:"), angle_spin);
  form->addRow(QObject::tr("Maximum distance:"), distance_spin);
  v->addLayout(form);

  v->addStretch(1);
  widget->setLayout(v);
  return widget;
}

void NonCovalent::setAngleTolerance(float angleTolerance)
{
  m_angleToleranceDegrees = float(angleTolerance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("nonCovalent/angleTolerance", m_angleToleranceDegrees);
}

void NonCovalent::setMaximumDistance(float maximumDistance)
{
  m_maximumDistance = float(maximumDistance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("nonCovalent/maximumDistance", m_maximumDistance);
}

} // namespace QtPlugins
} // namespace Avogadro
