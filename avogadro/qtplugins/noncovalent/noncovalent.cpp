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
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

#include <algorithm>
#include <cmath>
#include <sstream>

// bond angles
#define M_TETRAHEDRAL (acosf(-1.0f / 3.0f))
#define M_TRIGONAL (2.0f * M_PI / 3.0f)

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::AtomHybridization;
using Core::AtomUtilities;
using Core::Bond;
using Core::Elements;
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
  m_angleTolerancesDegrees = {
  	settings.value("nonCovalent/angleTolerance0", 40.0).toDouble(),
  	settings.value("nonCovalent/angleTolerance1", 40.0).toDouble(),
  	settings.value("nonCovalent/angleTolerance2", 40.0).toDouble()
  };
  m_maximumDistances = {
  	settings.value("nonCovalent/maximumDistance0", 1.0).toDouble(),
  	settings.value("nonCovalent/maximumDistance1", 2.0).toDouble(),
  	settings.value("nonCovalent/maximumDistance2", 2.0).toDouble()
  };
  auto hydrogenBColor = settings.value("nonCovalent/lineColor0", QColor(64, 192, 255)).value<QColor>();
  auto halogenBColor = settings.value("nonCovalent/lineColor1", QColor(128, 255, 64)).value<QColor>();
  auto chalcogenBColor = settings.value("nonCovalent/lineColor2", QColor(255, 192, 64)).value<QColor>();
  m_lineColors = {
    Vector3ub(hydrogenBColor.red(), hydrogenBColor.green(), hydrogenBColor.blue()),
    Vector3ub(halogenBColor.red(), halogenBColor.green(), halogenBColor.blue()),
    Vector3ub(chalcogenBColor.red(), chalcogenBColor.green(), chalcogenBColor.blue())
  };
  m_lineWidths = {
    settings.value("nonCovalent/lineWidth0", 5.0).toFloat(),
    settings.value("nonCovalent/lineWidth1", 5.0).toFloat(),
    settings.value("nonCovalent/lineWidth2", 5.0).toFloat()
  };
}

NonCovalent::~NonCovalent() {}

enum InteractionTypes {
  NONE = -1,
  HYDROGEN_BOND = 0,
  HALOGEN_BOND = 1,
  CHALCOGEN_BOND = 2
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
    case 9: case 17: case 35: case 53: // halogen bond
      for (const Bond *b : molecule.bonds(i)) {
        Index j = (b->atom1().index() == i ? b->atom2() : b->atom1()).index();
        unsigned char jnum = molecule.atomicNumber(j);
        switch (jnum) {
          case 6: case 7: case 8: case 9:
          case 16: case 17: case 35: case 53: // F, O, N, Cl, Br, C, I, S
            return HALOGEN_BOND;
        }
      }
      break;
    case 8: case 16: case 34: case 52: // chalcogen bond
      for (const Bond *b : molecule.bonds(i)) {
        Index j = (b->atom1().index() == i ? b->atom2() : b->atom1()).index();
        unsigned char jnum = molecule.atomicNumber(j);
        switch (jnum) {
          case 6: // C
            return CHALCOGEN_BOND;
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
        case 7: case 8: case 9: case 17: // F, O, N, Cl
          return true;
      }
      break;
    case HALOGEN_BOND:
      switch (nnum) {
        case 7: case 8: case 9: case 17: // F, O, N, Cl
          return true;
      }
      break;
    case CHALCOGEN_BOND:
      switch (nnum) {
        case 7: case 8: case 9: case 16:
        case 17: case 34: case 52: // F, O, N, Cl, S, Se, Te
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
    const Molecule &molecule, Index i, const Vector3 &in, float angleTolerance
) {
  Array<const Bond *> bonds = molecule.bonds(i);
  Vector3 pos = molecule.atomPosition3d(i);
  /* Return true if any of the bonds to i forms a small enough angle
   * with 'in' at the opposite side of atom 'i' */
  for (const Bond *b: bonds) {
    Index n = b->getOtherAtom(i).index();
      Vector3 npos = molecule.atomPosition3d(n);
      float oppositeAngle = M_PI - computeAngle(in, npos - pos);
      if (oppositeAngle <= angleTolerance)
        return true;
  }
  return false;
}

static bool checkPairVector(
    const Molecule &molecule, Index n, const Vector3 &in, float angleTolerance
) {
  AtomHybridization hybridization = AtomUtilities::perceiveHybridization(molecule.atom(n));
  Array<const Bond *> bonds = molecule.bonds(n);
  size_t bondCount = bonds.size();
  std::vector<Vector3> bondVectors;
  Vector3 pos = molecule.atomPosition3d(n);
  /* Compute all bond vectors around atom n */
  for (const Bond *b: bonds)
    bondVectors.emplace_back(molecule.atomPosition3d(b->getOtherAtom(n).index()) - pos);
  float pairAngle;
  switch (hybridization) {
    case Core::SP3:
      switch (bondCount) {
        case 0:
          pairAngle = 0.0f;
          break;
        case 1:
          pairAngle = fabs(computeAngle(bondVectors[0], in) - M_TETRAHEDRAL);
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
          pairAngle = fabs(computeAngle(bondVectors[0], in) - M_TRIGONAL);
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
          pairAngle = fabs(computeAngle(bondVectors[0], in) - M_PI);
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
  std::vector<Index> enabledAtoms;
  Array<Vector3> enabledPositions;
  Array<double> atomRadii;
  const size_t atomCount = molecule.atomCount();
  for (Index i = 0; i < atomCount; ++i) {
    enabledAtoms.push_back(i);
    enabledPositions.push_back(molecule.atomPosition3d(i));
    atomRadii.push_back(Elements::radiusVDW(molecule.atomicNumber(i)));
  }
  float absoluteMaxDistance = *std::max_element(
  	m_maximumDistances.begin(), m_maximumDistances.end()
  );
  NeighborPerceiver perceiver(enabledPositions, absoluteMaxDistance);

  auto *geometry = new GeometryNode;
  node.addChild(geometry);
  std::array<DashedLineGeometry *, 3> lineGroups;
  for (Index type = 0; type < 3; type++) {
    lineGroups[type] = new DashedLineGeometry;
    lineGroups[type]->identifier().molecule = &molecule;
    lineGroups[type]->identifier().type = Rendering::BondType;
    lineGroups[type]->setLineWidth(m_lineWidths[type]);
    geometry->addDrawable(lineGroups[type]);
  }
  Array<Index> neighbors;
  for (Index i: enabledAtoms) {
    enum InteractionTypes interactionType = getInteractionType(molecule, i);
    if (interactionType == NONE)
      continue;
    Vector3 pos = molecule.atomPosition3d(i);
    double radius = atomRadii[i];
    perceiver.getNeighborsInclusiveInPlace(neighbors, pos);
    for (Index ni : neighbors) {
      Index n = enabledAtoms[ni];
      if (!checkPairDonorIsValid(molecule, n, interactionType))
        continue;

      Vector3 npos = molecule.atomPosition3d(n);
      double nradius = atomRadii[n];
      Vector3 distance_vector = npos - pos;

      if (distance_vector.norm() > m_maximumDistances[interactionType] + radius + nradius)
        continue;
      if (!checkAtomPairNotBonded(molecule, i, n))
        continue;

      float angleTolerance = m_angleTolerancesDegrees[interactionType] * M_PI / 180.0;
      if (!checkHoleVector(molecule, i, distance_vector, angleTolerance))
        continue;
      if (!checkPairVector(molecule, n, -distance_vector, angleTolerance))
        continue;

      lineGroups[interactionType]->addDashedLine(
        pos.cast<float>(), npos.cast<float>(), m_lineColors[interactionType], 8
      );
    }
  }
}

QWidget *NonCovalent::setupWidget()
{
  auto *widget = new QWidget(qobject_cast<QWidget *>(this->parent()));
  auto *v = new QVBoxLayout;
  auto *tabs = new QTabWidget;
  
  for (Index i = 0; i < 3; i++) {
  	// angle tolerance
		auto *angle_spin = new QDoubleSpinBox;
		angle_spin->setRange(0.0, 180.0);
		angle_spin->setSingleStep(1.0);
		angle_spin->setDecimals(0);
		angle_spin->setSuffix(tr(" °"));
		angle_spin->setValue(m_angleTolerancesDegrees[i]);
		QObject::connect(angle_spin, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this,
			[this, i](float tolerance){ return setAngleTolerance(tolerance, i); }
		);
		
		// maximum distance
		auto *distance_spin = new QDoubleSpinBox;
		distance_spin->setRange(1.0, 10.0);
		distance_spin->setSingleStep(0.1);
		distance_spin->setDecimals(1);
		distance_spin->setSuffix(tr(" Å"));
		distance_spin->setValue(m_maximumDistances[i]);
		QObject::connect(distance_spin, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this, 
			[this, i](float distance){ return setMaximumDistance(distance, i); }
		);
  
  	// line width
		auto* lineWidth_spin = new QDoubleSpinBox;
		lineWidth_spin->setRange(1.0, 10.0);
		lineWidth_spin->setSingleStep(0.5);
		lineWidth_spin->setDecimals(1);
		lineWidth_spin->setValue(m_lineWidths[i]);
		QObject::connect(lineWidth_spin, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this, 
		    [this, i](float width){ return setLineWidth(width, i); }
		);
		
		auto *form = new QFormLayout;
  	form->addRow(QObject::tr("Angle tolerance:"), angle_spin);
  	form->addRow(QObject::tr("Maximum distance:"), distance_spin);
  	form->addRow(QObject::tr("Line width:"), lineWidth_spin);
  	
  	auto *page = new QWidget;
  	page->setLayout(form);
  	tabs->addTab(page, INTERACTION_NAMES[i]);
  }
  
  v->addWidget(tabs);
  v->addStretch(1);
  widget->setLayout(v);
  return widget;
}

void NonCovalent::setAngleTolerance(float angleTolerance, Index index)
{
  m_angleTolerancesDegrees[index] = float(angleTolerance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue(QString("nonCovalent/angleTolerance%1").arg(index), angleTolerance);
}

void NonCovalent::setMaximumDistance(float maximumDistance, Index index)
{
  m_maximumDistances[index] = float(maximumDistance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue(QString("nonCovalent/maximumDistance%1").arg(index), maximumDistance);
}

void NonCovalent::setLineWidth(float width, Index index)
{
  m_lineWidths[index] = width;
  emit drawablesChanged();

  QSettings settings;
  settings.setValue(QString("nonCovalent/lineWidth%1").arg(index), width);
}

} // namespace Avogadro
