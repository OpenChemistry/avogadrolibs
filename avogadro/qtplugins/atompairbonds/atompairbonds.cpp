/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "atompairbonds.h"

#include <avogadro/core/array.h>
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

namespace Avogadro {
namespace QtPlugins {

using Core::Array;
using Core::Bond;
using Core::NeighborPerceiver;
using QtGui::Molecule;
using QtGui::PluginLayerManager;
using Rendering::DashedLineGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

AtomPairBonds::AtomPairBonds(QObject *p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);
  
  QSettings settings;
  m_angleToleranceDegrees = settings.value("atomPairBonds/angleTolerance", 20.0).toDouble();
  m_maximumDistance = settings.value("atomPairBonds/maximumDistance", 2.0).toDouble();
  QColor hydrogenBColor = settings.value("atomPairBonds/lineColor0", QColor(64, 192, 255)).value<QColor>();
  m_lineColors = {
    Vector3ub(hydrogenBColor.red(), hydrogenBColor.green(), hydrogenBColor.blue())
  };
  m_lineWidths = {
    settings.value("atomPairBonds/lineWidth0", 2).toInt()
  };
}

AtomPairBonds::~AtomPairBonds() {}

enum InteractionTypes {
  NONE = -1,
  HYDROGEN_BOND = 0
};

static enum InteractionTypes getInteractionType(const Molecule &molecule, Index i) {
  unsigned char inum = molecule.atomicNumber(i);
  switch (inum) {
    case 1: // hydrogen bond
      for (const Bond *b : molecule.bonds(i)) {
        Index j = (b->atom1().index() == i ? b->atom2() : b->atom1()).index();
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

static bool checkPairDonorIsValid(const Molecule &molecule, Index n, int interactionType) {
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

static int checkAtomPairNotBonded(const Molecule &molecule, Index i, Index n) {
  Array<const Bond *> bonds = molecule.bonds(i);
  return std::all_of(bonds.begin(), bonds.end(), [i, n](const Bond *b)
    { return (b->atom1().index() == i ? b->atom2() : b->atom1()).index() != n; }
  );
}

void AtomPairBonds::process(const Molecule &molecule, Rendering::GroupNode &node)
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
  lines->setLineWidth(2.0);
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

      lines->addDashedLine(pos.cast<float>(), npos.cast<float>(), color, 8);
    }
  }
}

QWidget *AtomPairBonds::setupWidget()
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
  QObject::connect(angle_spin, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this, &AtomPairBonds::setAngleTolerance);
  
  // maximum distance
  QDoubleSpinBox *distance_spin = new QDoubleSpinBox;
  distance_spin->setRange(1.0, 10.0);
  distance_spin->setSingleStep(0.1);
  distance_spin->setDecimals(1);
  distance_spin->setSuffix(tr(" Å"));
  distance_spin->setValue(m_angleToleranceDegrees);
  QObject::connect(distance_spin, QOverload<double>::of(&QDoubleSpinBox::valueChanged), this, &AtomPairBonds::setMaximumDistance);
  
  QFormLayout *form = new QFormLayout;
  form->addRow(QObject::tr("Angle tolerance:"), angle_spin);
  form->addRow(QObject::tr("Maximum distance:"), distance_spin);
  v->addLayout(form);

  v->addStretch(1);
  widget->setLayout(v);
  return widget;
}

void AtomPairBonds::setAngleTolerance(float angleTolerance)
{
  m_angleToleranceDegrees = float(angleTolerance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("atomPairBonds/angleTolerance", m_angleToleranceDegrees);
}

void AtomPairBonds::setMaximumDistance(float maximumDistance)
{
  m_maximumDistance = float(maximumDistance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("atomPairBonds/maximumDistance", m_maximumDistance);
}

} // namespace QtPlugins
} // namespace Avogadro
