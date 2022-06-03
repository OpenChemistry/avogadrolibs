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
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

#include <iostream>

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
}

AtomPairBonds::~AtomPairBonds() {}

static const int HYDROGEN_BOND = 0;

static const float MAX_DISTANCES[] = {2.0};

static const float ABSOLUTE_MAX_DISTANCE = 2.0;

static int getInteractionType(const Molecule &molecule, Index i) {
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
  return -1;
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
  for (const Bond *b : molecule.bonds(i))
    if ((b->atom1().index() == i ? b->atom2() : b->atom1()).index() == n)
      return false;
  return true;
}

void AtomPairBonds::process(const Molecule &molecule, Rendering::GroupNode &node)
{
  float radius(0.1f);
  Vector3ub color(64, 192, 255);

  NeighborPerceiver perceiver(molecule.atomPositions3d(), ABSOLUTE_MAX_DISTANCE);
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
    int interactionType = getInteractionType(molecule, i);
    if (interactionType < 0)
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

      if (distance_vector.norm() > MAX_DISTANCES[interactionType])
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

  // maximum distance
  QDoubleSpinBox *spin = new QDoubleSpinBox;
  spin->setRange(0.0, 180.0);
  spin->setSingleStep(1.0);
  spin->setDecimals(0);
  spin->setSuffix(tr(" °"));
  spin->setValue(m_angleToleranceDegrees);
  QObject::connect(spin, SIGNAL(valueChanged(double)), this,
                   SLOT(setMaximumDistance(double)));
  QFormLayout *form = new QFormLayout;
  //form->addRow(QObject::tr("Angle tolerance:"), spin);
  v->addLayout(form);

  v->addStretch(1);
  widget->setLayout(v);
  return widget;
}

void AtomPairBonds::setAngleTolerance(double angleTolerance)
{
  m_angleToleranceDegrees = float(angleTolerance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("atomPairBonds/angleTolerance", m_angleToleranceDegrees);
}

} // namespace QtPlugins
} // namespace Avogadro
