/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "closecontacts.h"

#include <avogadro/core/array.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/neighborperceiver.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/dashedlinegeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QtCore/QSettings>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::Bond;
using Core::NeighborPerceiver;
using QtGui::Molecule;
using QtGui::PluginLayerManager;
using Rendering::DashedLineGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

CloseContacts::CloseContacts(QObject *p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);
  
  QSettings settings;
  m_maximumDistance = settings.value("closeContacts/maximumDistance", 2.5).toDouble();
}

CloseContacts::~CloseContacts() {}

static bool checkPairNot1213(const Molecule &molecule, Index i, Index n)
{
  static Array<Index> bondedCache;
  static Index lastIndex;
  static bool lastIndexValid = false;

  if (!lastIndexValid || lastIndex != i) {
    bondedCache.clear();
    for (const Bond *b : molecule.bonds(i))
      bondedCache.push_back(b->atom1().index() == i ? b->atom2().index() : b->atom1().index());
    lastIndex = i;
    lastIndexValid = true;
  }

  for (const Bond *b : molecule.bonds(n)) {
    Index m = (b->atom1().index() == n ? b->atom2() : b->atom1()).index();
    if (m == i) // exclude 1-2 pairs
      return false;
    for (Index bn: bondedCache)
      if (bn == m) // exclude 1-3 pairs
        return false;
  }
  return true;
}

void CloseContacts::process(const Molecule &molecule, Rendering::GroupNode &node)
{
  Vector3ub color(128, 128, 128);

  //Add general contacts
  NeighborPerceiver perceiver(molecule.atomPositions3d(), m_maximumDistance);
  std::vector<bool> isAtomEnabled(molecule.atomCount());
  for (Index i = 0; i < molecule.atomCount(); ++i)
    isAtomEnabled[i] = m_layerManager.atomEnabled(i);

  auto *geometry = new GeometryNode;
  node.addChild(geometry);
  auto *lines = new DashedLineGeometry;
  lines->identifier().molecule = &molecule;
  lines->identifier().type = Rendering::BondType;
  lines->setLineWidth(2.0);
  geometry->addDrawable(lines);
  Array<Index> neighbors;
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    if (!isAtomEnabled[i])
      continue;
    Vector3 pos = molecule.atomPosition3d(i);
    perceiver.getNeighborsInclusiveInPlace(neighbors, pos);
    for (Index n : neighbors) {
      if (n <= i) // check each pair only once
        continue;
      if (!isAtomEnabled[n])
        continue;
      if (!checkPairNot1213(molecule, i, n))
        continue;

      Vector3 npos = molecule.atomPosition3d(n);
      double distance = (npos - pos).norm();
      if (distance < m_maximumDistance)
        lines->addDashedLine(pos.cast<float>(), npos.cast<float>(), color, 8);
    }
  }

  // Add charged atoms
  Array<Vector3> positions;
  Array<signed char> charges;
  Array<Index> residues;
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    if (molecule.formalCharge(i) != 0) {
      if (!isAtomEnabled[i])
        continue;
      positions.push_back(molecule.atomPosition3d(i));
      charges.push_back(molecule.formalCharge(i));
      residues.push_back(Index(0) - 1);
    }
  }

  // Add predicted charged atoms from residues
  for (const auto &r: molecule.residues()) {
    for (const auto &a: r.residueAtoms()) {
      if (molecule.formalCharge(a.index()) != 0)
        continue;
      bool gammaOxygen = false;
      bool doubleBond = false;
      bool alphaDoubleBond = false;
      auto bonds = molecule.getAtomBonds(a.index());
      auto orders = molecule.getAtomOrders(a.index());
      for (Index i = 0; i < bonds.size(); i++) {
        Index b = bonds[i].first == a.index() ? bonds[i].second : bonds[i].first;
        if (molecule.atomicNumber(b) == 6) {
          if (orders[i] == 2)
            alphaDoubleBond = true;
          auto bonds2 = molecule.getAtomBonds(b);
          auto orders2 = molecule.getAtomOrders(b);
          for (Index j = 0; j < orders2.size(); j++) {
            if (orders2[j] == 2)
              doubleBond = true;
            Index c = bonds2[j].first == b ? bonds2[j].second : bonds2[j].first;
            if (molecule.atomicNumber(c) == 8 && c != a.index())
              gammaOxygen = true;
          }
        }
      }
      // Check what residue atom we are on
      switch (molecule.atomicNumber(a.index())) {
        case 7:
          if (!gammaOxygen && !(
            !r.residueName().compare("HIS") && !alphaDoubleBond ||
            !r.residueName().compare("TRP") && doubleBond
          )) {
            positions.push_back(molecule.atomPosition3d(a.index()));
            charges.push_back(1.0);
            residues.push_back(r.residueId());
          }
          break;
        case 8:
          if (gammaOxygen && doubleBond) {
            positions.push_back(molecule.atomPosition3d(a.index()));
            charges.push_back(-1.0);
            residues.push_back(r.residueId());
          }
          break;
      }
    }
  }

  // detect contacts among them
  NeighborPerceiver ionPerceiver(positions, 4.0);
  for (Index i = 0; i < positions.size(); ++i) {
    const Vector3 &pos = positions[i];
    ionPerceiver.getNeighborsInclusiveInPlace(neighbors, pos);
    for (Index n: neighbors) {
      if (n <= i) // check each pair only once
        continue;
      if (residues[n] == residues[i] && residues[i] != Index(0) - 1)
        continue; // ignore intra-residue interactions

      Vector3 npos = positions[n];
      double distance = (npos - pos).norm();
      if (distance < 4.0) {
        if (charges[i] * charges[n] > 0.0)
          lines->addDashedLine(pos.cast<float>(), npos.cast<float>(), Vector3ub(255, 0, 0), 8);
        else
          lines->addDashedLine(pos.cast<float>(), npos.cast<float>(), Vector3ub(255, 0, 255), 8);
      }
    }
  }
}

QWidget *CloseContacts::setupWidget()
{
  auto *widget = new QWidget(qobject_cast<QWidget *>(this->parent()));
  auto *v = new QVBoxLayout;

  // maximum distance
  auto *spin = new QDoubleSpinBox;
  spin->setRange(1.5, 10.0);
  spin->setSingleStep(0.1);
  spin->setDecimals(1);
  spin->setSuffix(tr(" Å"));
  spin->setValue(m_maximumDistance);
  QObject::connect(spin, SIGNAL(valueChanged(double)), this,
                   SLOT(setMaximumDistance(double)));
  auto *form = new QFormLayout;
  form->addRow(QObject::tr("Maximum distance:"), spin);
  v->addLayout(form);

  v->addStretch(1);
  widget->setLayout(v);
  return widget;
}

void CloseContacts::setMaximumDistance(double maximumDistance)
{
  m_maximumDistance = float(maximumDistance);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("closeContacts/maximumDistance", m_maximumDistance);
}

} // namespace Avogadro
