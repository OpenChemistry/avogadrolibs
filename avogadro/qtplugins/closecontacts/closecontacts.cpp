/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "closecontacts.h"

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
