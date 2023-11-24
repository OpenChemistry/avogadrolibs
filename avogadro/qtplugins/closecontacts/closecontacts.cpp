/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "closecontacts.h"

#include <avogadro/core/array.h>
#include <avogadro/core/atom.h>
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
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::Atom;
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
  m_maximumDistances = {
    settings.value("closeContacts/maximumDistance0", 2.0).toDouble(),
    settings.value("closeContacts/maximumDistance1", 4.0).toDouble(),
    settings.value("closeContacts/maximumDistance2", 4.0).toDouble()
  };
  auto contactColor = settings.value("closeContacts/lineColor0", QColor(128, 128, 128)).value<QColor>();
  auto saltBColor = settings.value("closeContacts/lineColor1", QColor(192, 0, 255)).value<QColor>();
  auto repulsiveColor = settings.value("closeContacts/lineColor2", QColor(255, 64, 64)).value<QColor>();
  m_lineColors = {
    Vector3ub(contactColor.red(), contactColor.green(), contactColor.blue()),
    Vector3ub(saltBColor.red(), saltBColor.green(), saltBColor.blue()),
    Vector3ub(repulsiveColor.red(), repulsiveColor.green(), repulsiveColor.blue())
  };
  m_lineWidths = {
    settings.value("closeContacts/lineWidth0", 2.0).toFloat(),
    settings.value("closeContacts/lineWidth1", 5.0).toFloat(),
    settings.value("closeContacts/lineWidth2", 5.0).toFloat()
  };
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

void addChargedAtom(
  Array<Vector3> &positions, Array<signed char> &charges, Array<Index> &residues,
  const Molecule &molecule, Index residueId, Atom atom, double charge
) {
  auto pos = molecule.atomPosition3d(atom.index());
  if (molecule.formalCharge(atom.index()) != 0) {
    for (Index i = 0; i < positions.size(); i++) {
      if ((positions[i] - pos).norm() < 0.00001) {
        residues[i] = residueId;
        return;
      }
    }
  }
  positions.push_back(pos);
  charges.push_back(charge);
  residues.push_back(residueId);
}

void CloseContacts::process(const Molecule &molecule, Rendering::GroupNode &node)
{
  //Add general contacts
  NeighborPerceiver perceiver(molecule.atomPositions3d(), m_maximumDistances[0]);
  std::vector<bool> isAtomEnabled(molecule.atomCount());
  for (Index i = 0; i < molecule.atomCount(); ++i)
    isAtomEnabled[i] = m_layerManager.atomEnabled(i);

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
      if (distance < m_maximumDistances[0])
        lineGroups[0]->addDashedLine(pos.cast<float>(), npos.cast<float>(), m_lineColors[0], 8);
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
    if (!r.residueName().compare("LYS")) {
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("NZ"), 1.0);
    } else if (!r.residueName().compare("ARG")) {
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("NE"), 1.0);
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("NH1"), 1.0);
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("NH2"), 1.0);
    } else if (!r.residueName().compare("HIS")) {
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("ND1"), 1.0);
    } else if (!r.residueName().compare("ASP")) {
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("OD1"), -1.0);
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("OD2"), -1.0);
    } else if (!r.residueName().compare("GLU")) {
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("OE1"), -1.0);
      addChargedAtom(positions, charges, residues, molecule, r.residueId(), r.getAtomByName("OE2"), -1.0);
    }
  }

  // detect contacts among them
  NeighborPerceiver ionPerceiver(positions, std::max(m_maximumDistances[1], m_maximumDistances[2]));
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
      
      if (charges[i] * charges[n] > 0.0 && distance < m_maximumDistances[2])
        lineGroups[2]->addDashedLine(pos.cast<float>(), npos.cast<float>(), m_lineColors[2], 8);
      else if (distance < m_maximumDistances[1])
        lineGroups[1]->addDashedLine(pos.cast<float>(), npos.cast<float>(), m_lineColors[1], 8);
    }
  }
}

QWidget *CloseContacts::setupWidget()
{
  auto *widget = new QWidget(qobject_cast<QWidget *>(this->parent()));
  auto *v = new QVBoxLayout;
  auto *tabs = new QTabWidget;

  for (Index i = 0; i < 3; i++) {
    // maximum distance
    auto *distance_spin = new QDoubleSpinBox;
    distance_spin->setRange(1.5, 10.0);
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

void CloseContacts::setMaximumDistance(float maximumDistance, Index index)
{
  m_maximumDistances[index] = maximumDistance;
  emit drawablesChanged();

  QSettings settings;
  settings.setValue(QString("closeContacts/maximumDistance%1").arg(index), maximumDistance);
}

void CloseContacts::setLineWidth(float width, Index index)
{
  m_lineWidths[index] = width;
  emit drawablesChanged();

  QSettings settings;
  settings.setValue(QString("closeContacts/lineWidth%1").arg(index), width);
}

} // namespace Avogadro
