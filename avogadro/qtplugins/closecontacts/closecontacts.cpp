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
#include <avogadro/rendering/linestripgeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QtCore/QSettings>
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
using Rendering::LineStripGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

CloseContacts::CloseContacts(QObject* p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);
  
  QSettings settings;
  m_maximumDistance = settings.value("closeContacts/maximumDistance", 2.5).toDouble();
}

CloseContacts::~CloseContacts() {}

void CloseContacts::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  float radius(0.1f);
  Vector3ub color(128, 255, 64);
  Array<Vector3ub> colors;
  colors.push_back(color);
  colors.push_back(color);

  NeighborPerceiver perceiver(molecule.atomPositions3d(), m_maximumDistance);

  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);
  LineStripGeometry* lines = new LineStripGeometry;
  lines->identifier().molecule = &molecule;
  lines->identifier().type = Rendering::BondType;
  geometry->addDrawable(lines);
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Vector3 pos = molecule.atomPosition3d(i);
    Array<Index> bonded;
    for (const Bond *b : molecule.bonds(i))
      bonded.push_back(b->atom1().index() == i ? b->atom2().index() : b->atom1().index());
    for (Index n : perceiver.getNeighbors(pos)) {
      if (n <= i)
        continue;
      bool go_on = false;
      for (const Bond *b : molecule.bonds(n)) {
        Index m = (b->atom1().index() == n ? b->atom2() : b->atom1()).index();
        if (m == i) {
          go_on = true;
          break;
        }
        for (Index bn: bonded) {
          if (bn == m) {
            go_on = true;
            break;
          }
        }
      }
      if (go_on)
        continue;

      Vector3 npos = molecule.atomPosition3d(n);
      double distance = (npos - pos).norm();
      if (distance < m_maximumDistance) {
        Array<Vector3f> points;
        points.push_back(pos.cast<float>());
        points.push_back(npos.cast<float>());
        lines->addLineStrip(points, colors, radius);
      }
    }
  }
}

QWidget* CloseContacts::setupWidget()
{
  QWidget *widget = new QWidget(qobject_cast<QWidget*>(this->parent()));
  QVBoxLayout *v = new QVBoxLayout;

  // maximum distance
  QDoubleSpinBox *spin = new QDoubleSpinBox;
  spin->setRange(1.5, 10.0);
  spin->setSingleStep(0.1);
  spin->setDecimals(1);
  spin->setSuffix(tr(" Å"));
  spin->setValue(m_maximumDistance);
  QObject::connect(spin, SIGNAL(valueChanged(double)), this,
                   SLOT(setMaximumDistance(double)));
  QFormLayout *form = new QFormLayout;
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

} // namespace QtPlugins
} // namespace Avogadro
