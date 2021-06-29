/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cartoons.h"

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/beziergeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <functional>
#include <list>
#include <utility>
#include <vector>

#include <iostream>

namespace Avogadro {
namespace QtPlugins {

using Core::AtomicNumber;
using Core::Elements;
using Core::Molecule;
using Rendering::BezierGeometry;
using Rendering::BSplineGeometry;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;
using std::list;
using std::map;
using std::pair;
using std::reference_wrapper;
using std::vector;

typedef list<pair<const Core::Atom, const Core::Atom>> AtomsPairList;

Cartoons::Cartoons(QObject* parent)
  : ScenePlugin(parent), m_group(nullptr), m_setupWidget(nullptr),
    m_enabled(false), m_showBackbone(false), m_showTrace(false),
    m_showTube(true), m_showRibbon(false), m_showRope(false),
    m_showCartoon(false)
{}

Cartoons::~Cartoons()
{
  if (m_setupWidget)
    m_setupWidget->deleteLater();
}

map<size_t, AtomsPairList> getBackboneByResidues(const Molecule& molecule)
{
  auto graph = molecule.graph();
  map<size_t, AtomsPairList> result;
  for (const auto& residue : molecule.residues()) {
    if (!residue.isHeterogen()) {
      Core::Atom ac = residue.getAtomByName("CA");
      Core::Atom h = residue.getAtomByName("H");
      if (ac.isValid()) {
        size_t index = graph.getConnectedID(ac.index());
        if (result.find(index) == result.end()) {
          result[index] = AtomsPairList();
        }
        result[index].push_back(std::make_pair(ac, h));
      }
    }
  }
  return result;
}

map<size_t, AtomsPairList> getBackboneManually(const Molecule& molecule)
{
  // manual filter
  map<size_t, AtomsPairList> result;
  return result;
}

void renderBackbone(const AtomsPairList& backbone, const Molecule& molecule,
                    Rendering::GroupNode& node)
{
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

  Index i = 0;
  float bondRadius = 0.1f;
  for (AtomsPairList::const_iterator it = backbone.begin();
       it != backbone.end(); ++it) {
    const auto& atom = *it;
    Vector3ub color = atom.first.color();
    Vector3f pos = atom.first.position3d().cast<float>();
    spheres->addSphere(pos, color, bondRadius);
    if (std::next(it) != backbone.end()) {
      const auto& nextAtom = *std::next(it);
      Vector3f pos = atom.first.position3d().cast<float>();
      Vector3f pos2 = nextAtom.first.position3d().cast<float>();
      Vector3ub color = atom.first.color();
      Vector3ub color2 = nextAtom.first.color();
      Vector3f bondVector = pos2 - pos;
      float bondLength = bondVector.norm();
      bondVector /= bondLength;
      cylinders->addCylinder(pos, pos2, bondRadius, color, color2, i);
    }
    ++i;
  }
}

void renderRope(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BezierGeometry* bezier = new BezierGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::BondType;
  geometry->addDrawable(bezier);

  float bondRadius = 1.0f;
  for (const auto& atom : backbone) {
    Vector3ub color = atom.first.color();
    Vector3f pos = atom.first.position3d().cast<float>();
    bezier->addPoint(pos, color, bondRadius, 0);
  }
}

void renderTube(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node, float bondRadius)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BSplineGeometry* bezier = new BSplineGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::BondType;
  geometry->addDrawable(bezier);

  for (const auto& atom : backbone) {
    Vector3ub color = atom.first.color();
    Vector3f pos = atom.first.position3d().cast<float>();
    bezier->addPoint(pos, color, bondRadius, 0);
  }
}

void Cartoons::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  if (m_showBackbone || m_showTrace || m_showTube || m_showRibbon ||
      m_showCartoon || m_showRope) {
    map<size_t, AtomsPairList> alphaAndHydrogens;
    if (molecule.residues().size() > 0) {
      alphaAndHydrogens = getBackboneByResidues(molecule);
    }
    if (alphaAndHydrogens.size() == 0) {
      alphaAndHydrogens = getBackboneManually(molecule);
    }
    for (const auto& group : alphaAndHydrogens) {
      const auto& alphaAndHydrogen = group.second;
      m_group = &node;
      if (m_showBackbone) {
        renderBackbone(alphaAndHydrogen, molecule, node);
      }
      if (m_showTrace) {
        renderTube(alphaAndHydrogen, molecule, node, -0.15f);
      }
      if (m_showTube) {
        renderTube(alphaAndHydrogen, molecule, node, 0.15f);
      }
      if (m_showRibbon) {
      }
      if (m_showCartoon) {
      }
      if (m_showRope) {
        renderRope(alphaAndHydrogen, molecule, node);
      }
    }
  }
} // namespace QtPlugins

void Cartoons::processEditable(const QtGui::RWMolecule& molecule,
                               Rendering::GroupNode& node)
{}

bool Cartoons::isEnabled() const
{
  return m_enabled;
}

void Cartoons::setEnabled(bool enable)
{
  m_enabled = enable;
}

QWidget* Cartoons::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    QVBoxLayout* v = new QVBoxLayout;
    const char* boxesText[] = { "Backbone", "Trace",   "Tube",
                                "Ribbon",   "Cartoon", "Rope" };
    vector<reference_wrapper<bool>> boxesBools = { m_showBackbone, m_showTrace,
                                                   m_showTube,     m_showRibbon,
                                                   m_showCartoon,  m_showRope };
    m_jumpTable[0] = &Cartoons::showBackbone;
    m_jumpTable[1] = &Cartoons::showTrace;
    m_jumpTable[2] = &Cartoons::showTube;
    m_jumpTable[3] = &Cartoons::showRibbon;
    m_jumpTable[4] = &Cartoons::showCartoon;
    m_jumpTable[5] = &Cartoons::showRope;
    for (size_t i = 0; i < 6; ++i) {
      QCheckBox* check = new QCheckBox(tr(boxesText[i]));
      check->setChecked(boxesBools[i]);
      connect(check, &QCheckBox::clicked, this, m_jumpTable[i]);
      v->addWidget(check);
    }

    m_setupWidget->setLayout(v);
  }
  return m_setupWidget;
}

void Cartoons::showBackbone(bool show)
{
  if (show != m_showBackbone) {
    m_showBackbone = show;
    emit drawablesChanged();
  }
}

void Cartoons::showTrace(bool show)
{
  if (show != m_showTrace) {
    m_showTrace = show;
    emit drawablesChanged();
  }
}

void Cartoons::showTube(bool show)
{
  if (show != m_showTube) {
    m_showTube = show;
    emit drawablesChanged();
  }
}

void Cartoons::showRibbon(bool show)
{
  if (show != m_showRibbon) {
    m_showRibbon = show;
    emit drawablesChanged();
  }
}

void Cartoons::showCartoon(bool show)
{
  if (show != m_showCartoon) {
    m_showCartoon = show;
    emit drawablesChanged();
  }
}

void Cartoons::showRope(bool show)
{
  if (show != m_showRope) {
    m_showRope = show;
    emit drawablesChanged();
  }
}

} // namespace QtPlugins
} // namespace Avogadro
