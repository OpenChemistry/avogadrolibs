/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cartoons.h"

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/rendering/beziergeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <functional>
#include <iostream>
#include <list>
#include <utility>
#include <vector>

namespace Avogadro {
namespace QtPlugins {

using Core::Atom;
using Core::AtomicNumber;
using Core::Elements;
using Core::Molecule;
using Core::Residue;
using Rendering::BezierGeometry;
using Rendering::BSplineGeometry;
using Rendering::Cartoon;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;
using std::list;
using std::map;
using std::pair;
using std::reference_wrapper;
using std::vector;

struct BackboneResidue
{
  BackboneResidue() {}
  BackboneResidue(const Vector3f p, const Vector3ub& c1, const Vector3ub& c2,
                  const size_t& g, size_t id, bool sel,
                  Residue::SecondaryStructure sec)
    : pos(p), color1(c1), color2(c2), group(g), residueID(id), selected(sel),
      secondaryStructure(sec)

  {}
  Vector3f pos;
  Vector3ub color1;
  Vector3ub color2;
  size_t group;
  size_t residueID;
  bool selected;
  Residue::SecondaryStructure secondaryStructure;
};

typedef list<BackboneResidue> AtomsPairList;

Cartoons::Cartoons(QObject* parent)
  : ScenePlugin(parent), m_group(nullptr), m_setupWidget(nullptr),
    m_enabled(true)
{
  QSettings settings;
  m_showBackbone = settings.value("cartoon/backbone", true).toBool();
  m_showSimpleCartoon = settings.value("cartoon/simpleCartoon", true).toBool();
  m_showCartoon = settings.value("cartoon/Cartoon", true).toBool();
  m_showTrace = settings.value("cartoon/trace", false).toBool();
  m_showTube = settings.value("cartoon/tube", false).toBool();
  m_showRibbon = settings.value("cartoon/ribbon", false).toBool();
  m_showRope = settings.value("cartoon/rope", false).toBool();
}

Cartoons::~Cartoons()
{
  if (m_setupWidget)
    m_setupWidget->deleteLater();
}

void addBackBone(map<size_t, AtomsPairList>& result,
                 map<size_t, BackboneResidue>& previousCA, const Atom& caAtom,
                 const Vector3ub& color, Index group,
                 Residue::SecondaryStructure sec)
{
  Vector3ub color1;
  if (result.find(group) == result.end()) {
    result[group] = AtomsPairList();
    color1 = Vector3ub(0, 0, 0);
  } else {
    color1 = previousCA[group].color2;
  }

  Vector3f ca = caAtom.position3d().cast<float>();
  BackboneResidue backBone = BackboneResidue(
    ca, color1, color, group, caAtom.index(), caAtom.selected(), sec);
  // the 1º insertion will always be incompleated, so fix it
  if (result[group].size() == 1) {
    result[group].front().color1 = color1;
  }
  previousCA[group] = backBone;
  result[group].push_back(backBone);
}

map<size_t, AtomsPairList> getBackboneByResidues(const Molecule& molecule)
{
  const auto& graph = molecule.graph();
  map<size_t, AtomsPairList> result;
  map<size_t, BackboneResidue> previousCA;
  for (const auto& residue : molecule.residues()) {
    if (!residue.isHeterogen()) {
      Atom caAtom = residue.getAtomByName("CA");
      Atom oAtom = residue.getAtomByName("O");
      if (caAtom.isValid() && oAtom.isValid()) {
        // get the group ID and check if it's initialized in the map
        size_t group = graph.getConnectedID(caAtom.index());
        addBackBone(result, previousCA, caAtom, residue.color(), group,
                    residue.secondaryStructure());
      }
    }
  }
  return result;
}

map<size_t, AtomsPairList> getBackboneManually(const Molecule& molecule)
{
  // manual filter
  const auto& graph = molecule.graph();
  map<size_t, AtomsPairList> result;
  map<size_t, BackboneResidue> previousCA;

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    const auto atom = molecule.atom(i);
    if (atom.atomicNumber() == AtomicNumber::Carbon) {
      size_t group = graph.getConnectedID(atom.index());
      addBackBone(result, previousCA, atom, atom.color(), group,
                  Residue::SecondaryStructure::undefined);
    }
  }
  return result;
}

void renderBackbone(const AtomsPairList& backbone, const Molecule& molecule,
                    Rendering::GroupNode& node, float radius)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  SphereGeometry* spheres = new SphereGeometry;
  spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  CylinderGeometry* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::AtomType;
  geometry->addDrawable(cylinders);

  Index i = 0;
  for (AtomsPairList::const_iterator it = backbone.begin();
       it != backbone.end(); ++it) {
    const auto& bone = *it;
    auto color1 = bone.color1;
    auto color2 = bone.color2;
    if (bone.selected) {
      color1 += Vector3ub(155, 0, 0);
      color2 += Vector3ub(155, 0, 0);
    }
    const Vector3f& pos = bone.pos;
    spheres->addSphere(pos, color1, radius, bone.residueID);
    if (std::next(it) != backbone.end()) {
      const auto& nextBone = *std::next(it);
      const Vector3f& pos2 = nextBone.pos;
      cylinders->addCylinder(pos, pos2, radius, color1, color2, bone.residueID);
    }
    ++i;
  }
}

void renderRope(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node, float radius)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BezierGeometry* bezier = new BezierGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::AtomType;
  geometry->addDrawable(bezier);

  Vector3ub color = Vector3ub::Zero();
  for (const auto& bone : backbone) {
    bezier->addPoint(bone.pos, bone.color1 + color, radius, bone.group,
                     bone.residueID);
    color = bone.selected ? Vector3ub(155, 0, 0) : Vector3ub::Zero();
  }
}

void renderTube(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node, float radius)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BSplineGeometry* bezier = new BSplineGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::AtomType;
  geometry->addDrawable(bezier);

  Vector3ub color = Vector3ub::Zero();
  for (const auto& bone : backbone) {
    bezier->addPoint(bone.pos, bone.color1 + color, radius, bone.group,
                     bone.residueID);
    color = bone.selected ? Vector3ub(155, 0, 0) : Vector3ub::Zero();
  }
}

void renderSimpleCartoon(const AtomsPairList& backbone,
                         const Molecule& molecule, Rendering::GroupNode& node,
                         float radius)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  Cartoon* cartoon = new Cartoon;
  cartoon->identifier().molecule = &molecule;
  cartoon->identifier().type = Rendering::AtomType;
  geometry->addDrawable(cartoon);
  Vector3ub color = Vector3ub::Zero();
  for (const auto& bone : backbone) {
    cartoon->CurveGeometry::addPoint(bone.pos, bone.color1 + color, radius,
                                     bone.group, bone.residueID);
    color = bone.selected ? Vector3ub(155, 0, 0) : Vector3ub::Zero();
  }
}

void renderCartoon(const AtomsPairList& backbone, const Molecule& molecule,
                   Rendering::GroupNode& node, float radius)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  Cartoon* cartoon = new Cartoon(radius * 0.2f, radius * 1.5f);
  cartoon->identifier().molecule = &molecule;
  cartoon->identifier().type = Rendering::AtomType;
  geometry->addDrawable(cartoon);
  Vector3ub color = Vector3ub::Zero();
  for (const auto& bone : backbone) {
    cartoon->addPoint(bone.pos, bone.color1 + color, bone.group, bone.residueID,
                      bone.secondaryStructure);
    color = bone.selected ? Vector3ub(155, 0, 0) : Vector3ub::Zero();
  }
}

void Cartoons::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  m_group = &node;
  if (m_showBackbone || m_showTrace || m_showTube || m_showRibbon ||
      m_showSimpleCartoon || m_showCartoon || m_showRope) {
    map<size_t, AtomsPairList> backbones;
    if (molecule.residues().size() > 0) {
      backbones = getBackboneByResidues(molecule);
    }
    if (backbones.size() == 0) {
      backbones = getBackboneManually(molecule);
    }
    for (const auto& group : backbones) {
      const auto& backbone = group.second;
      if (m_showBackbone) {
        renderBackbone(backbone, molecule, node, 0.1f);
      }
      if (m_showTrace) {
        renderTube(backbone, molecule, node, -0.15f);
      }
      if (m_showTube) {
        renderTube(backbone, molecule, node, 0.15f);
      }
      if (m_showRibbon) {
        renderCartoon(backbone, molecule, node, -1.0f * Cartoon::ELIPSE_RATIO);
      }
      if (m_showSimpleCartoon) {
        renderSimpleCartoon(backbone, molecule, node, 1.0f);
      }
      if (m_showCartoon) {
        renderCartoon(backbone, molecule, node, 1.0f);
      }
      if (m_showRope) {
        renderRope(backbone, molecule, node, 1.0f);
      }
    }
  }
}

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
    QStringList boxesText;
    boxesText << tr("Backbone", "protein rendering style")
              << tr("Trace", "protein rendering style")
              << tr("Tube", "protein rendering style")
              << tr("Ribbon", "protein rendering style")
              << tr("Simple Cartoon", "protein rendering style")
              << tr("Cartoon", "protein rendering style")
              << tr("Rope", "protein rendering style");
    vector<reference_wrapper<bool>> boxesBools = {
      m_showBackbone,      m_showTrace,   m_showTube, m_showRibbon,
      m_showSimpleCartoon, m_showCartoon, m_showRope
    };
    m_jumpTable[0] = &Cartoons::showBackbone;
    m_jumpTable[1] = &Cartoons::showTrace;
    m_jumpTable[2] = &Cartoons::showTube;
    m_jumpTable[3] = &Cartoons::showRibbon;
    m_jumpTable[4] = &Cartoons::showSimpleCartoon;
    m_jumpTable[5] = &Cartoons::showCartoon;
    m_jumpTable[6] = &Cartoons::showRope;
    for (size_t i = 0; i < boxesText.size(); ++i) {
      QCheckBox* check = new QCheckBox(boxesText[i]);
      check->setChecked(boxesBools[i]);
      connect(check, &QCheckBox::clicked, this, m_jumpTable[i]);
      v->addWidget(check);
    }

    // make sure there's empty space at the bottom,s otherwise the
    v->addStretch(1);
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
  QSettings settings;
  settings.setValue("cartoon/backbone", show);
}

void Cartoons::showTrace(bool show)
{
  if (show != m_showTrace) {
    m_showTrace = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/trace", show);
}

void Cartoons::showTube(bool show)
{
  if (show != m_showTube) {
    m_showTube = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/tube", show);
}

void Cartoons::showRibbon(bool show)
{
  if (show != m_showRibbon) {
    m_showRibbon = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/ribbon", show);
}

void Cartoons::showSimpleCartoon(bool show)
{
  if (show != m_showSimpleCartoon) {
    m_showSimpleCartoon = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/simpleCartoon", show);
}

void Cartoons::showCartoon(bool show)
{
  if (show != m_showCartoon) {
    m_showCartoon = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/cartoon", show);
}

void Cartoons::showRope(bool show)
{
  if (show != m_showRope) {
    m_showRope = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/rope", show);
}

} // namespace QtPlugins
} // namespace Avogadro
