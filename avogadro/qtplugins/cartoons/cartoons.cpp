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
#include <utility>
#include <vector>

namespace Avogadro {
namespace QtPlugins {

using Core::Atom;
using Core::AtomicNumber;
using Core::Elements;
using Core::Residue;
using QtGui::Molecule;
using QtGui::PluginLayerManager;
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

struct LayerCartoon : Core::LayerData
{
  QWidget* widget;
  bool showBackbone;
  bool showTrace;
  bool showTube;
  bool showRibbon;
  bool showSimpleCartoon;
  bool showCartoon;
  bool showRope;

  typedef void (Cartoons::*JumpTable)(bool);
  JumpTable jumpTable[7];

  std::string serialize() override final
  {
    return boolToString(showBackbone) + " " + boolToString(showTrace) + " " +
           boolToString(showTube) + " " + boolToString(showRibbon) + " " +
           boolToString(showSimpleCartoon) + " " + boolToString(showCartoon) +
           " " + boolToString(showRope);
  }
  void deserialize(std::string text) override final
  {
    std::stringstream ss(text);
    std::string aux;
    ss >> aux;
    showBackbone = stringToBool(aux);
    ss >> aux;
    showTrace = stringToBool(aux);
    ss >> aux;
    showTube = stringToBool(aux);
    ss >> aux;
    showRibbon = stringToBool(aux);
    ss >> aux;
    showSimpleCartoon = stringToBool(aux);
    ss >> aux;
    showCartoon = stringToBool(aux);
    ss >> aux;
    showRope = stringToBool(aux);
  }

  void setupWidget(Cartoons* slot)
  {
    if (!widget) {
      widget = new QWidget(qobject_cast<QWidget*>(slot->parent()));
      QVBoxLayout* v = new QVBoxLayout;
      QStringList boxesText;
      boxesText << QObject::tr("Backbone", "protein rendering style")
                << QObject::tr("Trace", "protein rendering style")
                << QObject::tr("Tube", "protein rendering style")
                << QObject::tr("Ribbon", "protein rendering style")
                << QObject::tr("Simple Cartoon", "protein rendering style")
                << QObject::tr("Cartoon", "protein rendering style")
                << QObject::tr("Rope", "protein rendering style");
      vector<reference_wrapper<bool>> boxesBools = {
        showBackbone,      showTrace,   showTube, showRibbon,
        showSimpleCartoon, showCartoon, showRope
      };
      jumpTable[0] = &Cartoons::showBackbone;
      jumpTable[1] = &Cartoons::showTrace;
      jumpTable[2] = &Cartoons::showTube;
      jumpTable[3] = &Cartoons::showRibbon;
      jumpTable[4] = &Cartoons::showSimpleCartoon;
      jumpTable[5] = &Cartoons::showCartoon;
      jumpTable[6] = &Cartoons::showRope;
      for (size_t i = 0; i < boxesText.size(); ++i) {
        QCheckBox* check = new QCheckBox(boxesText[i]);
        check->setChecked(boxesBools[i]);
        QObject::connect(check, &QCheckBox::clicked, slot, jumpTable[i]);
        v->addWidget(check);
      }
      // make sure there's empty space at the bottom,s otherwise the
      v->addStretch(1);
      widget->setLayout(v);
    }
  }

  LayerCartoon()
  {
    widget = nullptr;
    QSettings settings;
    showBackbone = settings.value("cartoon/backbone", true).toBool();
    showCartoon = settings.value("cartoon/cartoon", true).toBool();
    showTrace = settings.value("cartoon/trace", false).toBool();
    showTube = settings.value("cartoon/tube", false).toBool();
    showRibbon = settings.value("cartoon/ribbon", false).toBool();
    showRope = settings.value("cartoon/rope", false).toBool();
    showSimpleCartoon = settings.value("cartoon/simplecartoon", true).toBool();
  }

  ~LayerCartoon()
  {
    if (widget)
      widget->deleteLater();
  }
};

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

Cartoons::Cartoons(QObject* parent) : ScenePlugin(parent), m_group(nullptr)
{
  m_layerManager = PluginLayerManager(m_name);
}

Cartoons::~Cartoons() {}

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

map<size_t, AtomsPairList> Cartoons::getBackboneByResidues(
  const Molecule& molecule, size_t layer)
{
  const auto& graph = molecule.graph();
  map<size_t, AtomsPairList> result;
  map<size_t, BackboneResidue> previousCA;
  for (const auto& residue : molecule.residues()) {
    if (!residue.isHeterogen()) {
      Atom caAtom = residue.getAtomByName("CA");
      Atom oAtom = residue.getAtomByName("O");
      if (caAtom.isValid() && oAtom.isValid() &&
          m_layerManager.atomEnabled(layer, caAtom.index()) &&
          m_layerManager.atomEnabled(layer, oAtom.index())) {
        // get the group ID and check if it's initialized in the map
        size_t group = graph.getConnectedID(caAtom.index());
        addBackBone(result, previousCA, caAtom, residue.color(), group,
                    residue.secondaryStructure());
      }
    }
  }
  return result;
}

map<size_t, AtomsPairList> Cartoons::getBackboneManually(
  const Molecule& molecule, size_t layer)
{
  // manual filter
  const auto& graph = molecule.graph();
  map<size_t, AtomsPairList> result;
  map<size_t, BackboneResidue> previousCA;

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    const auto atom = molecule.atom(i);
    if (atom.atomicNumber() == AtomicNumber::Carbon &&
        m_layerManager.atomEnabled(layer, atom.index())) {
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
  m_layerManager.load<LayerCartoon>();
  m_group = &node;
  for (size_t layer = 0; layer < m_layerManager.layerCount(); ++layer) {
    LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>(layer);
    if (interface.showBackbone || interface.showTrace || interface.showTube ||
        interface.showRibbon || interface.showSimpleCartoon ||
        interface.showCartoon || interface.showRope) {
      map<size_t, AtomsPairList> backbones;
      if (molecule.residues().size() > 0) {
        backbones = getBackboneByResidues(molecule, layer);
      }
      if (backbones.size() == 0) {
        continue; // maybe something in a different layer
      }
      size_t i = 0;
      for (const auto& group : backbones) {
        const auto& backbone = group.second;
        if (interface.showBackbone) {
          renderBackbone(backbone, molecule, node, 0.1f);
        }
        if (interface.showTrace) {
          renderTube(backbone, molecule, node, -0.15f);
        }
        if (interface.showTube) {
          renderTube(backbone, molecule, node, 0.15f);
        }
        if (interface.showRibbon) {
          renderCartoon(backbone, molecule, node,
                        -1.0f * Cartoon::ELIPSE_RATIO);
        }
        if (interface.showSimpleCartoon) {
          renderSimpleCartoon(backbone, molecule, node, 1.0f);
        }
        if (interface.showCartoon) {
          renderCartoon(backbone, molecule, node, 1.0f);
        }
        if (interface.showRope) {
          renderRope(backbone, molecule, node, 1.0f);
        }
        ++i;
      }
    }
  }
}

QWidget* Cartoons::setupWidget()
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  interface.setupWidget(this);
  return interface.widget;
}

void Cartoons::showBackbone(bool show)
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  if (show != interface.showBackbone) {
    interface.showBackbone = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/backbone", show);
}

void Cartoons::showTrace(bool show)
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  if (show != interface.showTrace) {
    interface.showTrace = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/trace", show);
}

void Cartoons::showTube(bool show)
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  if (show != interface.showTube) {
    interface.showTube = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/tube", show);
}

void Cartoons::showRibbon(bool show)
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  if (show != interface.showRibbon) {
    interface.showRibbon = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/ribbon", show);
}

void Cartoons::showSimpleCartoon(bool show)
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  if (show != interface.showSimpleCartoon) {
    interface.showSimpleCartoon = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/simpleCartoon", show);
}

void Cartoons::showCartoon(bool show)
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  if (show != interface.showCartoon) {
    interface.showCartoon = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/cartoon", show);
}

void Cartoons::showRope(bool show)
{
  LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>();
  if (show != interface.showRope) {
    interface.showRope = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("cartoon/rope", show);
}

} // namespace QtPlugins
} // namespace Avogadro
