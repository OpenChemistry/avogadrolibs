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
  bool showCartoon;
  bool showRope;

  typedef void (Cartoons::*JumpTable)(bool);
  JumpTable jumpTable[6];

  std::string save() override final
  {
    return boolToString(showBackbone) + " " + boolToString(showTrace) + " " +
           boolToString(showTube) + " " + boolToString(showRibbon) + " " +
           boolToString(showCartoon) + " " + boolToString(showRope);
  }
  void load(std::string text) override final
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
                << QObject::tr("Cartoon", "protein rendering style")
                << QObject::tr("Rope", "protein rendering style");
      vector<reference_wrapper<bool>> boxesBools = { showBackbone, showTrace,
                                                     showTube,     showRibbon,
                                                     showCartoon,  showRope };
      jumpTable[0] = &Cartoons::showBackbone;
      jumpTable[1] = &Cartoons::showTrace;
      jumpTable[2] = &Cartoons::showTube;
      jumpTable[3] = &Cartoons::showRibbon;
      jumpTable[4] = &Cartoons::showCartoon;
      jumpTable[5] = &Cartoons::showRope;
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
                  const size_t& g)
    : pos(p), color1(c1), color2(c2), group(g)
  {}
  Vector3f pos;
  Vector3ub color1;
  Vector3ub color2;
  size_t group;
};

typedef list<BackboneResidue> AtomsPairList;

Cartoons::Cartoons(QObject* parent) : ScenePlugin(parent), m_group(nullptr)
{
  m_layerManager = PluginLayerManager(m_name);
}

Cartoons::~Cartoons() {}

BackboneResidue createBackBone(const Atom& caAtom, const Atom& auxAtom,
                               const Atom* nextAtom, Index group, bool fliped)
{
  Vector3f ca = caAtom.position3d().cast<float>();
  Vector3f aux = auxAtom.position3d().cast<float>();
  Vector3ub color2;
  // incompleat orientation
  if (nextAtom == nullptr) {
    color2 = Vector3ub::Zero();
  } else {
    Vector3f next = nextAtom->position3d().cast<float>();
    color2 = nextAtom->color();
  }
  return BackboneResidue(ca, caAtom.color(), color2, group);
}

void addBackBone(map<size_t, AtomsPairList>& result,
                 map<size_t, pair<Atom, Atom>>& previousCA, const Atom& caAtom,
                 const Atom& auxAtom, Index group)
{
  Atom* next;
  if (result.find(group) == result.end()) {
    result[group] = AtomsPairList();
    next = nullptr;
  } else {
    next = &(previousCA[group].first);
  }
  BackboneResidue backBone =
    createBackBone(caAtom, auxAtom, next, group, false);
  // the 1º insertion will always be incompleated, so fix it
  if (result[group].size() == 1) {
    result[group].front() = createBackBone(
      previousCA[group].first, previousCA[group].second, &caAtom, group, true);
  }
  previousCA[group] = std::make_pair(caAtom, auxAtom);
  result[group].push_back(backBone);
}

map<size_t, AtomsPairList> Cartoons::getBackboneByResidues(
  const Molecule& molecule, size_t layer)
{
  const auto& graph = molecule.graph();
  map<size_t, AtomsPairList> result;
  map<size_t, pair<Atom, Atom>> previousCA;
  for (const auto& residue : molecule.residues()) {
    if (!residue.isHeterogen()) {
      Atom caAtom = residue.getAtomByName("CA");
      Atom oAtom = residue.getAtomByName("O");
      if (caAtom.isValid() && oAtom.isValid()) {
        if (!m_layerManager.atomEnabled(layer, caAtom.index()) ||
            !m_layerManager.atomEnabled(layer, oAtom.index())) {
          continue;
        }
        // get the group ID and check if it's initialized in the map
        size_t group = graph.getConnectedID(caAtom.index());
        addBackBone(result, previousCA, caAtom, oAtom, group);
      }
    }
  }
  return result;
}

map<size_t, AtomsPairList> Cartoons::getBackboneManually(
  const Molecule& molecule, size_t layer)
{
  // manual filter
  // const auto& graph = molecule.graph();
  map<size_t, AtomsPairList> result;
  map<size_t, pair<Atom, Atom>> previousCA;

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    const auto atom = molecule.atom(i);
    if (atom.atomicNumber() == AtomicNumber::Carbon) {
      Atom aux = Atom();
      for (const auto& bond : molecule.bonds(atom.index())) {
        if (int(bond->atom1().atomicNumber()) == int(AtomicNumber::Oxygen) ||
            int(bond->atom1().atomicNumber()) == int(AtomicNumber::Hydrogen)) {
          aux = bond->atom1();
          break;
        }
        if (int(bond->atom2().atomicNumber()) == int(AtomicNumber::Oxygen) ||
            int(bond->atom2().atomicNumber()) == int(AtomicNumber::Hydrogen)) {
          aux = bond->atom2();
          break;
        }
      }
      if (!m_layerManager.atomEnabled(layer, aux.index())) {
        continue;
      }
      if (aux.isValid()) {
        size_t group = 0; // graph.getConnectedID(atom.index());
        addBackBone(result, previousCA, atom, aux, group);
      }
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
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);

  Index i = 0;
  for (AtomsPairList::const_iterator it = backbone.begin();
       it != backbone.end(); ++it) {
    const auto& bone = *it;
    const Vector3f& pos = bone.pos;
    spheres->addSphere(pos, bone.color1, radius);
    if (std::next(it) != backbone.end()) {
      const auto& nextBone = *std::next(it);
      const Vector3f& pos2 = nextBone.pos;
      cylinders->addCylinder(pos, pos2, radius, bone.color1, bone.color2,
                             bone.group);
    }
    ++i;
  }
}

void renderRope(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node, float radius, size_t id)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BezierGeometry* bezier = new BezierGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::BondType;
  geometry->addDrawable(bezier);

  for (const auto& bone : backbone) {
    bezier->addPoint(bone.pos, bone.color1, radius, bone.group);
  }
}

void renderTube(const AtomsPairList& backbone, const Molecule& molecule,
                Rendering::GroupNode& node, float radius, size_t id)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  BSplineGeometry* bezier = new BSplineGeometry;
  bezier->identifier().molecule = &molecule;
  bezier->identifier().type = Rendering::BondType;
  geometry->addDrawable(bezier);

  for (const auto& bone : backbone) {
    bezier->addPoint(bone.pos, bone.color1, radius, bone.group);
  }
}

void renderCartoon(const AtomsPairList& backbone, const Molecule& molecule,
                   Rendering::GroupNode& node, float radius, size_t id)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  Cartoon* cartoon = new Cartoon;
  cartoon->identifier().molecule = &molecule;
  cartoon->identifier().type = Rendering::BondType;
  geometry->addDrawable(cartoon);
  for (const auto& bone : backbone) {
    cartoon->addPoint(bone.pos, bone.color1, radius, bone.group);
  }
}

void Cartoons::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  for (size_t layer = 0; layer < m_layerManager.count(); ++layer) {
    LayerCartoon& interface = m_layerManager.getSetting<LayerCartoon>(layer);
    m_group = &node;
    if (interface.showBackbone || interface.showTrace || interface.showTube ||
        interface.showRibbon || interface.showCartoon || interface.showRope) {
      map<size_t, AtomsPairList> backbones;
      if (molecule.residues().size() > 0) {
        backbones = getBackboneByResidues(molecule, layer);
      }
      if (backbones.size() == 0) {
        backbones = getBackboneManually(molecule, layer);
      }
      size_t i = 0;
      for (const auto& group : backbones) {
        const auto& backbone = group.second;
        if (interface.showBackbone) {
          renderBackbone(backbone, molecule, node, 0.1f);
        }
        if (interface.showTrace) {
          renderTube(backbone, molecule, node, -0.15f, i);
        }
        if (interface.showTube) {
          renderTube(backbone, molecule, node, 0.15f, i);
        }
        if (interface.showRibbon) {
          renderCartoon(backbone, molecule, node, -1.0f * Cartoon::ELIPSE_RATIO,
                        i);
        }
        if (interface.showCartoon) {
          renderCartoon(backbone, molecule, node, 1.0f, i);
        }
        if (interface.showRope) {
          renderRope(backbone, molecule, node, 1.0f, i);
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
