/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "ballandstick.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/utilities.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QPointer>
#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSlider>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

#include <algorithm>
#include <cmath>
#include <iostream>
#include <locale>
#include <sstream>

namespace Avogadro::QtPlugins {

using Core::Elements;
using QtGui::PluginLayerManager;
using Rendering::CylinderGeometry;
using Rendering::GeometryNode;
using Rendering::SphereGeometry;

namespace {
// See the comment in label.cpp: tokens are always written with a
// classic-locale stream, but older settings saved under a comma-decimal
// locale (Qt calls setlocale(LC_ALL, "") on Unix) may still use ','.
std::string commaToDot(std::string token)
{
  std::replace(token.begin(), token.end(), ',', '.');
  return token;
}
} // namespace

struct LayerBallAndStick : Core::LayerData
{
  // The panel is parented elsewhere (a dock), which may delete it first.
  QPointer<QWidget> widget;
  bool multiBonds = true;
  bool showHydrogens = true;
  float atomScale = 0.3f;
  float bondRadius = 0.1f;
  float opacity = 1.0f;

  LayerBallAndStick()
  {
    widget = nullptr;
    QSettings settings;

    atomScale = settings.value("ballandstick/atomScale", 0.3).toDouble();
    bondRadius = settings.value("ballandstick/bondRadius", 0.1).toDouble();
    multiBonds = settings.value("ballandstick/multiBonds", true).toBool();
    showHydrogens = settings.value("ballandstick/showHydrogens", true).toBool();
    opacity = settings.value("ballandstick/opacity", 1.0).toDouble();
  }

  LayerBallAndStick(std::string settings)
  {
    widget = nullptr;
    deserialize(settings);
  }

  ~LayerBallAndStick() override
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() final
  {
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << boolToString(multiBonds) << " " << boolToString(showHydrogens)
           << " " << atomScale << " " << bondRadius << " " << opacity;
    return output.str();
  }

  void deserialize(std::string text) final
  {
    std::stringstream ss(text);
    std::string aux;
    if (ss >> aux)
      multiBonds = stringToBool(aux);
    if (ss >> aux)
      showHydrogens = stringToBool(aux);
    if (ss >> aux) {
      if (auto v = Core::lexicalCast<float>(commaToDot(aux));
          v && std::isfinite(*v) && *v > 0.0f)
        // slider range in setupWidget(), which converts value * 10 to int
        atomScale = std::clamp(*v, 0.1f, 0.9f);
    }
    if (ss >> aux) {
      if (auto v = Core::lexicalCast<float>(commaToDot(aux));
          v && std::isfinite(*v) && *v > 0.0f)
        bondRadius = std::clamp(*v, 0.1f, 0.8f);
    }
    if (ss >> aux) { // backwards compatibility
      if (auto v = Core::lexicalCast<float>(commaToDot(aux)))
        opacity = std::clamp(*v, 0.0f, 1.0f);
    }
  }

  LayerData* clone() final { return new LayerBallAndStick(serialize()); }

  void setupWidget(BallAndStick* slot)
  {
    if (!widget) {
      widget = new QWidget(qobject_cast<QWidget*>(slot->parent()));
      auto* v = new QVBoxLayout;

      auto* f = new QFormLayout;
      auto* atomRadiusSlider = new QSlider(Qt::Horizontal);
      atomRadiusSlider->setMinimum(1);
      atomRadiusSlider->setMaximum(9);
      atomRadiusSlider->setTickInterval(1);
      atomRadiusSlider->setValue(atomScale * 10);
      QObject::connect(atomRadiusSlider, &QSlider::valueChanged, slot,
                       &BallAndStick::atomRadiusChanged);
      f->addRow(QObject::tr("Atom scale"), atomRadiusSlider);

      auto* bondRadiusSlider = new QSlider(Qt::Horizontal);
      bondRadiusSlider->setMinimum(1);
      bondRadiusSlider->setMaximum(8);
      bondRadiusSlider->setTickInterval(1);
      bondRadiusSlider->setValue(bondRadius * 10);
      QObject::connect(bondRadiusSlider, &QSlider::valueChanged, slot,
                       &BallAndStick::bondRadiusChanged);
      f->addRow(QObject::tr("Bond scale"), bondRadiusSlider);

      auto* opacitySlider = new QSlider(Qt::Horizontal);
      opacitySlider->setMinimum(0);
      opacitySlider->setMaximum(100);
      opacitySlider->setTickInterval(1);
      opacitySlider->setValue(static_cast<int>(opacity * 100));
      QObject::connect(opacitySlider, &QSlider::valueChanged, slot,
                       &BallAndStick::opacityChanged);
      f->addRow(QObject::tr("Opacity"), opacitySlider);

      v->addLayout(f);

      auto* check = new QCheckBox(QObject::tr("Show multiple bonds"));
      check->setChecked(multiBonds);
      QObject::connect(check, &QCheckBox::clicked, slot,
                       &BallAndStick::multiBonds);
      v->addWidget(check);

      check = new QCheckBox(QObject::tr("Show hydrogens"));
      check->setChecked(showHydrogens);
      QObject::connect(check, &QCheckBox::clicked, slot,
                       &BallAndStick::showHydrogens);
      v->addWidget(check);

      v->addStretch(1);
      widget->setLayout(v);
    }
  }
};

BallAndStick::BallAndStick(QObject* p) : ScenePlugin(p), m_group(nullptr)
{
  m_layerManager = PluginLayerManager(m_name);
}

BallAndStick::~BallAndStick() {}

namespace {

// The drawables process() builds, and a cursor into each. The same code walks
// the atoms and bonds to build them (append) and to move them (overwrite at
// the cursor), so an update cannot differ from a rebuild.
struct Targets
{
  SphereGeometry* spheres;
  SphereGeometry* translucentSpheres;
  SphereGeometry* selectedSpheres;
  CylinderGeometry* cylinders;
  CylinderGeometry* translucentBonds;

  bool update = false;
  bool ok = true; // false if an update found a different drawable layout
  size_t sphereCursor = 0, translucentSphereCursor = 0, selectedCursor = 0;
  size_t cylinderCursor = 0, translucentBondCursor = 0;

  void addSphere(SphereGeometry* geometry, size_t& cursor,
                 const Vector3f& position, const Vector3ub& color, float radius,
                 size_t index)
  {
    if (!update) {
      geometry->addSphere(position, color, radius, index);
    } else if (cursor < geometry->size()) {
      geometry->spheres()[cursor] =
        Rendering::SphereColor(position, radius, color);
    } else {
      ok = false;
    }
    ++cursor;
  }

  void addCylinder(CylinderGeometry* geometry, size_t& cursor,
                   const Vector3f& pos1, const Vector3f& pos2, float radius,
                   const Vector3ub& color1, const Vector3ub& color2,
                   size_t index)
  {
    if (!update) {
      geometry->addCylinder(pos1, pos2, radius, color1, color2, index);
    } else if (cursor < geometry->size()) {
      geometry->cylinders()[cursor] =
        Rendering::CylinderColor(pos1, pos2, radius, color1, color2);
    } else {
      ok = false;
    }
    ++cursor;
  }

  // True if every drawable was filled exactly to its size.
  bool complete() const
  {
    return ok && sphereCursor == spheres->size() &&
           translucentSphereCursor == translucentSpheres->size() &&
           selectedCursor == selectedSpheres->size() &&
           cylinderCursor == cylinders->size() &&
           translucentBondCursor == translucentBonds->size();
  }

  void markDirty()
  {
    spheres->markDirty();
    translucentSpheres->markDirty();
    selectedSpheres->markDirty();
    cylinders->markDirty();
    translucentBonds->markDirty();
  }
};

// Add (or, when t.update, overwrite) the spheres and cylinders for @p molecule.
template <typename Layers>
void populate(const QtGui::Molecule& molecule, Layers& layers,
              float singleBondRadius, Targets& t)
{
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    size_t layer = layers.getLayerID(i);
    if (!layers.layerEnabled(layer)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();

    auto* interface = layers.setting(layer);
    if (atomicNumber == 1 && !interface->showHydrogens)
      continue;

    Vector3ub color = atom.color();
    auto radius = static_cast<float>(Elements::radiusVDW(atomicNumber));
    float scale = interface->atomScale;

    if (interface->opacity < 1.0f) {
      t.addSphere(t.translucentSpheres, t.translucentSphereCursor,
                  atom.position3d().cast<float>(), color, radius * scale, i);
      t.translucentSpheres->setOpacity(interface->opacity);
    } else
      t.addSphere(t.spheres, t.sphereCursor, atom.position3d().cast<float>(),
                  color, radius * scale, i);

    if (atom.selected()) {
      // add the selected indicator
      color = Vector3ub(0, 0, 255);
      radius *= 1.2;
      t.addSphere(t.selectedSpheres, t.selectedCursor,
                  atom.position3d().cast<float>(), color, radius * scale, i);
    }
  }

  float opacity = 1.0f; // for any translucent bonds
  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    Index a1 = bond.atom1().index();
    Index a2 = bond.atom2().index();
    size_t layer1 = layers.getLayerID(a1);
    size_t layer2 = layers.getLayerID(a2);
    if (!layers.layerEnabled(layer1) && !layers.layerEnabled(layer2)) {
      continue;
    }

    auto* interface1 = layers.setting(layer1);
    auto* interface2 = layers.setting(layer2);

    if (!interface1->showHydrogens && !interface2->showHydrogens &&
        (bond.atom1().atomicNumber() == 1 ||
         bond.atom2().atomicNumber() == 1)) {
      continue;
    }

    bool doOpaque = true;
    if (interface1->opacity < 1.0f || interface2->opacity < 1.0f) {
      opacity = std::min(interface1->opacity, interface2->opacity);
      t.translucentBonds->setOpacity(opacity);
      doOpaque = false;
    }
    CylinderGeometry* target = doOpaque ? t.cylinders : t.translucentBonds;
    size_t& cursor = doOpaque ? t.cylinderCursor : t.translucentBondCursor;

    float bondRadius = (interface1->bondRadius + interface2->bondRadius) * 0.5f;

    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3ub color1 = bond.atom1().color();
    Vector3ub color2 = bond.atom2().color();
    Vector3f bondVector = pos2 - pos1;
    float bondLength = bondVector.norm();
    bondVector /= bondLength;

    switch (interface1->multiBonds || interface2->multiBonds ? bond.order()
                                                             : 1) {
      case 3: {
        Vector3f delta = bondVector.unitOrthogonal();
        // Rotate 45 degrees around the bond vector.
        Eigen::Quaternionf q;
        q = Eigen::AngleAxisf(45.0f * DEG_TO_RAD_F, bondVector);
        delta = q * delta * 2.0f * bondRadius;
        t.addCylinder(target, cursor, pos1 + delta, pos2 + delta,
                      bondRadius * 1.15, color1, color2, i);
        t.addCylinder(target, cursor, pos1 - delta, pos2 - delta,
                      bondRadius * 1.15, color1, color2, i);
        // This relies upon the single bond case below for the third cylinder.
        [[fallthrough]];
      }
      default:
      case 1:
        t.addCylinder(target, cursor, pos1, pos2, singleBondRadius, color1,
                      color2, i);
        break;
      case 2: {
        Vector3f delta = bondVector.unitOrthogonal();
        // Rotate 45 degrees around the bond vector.
        Eigen::Quaternionf q;
        q = Eigen::AngleAxisf(45.0f * DEG_TO_RAD_F, bondVector);
        delta = q * delta * bondRadius;
        t.addCylinder(target, cursor, pos1 + delta, pos2 + delta,
                      bondRadius * 1.3, color1, color2, i);
        t.addCylinder(target, cursor, pos1 - delta, pos2 - delta,
                      bondRadius * 1.3, color1, color2, i);
      }
    }
  }
}

} // namespace

void BallAndStick::process(const QtGui::Molecule& molecule,
                           Rendering::GroupNode& node)
{
  m_layerManager.load<LayerBallAndStick>();
  // Add a sphere node to contain all of the spheres.
  m_group = &node;
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  auto* spheres = new SphereGeometry;
  spheres->identifier().molecule = reinterpret_cast<const void*>(&molecule);
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  // if we have to draw any translucent spheres, we need to add a separate
  // geometry node for them
  auto* translucentSpheres = new SphereGeometry;
  translucentSpheres->setRenderPass(Rendering::TranslucentPass);
  translucentSpheres->identifier().molecule =
    reinterpret_cast<const void*>(&molecule);
  translucentSpheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(translucentSpheres);

  // for the selected atoms
  auto* selectedSpheres = new SphereGeometry;
  selectedSpheres->setOpacity(0.42);
  geometry->addDrawable(selectedSpheres);

  auto* cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);

  auto* translucentBonds = new CylinderGeometry;
  translucentBonds->setRenderPass(Rendering::TranslucentPass);
  translucentBonds->identifier().molecule = &molecule;
  translucentBonds->identifier().type = Rendering::BondType;
  geometry->addDrawable(translucentBonds);

  Targets targets{ spheres, translucentSpheres, selectedSpheres, cylinders,
                   translucentBonds };
  auto layers = m_layerManager.snapshot<LayerBallAndStick>();
  populate(molecule, layers, m_bondRadius, targets);

  // Remember what was built so updateCoordinates() can move it.
  m_geometry = geometry;
  m_spheres = spheres;
  m_translucentSpheres = translucentSpheres;
  m_selectedSpheres = selectedSpheres;
  m_cylinders = cylinders;
  m_translucentBonds = translucentBonds;
  m_molecule = &molecule;
  m_atomCount = molecule.atomCount();
  m_bondCount = molecule.bondCount();
}

bool BallAndStick::updateCoordinates(const QtGui::Molecule& molecule,
                                     Rendering::GroupNode& node)
{
  if (&node != m_group || &molecule != m_molecule || m_geometry == nullptr ||
      molecule.atomCount() != m_atomCount ||
      molecule.bondCount() != m_bondCount)
    return false;

  // The pointers are only good while the node still holds the geometry node
  // process() added, and that still holds the drawables. Both checks compare
  // pointers found in live containers, so nothing stale is dereferenced.
  bool found = false;
  for (const auto& child : node.children()) {
    if (child.node == m_geometry) {
      found = true;
      break;
    }
  }
  if (!found)
    return false;
  const auto& drawables = m_geometry->drawables();
  if (drawables.size() != 5 || drawables[0] != m_spheres ||
      drawables[1] != m_translucentSpheres ||
      drawables[2] != m_selectedSpheres || drawables[3] != m_cylinders ||
      drawables[4] != m_translucentBonds)
    return false;

  m_layerManager.load<LayerBallAndStick>();
  Targets targets{ m_spheres, m_translucentSpheres, m_selectedSpheres,
                   m_cylinders, m_translucentBonds };
  targets.update = true;
  auto layers = m_layerManager.snapshot<LayerBallAndStick>();
  populate(molecule, layers, m_bondRadius, targets);
  targets.markDirty();
  return targets.complete();
}

QWidget* BallAndStick::setupWidget()
{
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  interface->setupWidget(this);
  return interface->widget;
}

void BallAndStick::opacityChanged(int opacity)
{
  m_opacity = static_cast<float>(opacity) / 100.0f;
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_opacity != interface->opacity) {
    interface->opacity = m_opacity;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/opacity", m_opacity);
}

void BallAndStick::atomRadiusChanged(int value)
{
  m_atomScale = static_cast<float>(value) / 10.0f;

  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_atomScale != interface->atomScale) {
    interface->atomScale = m_atomScale;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/atomScale", m_atomScale);
}

void BallAndStick::bondRadiusChanged(int value)
{
  m_bondRadius = static_cast<float>(value) / 10.0f;

  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (m_bondRadius != interface->bondRadius) {
    interface->bondRadius = m_bondRadius;
    emit drawablesChanged();
  }

  QSettings settings;
  settings.setValue("ballandstick/bondRadius", m_bondRadius);
}

void BallAndStick::multiBonds(bool show)
{
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface->multiBonds) {
    interface->multiBonds = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/multiBonds", show);
}

void BallAndStick::showHydrogens(bool show)
{
  auto* interface = m_layerManager.getSetting<LayerBallAndStick>();
  if (show != interface->showHydrogens) {
    interface->showHydrogens = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("ballandstick/showHydrogens", show);
}

} // namespace Avogadro::QtPlugins
