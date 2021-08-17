/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "label.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/colorbutton.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/textlabel3d.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::Rendering::TextLabel3D;
using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::Molecule;
using QtGui::PluginLayerManager;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using std::map;

typedef Array<Molecule::BondType> NeighborListType;

namespace {
TextLabel3D* createLabel(const std::string& text, const Vector3f& pos,
                         float radius, const Vector3ub& color)
{
  Rendering::TextProperties tprop;
  tprop.setAlign(Rendering::TextProperties::HCenter,
                 Rendering::TextProperties::VCenter);
  tprop.setFontFamily(Rendering::TextProperties::SansSerif);

  tprop.setColorRgb(color[0], color[1], color[2]);
  TextLabel3D* label = new TextLabel3D;
  label->setText(text);
  label->setRenderPass(Rendering::OpaquePass);
  label->setTextProperties(tprop);
  label->setRadius(radius);
  label->setAnchor(pos);
  return label;
}
} // namespace

struct LayerLabel : Core::LayerData
{
  QWidget* widget;
  bool atomLabel;
  bool residueLabel;
  float radiusScalar;
  Vector3ub color;

  LayerLabel()
  {
    widget = nullptr;
    QSettings settings;
    atomLabel = settings.value("label/atomLabel", true).toBool();
    residueLabel = settings.value("label/residueLabel", false).toBool();
    radiusScalar = settings.value("label/radiusScalar", 0.5).toDouble();

    QColor q_color =
      settings.value("label/color", QColor(Qt::white)).value<QColor>();
    color[0] = static_cast<unsigned char>(q_color.red());
    color[1] = static_cast<unsigned char>(q_color.green());
    color[2] = static_cast<unsigned char>(q_color.blue());
  }

  ~LayerLabel()
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() override final
  {
    return boolToString(atomLabel) + " " + boolToString(residueLabel) + " " +
             std::to_string(radiusScalar) + " " + std::to_string(color[0]) 
             + " " + std::to_string(color[1]) + " " + std::to_string(color[2]);
  }
  void deserialize(std::string text) override final
  {
    std::stringstream ss(text);
    std::string aux;
    ss >> aux;
    atomLabel = stringToBool(aux);
    ss >> aux;
    residueLabel = stringToBool(aux);
    ss >> aux;
    radiusScalar = std::stof(aux);
    ss >> aux;
    color[0] = std::stoi(aux);
    ss >> aux;
    color[1] = std::stoi(aux);
    ss >> aux;
    color[2] = std::stoi(aux);
  }

  void setupWidget(Label* slot)
  {
    if (!widget) {
      widget = new QWidget(qobject_cast<QWidget*>(slot->parent()));
      QVBoxLayout* v = new QVBoxLayout;

      QFormLayout* form = new QFormLayout;
      // color button
      QtGui::ColorButton* color = new QtGui::ColorButton;
      QObject::connect(color, SIGNAL(colorChanged(const QColor&)), slot,
              SLOT(setColor(const QColor&)));
      form->addRow(QObject::tr("Color:"), color);

      // radius scalar
      QDoubleSpinBox* spin = new QDoubleSpinBox;
      spin->setRange(0.0, 1.5);
      spin->setSingleStep(0.1);
      spin->setDecimals(1);
      spin->setValue(radiusScalar);
      QObject::connect(spin, SIGNAL(valueChanged(double)), slot,
                       SLOT(setRadiusScalar(double)));
      form->addRow(QObject::tr("Distance from center:"), spin);

      v->addLayout(form);

      // residue or atoms?
      QCheckBox* check = new QCheckBox(QObject::tr("Atom Labels"));
      check->setChecked(atomLabel);
      QObject::connect(check, &QCheckBox::clicked, slot, &Label::atomLabel);
      v->addWidget(check);

      check = new QCheckBox(QObject::tr("Residue Labels"));
      check->setChecked(residueLabel);
      QObject::connect(check, &QCheckBox::clicked, slot, &Label::residueLabel);
      v->addWidget(check);

      v->addStretch(1);
      widget->setLayout(v);
    }
  }
};

Label::Label(QObject* parent_) : QtGui::ScenePlugin(parent_)
{
  m_layerManager = PluginLayerManager(m_name);
}

Label::~Label() {}

void Label::process(const Core::Molecule& molecule, Rendering::GroupNode& node)
{
  m_layerManager.load<LayerLabel>();
  for (size_t layer = 0; layer < m_layerManager.layerCount(); ++layer) {
    LayerLabel& interface = m_layerManager.getSetting<LayerLabel>(layer);
    if (interface.residueLabel) {
      processResidue(molecule, node, layer);
    }
    if (interface.atomLabel) {
      processAtom(molecule, node, layer);
    }
  }
}

void Label::processResidue(const Core::Molecule& molecule,
                           Rendering::GroupNode& node, size_t layer)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  for (const auto& residue : molecule.residues()) {
    Atom caAtom = residue.getAtomByName("CA");
    if (!caAtom.isValid() ||
        !m_layerManager.atomEnabled(layer, caAtom.index())) {
      continue;
    }
    auto text = residue.residueName();
    const auto atoms = residue.residueAtoms();
    Vector3f pos = Vector3f::Zero();
    for (const auto& atom : atoms) {
      pos += atom.position3d().cast<float>();
    }
    pos /= static_cast<float>(atoms.size());

    float radius = 0.0f;
    for (const auto& atom : atoms) {
      unsigned char atomicNumber = atom.atomicNumber();
      float auxR = static_cast<float>(Elements::radiusVDW(atomicNumber));
      auxR += (atom.position3d().cast<float>() - pos).norm();
      if (auxR > radius) {
        auxR = radius;
      }
    }

    Vector3ub color = m_layerManager.getSetting<LayerLabel>(layer).color;
    TextLabel3D* residueLabel = createLabel(text, pos, radius, color);
    geometry->addDrawable(residueLabel);
  }
}

void Label::processAtom(const Core::Molecule& molecule,
                        Rendering::GroupNode& node, size_t layer)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  std::map<unsigned char, size_t> atomCount;
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);

    unsigned char atomicNumber = atom.atomicNumber();
    if (atomCount.find(atomicNumber) == atomCount.end()) {
      atomCount[atomicNumber] = 1;
    } else {
      ++atomCount[atomicNumber];
    }

    if (!m_layerManager.atomEnabled(layer, i)) {
      continue;
    }

    auto text = atom.label();
    if (text == "") {
      text = Elements::symbol(atomicNumber) +
             std::to_string(atomCount[atomicNumber]);
    }
    const Vector3f pos(atom.position3d().cast<float>());
    LayerLabel& interface = m_layerManager.getSetting<LayerLabel>(layer);
    Vector3ub color = interface.color;
    float radius = static_cast<float>(Elements::radiusVDW(atomicNumber)) *
                   interface.radiusScalar;

    TextLabel3D* atomLabel = createLabel(text, pos, radius, color);
    geometry->addDrawable(atomLabel);
  }
}

void Label::setColor(const QColor& color)
{
  LayerLabel& interface = m_layerManager.getSetting<LayerLabel>();

  interface.color[0] = static_cast<unsigned char>(color.red());
  interface.color[1] = static_cast<unsigned char>(color.green());
  interface.color[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/color", color);
}

void Label::atomLabel(bool show)
{
  LayerLabel& interface = m_layerManager.getSetting<LayerLabel>();
  if (show != interface.atomLabel) {
    interface.atomLabel = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("label/atomLabel", show);
}

void Label::residueLabel(bool show)
{
  LayerLabel& interface = m_layerManager.getSetting<LayerLabel>();
  if (show != interface.residueLabel) {
    interface.residueLabel = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("label/residueLabel", show);
}

void Label::setRadiusScalar(double radius)
{
  LayerLabel& interface = m_layerManager.getSetting<LayerLabel>();
  interface.radiusScalar = float(radius);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/radiusScalar", interface.radiusScalar);
}

QWidget* Label::setupWidget()
{
  LayerLabel& interface = m_layerManager.getSetting<LayerLabel>();
  interface.setupWidget(this);
  return interface.widget;
}

} // namespace QtPlugins
} // namespace Avogadro
