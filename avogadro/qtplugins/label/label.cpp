/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "label.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/colorbutton.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/textlabel3d.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro::QtPlugins {

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
  tprop.setColorRgb(color.data());

  auto* label = new TextLabel3D;
  label->setText(text);
  label->setRenderPass(Rendering::TranslucentPass);
  label->setTextProperties(tprop);
  label->setRadius(radius);
  label->setAnchor(pos);
  return label;
}
} // namespace

struct LayerLabel : Core::LayerData
{
  enum LabelOptions : char
  {
    None = 0x00,
    Index = 0x01,
    Name = 0x02,
    Custom = 0x04,
    Ordinal = 0x08
  };
  char atomOptions;
  char residueOptions;

  QWidget* widget;
  float radiusScalar;
  Vector3ub color;

  LayerLabel()
  {
    widget = nullptr;
    QSettings settings;
    atomOptions = char(settings.value("label/atomoptions", 0x02).toInt());
    residueOptions = char(settings.value("label/residueoptions", 0x00).toInt());
    radiusScalar = settings.value("label/radiusscalar", 0.5).toDouble();

    auto q_color =
      settings.value("label/color", QColor(Qt::white)).value<QColor>();
    color[0] = static_cast<unsigned char>(q_color.red());
    color[1] = static_cast<unsigned char>(q_color.green());
    color[2] = static_cast<unsigned char>(q_color.blue());
  }

  ~LayerLabel() override
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() final
  {
    std::string aux = (const char*)atomOptions;
    std::string aux2 = (const char*)residueOptions;
    return aux + " " + aux2 + " " + std::to_string(radiusScalar) + " " +
           std::to_string(color[0]) + " " + std::to_string(color[1]) + " " +
           std::to_string(color[2]);
  }
  void deserialize(std::string text) final
  {
    std::stringstream ss(text);
    std::string aux;
    ss >> aux;
    atomOptions = aux[0];
    ss >> aux;
    residueOptions = aux[0];
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
      auto* v = new QVBoxLayout;

      auto* form = new QFormLayout;
      // color button
      auto* colorButton = new QtGui::ColorButton;
      QObject::connect(colorButton, SIGNAL(colorChanged(const QColor&)), slot,
                       SLOT(setColor(const QColor&)));
      form->addRow(QObject::tr("Color:"), colorButton);

      // radius scalar
      auto* spin = new QDoubleSpinBox;
      spin->setRange(0.0, 1.5);
      spin->setSingleStep(0.1);
      spin->setDecimals(1);
      spin->setValue(radiusScalar);
      QObject::connect(spin, SIGNAL(valueChanged(double)), slot,
                       SLOT(setRadiusScalar(double)));
      form->addRow(QObject::tr("Distance from center:"), spin);

      auto* atom = new QComboBox;
      atom->setObjectName("atom");
      char elements[] = { None, Index, Name, Custom, Ordinal };
      for (char option : elements) {
        if (option == 0) {
          atom->addItem(QObject::tr("None"), QVariant(LabelOptions::None));
        } else {
          char val = LabelOptions::None;
          QStringList text;
          if (option & LabelOptions::Custom) {
            text << QObject::tr("Custom");
            val = LabelOptions::Custom;
          }
          if (option & LabelOptions::Index) {
            text << ((text.size() == 0) ? QObject::tr("Index")
                                        : QObject::tr("In."));
            val |= LabelOptions::Index;
          }
          if (option & LabelOptions::Name) {
            text << ((text.size() == 0) ? QObject::tr("Element")
                                        : QObject::tr("El."));
            val |= LabelOptions::Name;
          }
          if (option & LabelOptions::Ordinal) {
            text << ((text.size() == 0) ? QObject::tr("Element & Ordinal")
                                        : QObject::tr("El.&Or."));
            val |= LabelOptions::Ordinal;
          }
          QString join = QObject::tr(", ");
          atom->addItem(text.join(join), QVariant(val));
          if (val == atomOptions) {
            atom->setCurrentText(text.join(join));
          }
        }
      }
      QObject::connect(atom, SIGNAL(currentIndexChanged(int)), slot,
                       SLOT(atomLabelType(int)));
      int index = atom->findData(int(atomOptions));
      atom->model()->sort(0, Qt::AscendingOrder);
      form->addRow(QObject::tr("Atom Label:"), atom);

      auto* residue = new QComboBox;
      residue->setObjectName("residue");
      for (char i = 0x00; i < std::pow(2, 2); ++i) {
        if (i == 0) {
          residue->addItem(QObject::tr("None"), QVariant(LabelOptions::None));
        } else {
          char val = 0x00;
          QStringList text;
          if (i & LabelOptions::Index) {
            text << QObject::tr("ID");
            val |= LabelOptions::Index;
          }
          if (i & LabelOptions::Name) {
            text << QObject::tr("Name");
            val |= LabelOptions::Name;
          }
          if (val != 0x00) {
            QString join = QObject::tr(" & ");
            residue->addItem(text.join(join), QVariant(val));
            if (val == residueOptions) {
              residue->setCurrentText(text.join(join));
            }
          }
        }
      }
      QObject::connect(residue, SIGNAL(currentIndexChanged(int)), slot,
                       SLOT(residueLabelType(int)));
      index = residue->findData(int(residueOptions));
      residue->model()->sort(0, Qt::AscendingOrder);
      form->addRow(QObject::tr("Residue Label:"), residue);

      v->addLayout(form);
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

void Label::process(const QtGui::Molecule& molecule, Rendering::GroupNode& node)
{
  m_layerManager.load<LayerLabel>();
  for (size_t layer = 0; layer < m_layerManager.layerCount(); ++layer) {
    auto& interface = m_layerManager.getSetting<LayerLabel>(layer);
    if (interface.residueOptions) {
      processResidue(molecule, node, layer);
    }
    if (interface.atomOptions) {
      processAtom(molecule, node, layer);
    }
  }
}

void Label::processResidue(const Core::Molecule& molecule,
                           Rendering::GroupNode& node, size_t layer)
{
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  for (const auto& residue : molecule.residues()) {
    Atom caAtom = residue.getAtomByName("CA");
    if (!caAtom.isValid() ||
        !m_layerManager.atomEnabled(layer, caAtom.index())) {
      continue;
    }
    auto name = residue.residueName();
    const auto atoms = residue.residueAtoms();
    Vector3f pos = Vector3f::Zero();
    for (const auto& atom : atoms) {
      pos += atom.position3d().cast<float>();
    }
    pos /= static_cast<float>(atoms.size());

    float radius = 0.0f;
    for (const auto& atom : atoms) {
      unsigned char atomicNumber = atom.atomicNumber();
      auto auxR = static_cast<float>(Elements::radiusVDW(atomicNumber));
      auxR += (atom.position3d().cast<float>() - pos).norm();
      if (auxR > radius) {
        auxR = radius;
      }
    }

    auto& interface = m_layerManager.getSetting<LayerLabel>(layer);
    Vector3ub color = interface.color;
    std::string text = "";
    if (interface.residueOptions & LayerLabel::LabelOptions::Index) {
      text = std::to_string(residue.residueId());
    }
    if (interface.residueOptions & LayerLabel::LabelOptions::Name) {
      text += (text == "" ? "" : " / ") + name;
    }
    TextLabel3D* residueLabel = createLabel(text, pos, radius, color);
    geometry->addDrawable(residueLabel);
  }
}

void Label::processAtom(const Core::Molecule& molecule,
                        Rendering::GroupNode& node, size_t layer)
{
  auto* geometry = new GeometryNode;
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

    auto& interface = m_layerManager.getSetting<LayerLabel>(layer);
    std::string text = "";
    if (interface.atomOptions & LayerLabel::LabelOptions::Custom) {
      text += (text == "" ? "" : " / ") + atom.label();
    }
    if (interface.atomOptions & LayerLabel::LabelOptions::Index) {
      text += (text == "" ? "" : " / ") + std::to_string(atom.index());
    }
    if (interface.atomOptions & LayerLabel::LabelOptions::Name) {
      text +=
        (text == "" ? "" : " / ") + std::string(Elements::symbol(atomicNumber));
    }
    if (interface.atomOptions & LayerLabel::LabelOptions::Ordinal) {
      text += (text == "" ? "" : " / ") +
              std::string(Elements::symbol(atomicNumber) +
                          std::to_string(atomCount[atomicNumber]));
    }
    if (text != "") {
      const Vector3f pos(atom.position3d().cast<float>());
      Vector3ub color = interface.color;
      float radius = static_cast<float>(Elements::radiusVDW(atomicNumber)) *
                     interface.radiusScalar;

      TextLabel3D* atomLabel = createLabel(text, pos, radius, color);
      geometry->addDrawable(atomLabel);
    }
  }
}

void Label::setColor(const QColor& color)
{
  auto& interface = m_layerManager.getSetting<LayerLabel>();

  interface.color[0] = static_cast<unsigned char>(color.red());
  interface.color[1] = static_cast<unsigned char>(color.green());
  interface.color[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/color", color);
}

void Label::atomLabelType(int index)
{
  auto& interface = m_layerManager.getSetting<LayerLabel>();
  interface.atomOptions = char(setupWidget()
                                 ->findChildren<QComboBox*>("atom")[0]
                                 ->itemData(index)
                                 .toInt());
  emit drawablesChanged();
}

void Label::residueLabelType(int index)
{
  auto& interface = m_layerManager.getSetting<LayerLabel>();
  interface.residueOptions = char(setupWidget()
                                    ->findChildren<QComboBox*>("residue")[0]
                                    ->itemData(index)
                                    .toInt());
  emit drawablesChanged();
}

void Label::setRadiusScalar(double radius)
{
  auto& interface = m_layerManager.getSetting<LayerLabel>();
  interface.radiusScalar = float(radius);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/radiusScalar", interface.radiusScalar);
}

QWidget* Label::setupWidget()
{
  auto& interface = m_layerManager.getSetting<LayerLabel>();
  interface.setupWidget(this);
  return interface.widget;
}

} // namespace Avogadro
