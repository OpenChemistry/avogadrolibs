/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "label.h"

#include <iomanip>
#include <iostream>
#include <sstream>

// for partial charges
#include <avogadro/calc/chargemanager.h>

#include <avogadro/core/contrastcolor.h>
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
using Core::contrastColor;
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
  enum LabelOptions
  {
    None = 0,
    Index = 1,
    Name = 2,
    Custom = 4,
    Ordinal = 8,
    UniqueID = 16,
    PartialCharge = 32,
    Length = 64 // for bonds obviously
  };
  unsigned short atomOptions;
  unsigned short residueOptions;
  unsigned short bondOptions;

  QWidget* widget;
  float radiusScalar;
  Vector3ub color;

  LayerLabel()
  {
    widget = nullptr;
    QSettings settings;
    atomOptions =
      settings.value("label/atomoptions", LabelOptions::Name).toInt();
    residueOptions =
      settings.value("label/residueoptions", LabelOptions::None).toInt();
    bondOptions =
      settings.value("label/bondoptions", LabelOptions::None).toInt();
    radiusScalar = settings.value("label/radiusscalar", 0.5).toDouble();

    auto q_color =
      settings.value("label/color", QColor(Qt::white)).value<QColor>();
    color[0] = static_cast<unsigned char>(q_color.red());
    color[1] = static_cast<unsigned char>(q_color.green());
    color[2] = static_cast<unsigned char>(q_color.blue());
  }

  LayerLabel(std::string settings)
  {
    widget = nullptr;
    deserialize(settings);
  }

  LayerData* clone() final { return new LayerLabel(serialize()); }

  ~LayerLabel() override
  {
    if (widget)
      widget->deleteLater();
  }

  std::string serialize() final
  {
    std::stringstream output;
    output << atomOptions << " " << residueOptions << " " << radiusScalar << " "
           << (int)color[0] << " " << (int)color[1] << " " << (int)color[2]
           << " " << bondOptions;
    return output.str();
  }

  void deserialize(std::string text) final
  {
    std::stringstream ss(text);
    std::string aux;
    ss >> aux;
    atomOptions = std::stoi(aux);
    ss >> aux;
    residueOptions = std::stoi(aux);
    ss >> aux;
    radiusScalar = std::stof(aux);
    ss >> aux;
    color[0] = std::stoi(aux);
    ss >> aux;
    color[1] = std::stoi(aux);
    ss >> aux;
    color[2] = std::stoi(aux);
    ss >> aux;
    if (!aux.empty())
      bondOptions = std::stoi(aux); // backwards compatibility
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

      // set up the various atom options
      [[maybe_unused]] char val = LabelOptions::None;
      QStringList text;

      // first add the individual options
      atom->addItem(QObject::tr("None"), int(LabelOptions::None));
      atom->addItem(QObject::tr("Index"), int(LabelOptions::Index));
      atom->addItem(QObject::tr("Unique ID"), int(LabelOptions::UniqueID));
      atom->addItem(QObject::tr("Element"), int(LabelOptions::Name));
      atom->addItem(QObject::tr("Element & Number"),
                    int(LabelOptions::Ordinal));
      atom->addItem(QObject::tr("Element & ID"),
                    int(LabelOptions::Name | LabelOptions::UniqueID));
      atom->addItem(QObject::tr("Partial Charge", "atomic partial charge"),
                    int(LabelOptions::PartialCharge));
      atom->addItem(QObject::tr("Custom"), int(LabelOptions::Custom));

      // check for current option based on item data
      for (int i = 0; i < atom->count(); ++i) {
        if (atom->itemData(i).toInt() == atomOptions) {
          atom->setCurrentIndex(i);
          break;
        }
      }

      QObject::connect(atom, SIGNAL(currentIndexChanged(int)), slot,
                       SLOT(atomLabelType(int)));

      form->addRow(QObject::tr("Atom Label:"), atom);

      // bond label
      auto* bond = new QComboBox;
      bond->setObjectName("bond");

      // set up the various bond options
      bond->addItem(QObject::tr("None"), int(LabelOptions::None));
      bond->addItem(QObject::tr("Length"), int(LabelOptions::Length));
      bond->addItem(QObject::tr("Index"), int(LabelOptions::Index));
      bond->addItem(QObject::tr("Custom"), int(LabelOptions::Custom));

      QObject::connect(bond, SIGNAL(currentIndexChanged(int)), slot,
                       SLOT(bondLabelType(int)));
      form->addRow(QObject::tr("Bond Label:"), bond);

      auto* residue = new QComboBox;
      residue->setObjectName("residue");
      for (char i = 0x00; i < std::pow(2, 2); ++i) {
        if (i == 0) {
          residue->addItem(QObject::tr("None"), QVariant(LabelOptions::None));
        } else {
          char optval = 0x00;
          QStringList opttext;
          if (i & LabelOptions::Index) {
            opttext << QObject::tr("ID");
            optval |= LabelOptions::Index;
          }
          if (i & LabelOptions::Name) {
            opttext << QObject::tr("Name");
            optval |= LabelOptions::Name;
          }
          if (optval != 0x00) {
            QString join = QObject::tr(" & ");
            residue->addItem(opttext.join(join), QVariant(optval));
            if (optval == residueOptions) {
              residue->setCurrentText(opttext.join(join));
            }
          }
        }
      }
      QObject::connect(residue, SIGNAL(currentIndexChanged(int)), slot,
                       SLOT(residueLabelType(int)));

      // residue->model()->sort(0, Qt::AscendingOrder);
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
    auto* interface = m_layerManager.getSetting<LayerLabel>(layer);
    if (interface->residueOptions) {
      processResidue(molecule, node, layer);
    }
    if (interface->atomOptions) {
      processAtom(molecule, node, layer);
    }
    if (interface->bondOptions) {
      processBond(molecule, node, layer);
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

    auto* interface = m_layerManager.getSetting<LayerLabel>(layer);
    Vector3ub color = interface->color;
    std::string text = "";
    if (interface->residueOptions & LayerLabel::LabelOptions::Index) {
      text = std::to_string(residue.residueId());
    }
    if (interface->residueOptions & LayerLabel::LabelOptions::Name) {
      text += (text == "" ? "" : " / ") + name;
    }
    TextLabel3D* residueLabel = createLabel(text, pos, radius, color);
    geometry->addDrawable(residueLabel);
  }
}

QString partialCharge(Molecule* molecule, int atom)
{
  // TODO: we need to track type and/or calling the charge calculator
  float charge = 0.0;
  std::set<std::string> types = molecule->partialChargeTypes();
  if (types.size() > 0) {
    auto first = types.cbegin();
    MatrixX charges = molecule->partialCharges((*first));
    charge = charges(atom, 0);
  } else {
    // find something
    const auto options =
      Calc::ChargeManager::instance().identifiersForMolecule(*molecule);
    if (options.size() > 0) {
      // look for GFN2 or AM1BCC, then MMFF94 then Gasteiger
      std::string type;
      if (options.find("GFN2") != options.end())
        type = "GFN2";
      else if (options.find("am1bcc") != options.end())
        type = "am1bcc";
      else if (options.find("mmff94") != options.end())
        type = "mmff94";
      else if (options.find("gasteiger") != options.end())
        type = "gasteiger";
      else
        type = *options.begin();

      MatrixX charges =
        Calc::ChargeManager::instance().partialCharges(type, *molecule);
      charge = charges(atom, 0);
    }
  }
  // e.g. '-0.12' => 5 characters
  return QString("%L1").arg(charge, 5, 'f', 2);
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

    auto* interface = m_layerManager.getSetting<LayerLabel>(layer);
    std::string text = atom.label();

    if (interface->atomOptions & LayerLabel::LabelOptions::PartialCharge) {
      QString charge = partialCharge(const_cast<Molecule*>(&molecule), i);
      text += charge.toStdString();
    }
    if (interface->atomOptions & LayerLabel::LabelOptions::Custom) {
      // already set
    }
    if (interface->atomOptions & LayerLabel::LabelOptions::Index) {
      text += (text == "" ? "" : " / ") + std::to_string(atom.index() + 1);
    }
    if (interface->atomOptions & LayerLabel::LabelOptions::Name) {
      text +=
        (text == "" ? "" : " / ") + std::string(Elements::symbol(atomicNumber));
    }
    if (interface->atomOptions & LayerLabel::LabelOptions::Ordinal) {
      text += (text == "" ? "" : " / ") +
              std::string(Elements::symbol(atomicNumber) +
                          std::to_string(atomCount[atomicNumber]));
    }
    if (interface->atomOptions & LayerLabel::LabelOptions::UniqueID) {
      text += (text == "" ? "" : " / ") + std::to_string(atom.index());
    }
    if (text != "") {
      const Vector3f pos(atom.position3d().cast<float>());
      Vector3ub color = atom.color();
      float radius = static_cast<float>(Elements::radiusVDW(atomicNumber)) *
                     interface->radiusScalar;

      TextLabel3D* atomLabel =
        createLabel(text, pos, radius, contrastColor(color));
      geometry->addDrawable(atomLabel);
    }
  }
}

void Label::processBond(const Core::Molecule& molecule,
                        Rendering::GroupNode& node,
                        [[maybe_unused]] size_t layer)
{
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  std::map<unsigned char, size_t> bondCount;
  for (Index i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);

    // check if the bond is enabled in this layer
    if (!m_layerManager.bondEnabled(bond.atom1().index(),
                                    bond.atom2().index())) {
      continue;
    }

    // get the options for this bond
    Core::Atom atom1 = bond.atom1();
    Core::Atom atom2 = bond.atom2();
    auto* interface1 = m_layerManager.getSetting<LayerLabel>(
      m_layerManager.getLayerID(atom1.index()));
    auto* interface2 = m_layerManager.getSetting<LayerLabel>(
      m_layerManager.getLayerID(atom2.index()));

    // get the union of the options
    char options = interface1->bondOptions | interface2->bondOptions;
    Vector3ub color = interface1->color;
    unsigned char atomicNumber1 = atom1.atomicNumber();
    unsigned char atomicNumber2 = atom2.atomicNumber();
    float radiusVDW1 = static_cast<float>(Elements::radiusVDW(atomicNumber1));
    float radiusVDW2 = static_cast<float>(Elements::radiusVDW(atomicNumber2));
    float radius = (radiusVDW1 + radiusVDW2) * interface1->radiusScalar / 2.0f;

    std::stringstream text;
    // hopefully not all at once
    if (options & LayerLabel::LabelOptions::Index) {
      text << bond.index();
    }
    if (options & LayerLabel::LabelOptions::Custom) {
      text << bond.label();
    }
    if (options & LayerLabel::LabelOptions::Length) {
      text << std::fixed << std::setprecision(2) << bond.length();
    }

    // position will be between the two atoms
    Vector3f pos =
      (atom1.position3d().cast<float>() + atom2.position3d().cast<float>()) /
      2.0f;

    TextLabel3D* bondLabel = createLabel(text.str(), pos, radius, color);
    geometry->addDrawable(bondLabel);
  }
}

void Label::setColor(const QColor& color)
{
  auto* interface = m_layerManager.getSetting<LayerLabel>();

  interface->color[0] = static_cast<unsigned char>(color.red());
  interface->color[1] = static_cast<unsigned char>(color.green());
  interface->color[2] = static_cast<unsigned char>(color.blue());

  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/color", color);
}

void Label::atomLabelType(int index)
{
  auto* interface = m_layerManager.getSetting<LayerLabel>();
  interface->atomOptions = char(setupWidget()
                                  ->findChildren<QComboBox*>("atom")[0]
                                  ->itemData(index)
                                  .toInt());
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/atomoptions", interface->atomOptions);
}

void Label::bondLabelType(int index)
{
  auto* interface = m_layerManager.getSetting<LayerLabel>();
  interface->bondOptions = char(setupWidget()
                                  ->findChildren<QComboBox*>("bond")[0]
                                  ->itemData(index)
                                  .toInt());
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/bondoptions", interface->bondOptions);
}

void Label::residueLabelType(int index)
{
  auto* interface = m_layerManager.getSetting<LayerLabel>();
  interface->residueOptions = char(setupWidget()
                                     ->findChildren<QComboBox*>("residue")[0]
                                     ->itemData(index)
                                     .toInt());
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/residueoptions", interface->residueOptions);
}

void Label::setRadiusScalar(double radius)
{
  auto* interface = m_layerManager.getSetting<LayerLabel>();
  interface->radiusScalar = float(radius);
  emit drawablesChanged();

  QSettings settings;
  settings.setValue("label/radiusscalar", interface->radiusScalar);
}

QWidget* Label::setupWidget()
{
  auto* interface = m_layerManager.getSetting<LayerLabel>();
  interface->setupWidget(this);
  return interface->widget;
}

} // namespace Avogadro::QtPlugins
