/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "label.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/textlabel3d.h>

#include <QtCore/QSettings>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::Rendering::TextLabel3D;
using Core::Array;
using Core::Elements;
using Core::Molecule;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using std::map;

typedef Array<Molecule::BondType> NeighborListType;

Label::Label(QObject* parent_)
  : QtGui::ScenePlugin(parent_), m_enabled(false), m_setupWidget(nullptr)
{
  QSettings settings;
  m_atomLabel = settings.value("label/atomLabel", true).toBool();
  m_residueLabel = settings.value("label/residueLabel", false).toBool();
}

Label::~Label()
{
  if (m_setupWidget)
    m_setupWidget->deleteLater();
}

void Label::process(const Core::Molecule& molecule, Rendering::GroupNode& node)
{
  if (m_residueLabel) {
    processResidue(molecule, node);
  }
  if (m_atomLabel) {
    processAtom(molecule, node);
  }
}

TextLabel3D* createLabel(const std::string& text, const Vector3f& pos,
                         float radius)
{
  Rendering::TextProperties tprop;
  tprop.setAlign(Rendering::TextProperties::HCenter,
                 Rendering::TextProperties::VCenter);
  tprop.setFontFamily(Rendering::TextProperties::SansSerif);

  tprop.setColorRgb(255, 255, 255);
  TextLabel3D* label = new TextLabel3D;
  label->setText(text);
  label->setRenderPass(Rendering::OpaquePass);
  label->setTextProperties(tprop);
  label->setRadius(radius);
  label->setAnchor(pos);
  return label;
}

void Label::processResidue(const Core::Molecule& molecule,
                           Rendering::GroupNode& node)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  for (const auto& residue : molecule.residues()) {
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

    TextLabel3D* residueLabel = createLabel(text, pos, radius);
    geometry->addDrawable(residueLabel);
  }
}

void Label::processAtom(const Core::Molecule& molecule,
                        Rendering::GroupNode& node)
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
    auto text =
      Elements::symbol(atomicNumber) + std::to_string(atomCount[atomicNumber]);
    const Vector3f pos(atom.position3d().cast<float>());
    float radius = static_cast<float>(Elements::radiusVDW(atomicNumber)) * 0.6f;

    TextLabel3D* atomLabel = createLabel(text, pos, radius);
    geometry->addDrawable(atomLabel);
  }
}

bool Label::isEnabled() const
{
  return m_enabled;
}

void Label::setEnabled(bool enable)
{
  m_enabled = enable;
}

void Label::atomLabel(bool show)
{
  if (show != m_atomLabel) {
    m_atomLabel = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("label/atomLabel", show);
}

void Label::residueLabel(bool show)
{
  if (show != m_residueLabel) {
    m_residueLabel = show;
    emit drawablesChanged();
  }
  QSettings settings;
  settings.setValue("label/residueLabel", show);
}

QWidget* Label::setupWidget()
{
  if (!m_setupWidget) {
    m_setupWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    QVBoxLayout* v = new QVBoxLayout;

    QCheckBox* check = new QCheckBox(tr("Atom Labels"));
    check->setChecked(m_atomLabel);
    connect(check, SIGNAL(clicked(bool)), SLOT(atomLabel(bool)));
    v->addWidget(check);

    check = new QCheckBox(tr("Residue Labels"));
    check->setChecked(m_residueLabel);
    connect(check, SIGNAL(toggled(bool)), SLOT(residueLabel(bool)));
    v->addWidget(check);

    v->addStretch(1);
    m_setupWidget->setLayout(v);
  }
  return m_setupWidget;
}

} // namespace QtPlugins
} // namespace Avogadro
