/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "labeleditor.h"

#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/primitive.h>
#include <avogadro/rendering/textlabel3d.h>

#include <QAction>
#include <QKeyEvent>

#include <QDebug>

namespace Avogadro::QtPlugins {

using Core::Elements;
using Rendering::GeometryNode;
using Rendering::Identifier;
using Rendering::TextLabel3D;

LabelEditor::LabelEditor(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_glWidget(nullptr), m_renderer(nullptr)
{
  m_activateAction->setText(tr("Edit Labels"));
  m_activateAction->setToolTip(
    tr("Atom Label Tool\n\n"
       "Left Mouse:\tClick on Atoms to add Custom Labels"));
  setIcon();
}

LabelEditor::~LabelEditor() {}

void LabelEditor::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/label_dark.svg"));
  else
    m_activateAction->setIcon(QIcon(":/icons/label_light.svg"));
}

QUndoCommand* LabelEditor::mouseReleaseEvent(QMouseEvent* e)
{
  e->ignore();
  return nullptr;
}

QUndoCommand* LabelEditor::mouseMoveEvent(QMouseEvent* e)
{
  e->ignore();
  return nullptr;
}

QUndoCommand* LabelEditor::keyPressEvent(QKeyEvent* e)
{
  if (!atomPicked())
    return nullptr;
  if (e->key() == Qt::Key_Escape && e->modifiers() == Qt::NoModifier) {
    m_text.clear();
    m_selectedAtom.reset();
    emit atomPickedChanged();
  } else if (e->key() == Qt::Key_Backspace)
    m_text.chop(1);
  else if (e->key() == Qt::Key_Enter || e->key() == Qt::Key_Return)
    save();
  else if (!e->text().isEmpty() && e->text()[0].isPrint())
    m_text.append(e->text());
  else
    return nullptr;
  e->accept();
  emit drawablesChanged();
  return nullptr;
}

void LabelEditor::save()
{
  const auto atom = m_selectedAtom.atom();
  const auto label = m_text.toStdString();
  if (label != atom.label())
    m_molecule->setAtomLabel(atom.index(), label, tr("Edit Atom Label"));
  m_text.clear();
  m_selectedAtom.reset();
  emit atomPickedChanged();

  // make sure the label display is made active
  emit requestActiveDisplayTypes(QStringList() << "Labels");
}

qsizetype LabelEditor::pickedAtomIndex() const
{
  const auto atom = m_selectedAtom.atom();
  return atom.isValid() ? static_cast<qsizetype>(atom.index()) : -1;
}

bool LabelEditor::handleCommand(const QString& command,
                                const QVariantMap& options)
{
  if (command != "setPickedLabel" || !atomPicked() ||
      !options.contains("label"))
    return false;
  m_text = options.value("label").toString();
  save();
  emit drawablesChanged();
  return true;
}

QUndoCommand* LabelEditor::mousePressEvent(QMouseEvent* e)
{
  if (!m_renderer || !m_molecule)
    return nullptr;

  if (e->buttons() & Qt::LeftButton) {
    if (m_selectedAtom.isValid()) {
      e->accept();
      save();
      emit drawablesChanged();
    }

    Identifier clickedObject = m_renderer->hit(e->pos().x(), e->pos().y());
    if (clickedObject.type == Rendering::AtomType &&
        clickedObject.molecule == &m_molecule->molecule() &&
        clickedObject.index < m_molecule->atomCount()) {
      e->accept();
      m_selectedAtom.set(m_molecule->atom(clickedObject.index));
      m_text = QString::fromStdString(m_selectedAtom.atom().label());
      emit atomPickedChanged();
      emit drawablesChanged();
    } else {
      // clicked on empty space
      e->ignore();
    }
  } else {
    e->ignore();
  }

  return nullptr;
}

namespace {
TextLabel3D* createLabel(const std::string& text, const Vector3f& pos,
                         float radius)
{
  Rendering::TextProperties tprop;
  tprop.setAlign(Rendering::TextProperties::HCenter,
                 Rendering::TextProperties::VCenter);
  tprop.setFontFamily(Rendering::TextProperties::SansSerif);

  tprop.setColorRgb(255, 255, 255);
  auto* label = new TextLabel3D;
  label->setText(text);
  label->setRenderPass(Rendering::Overlay3DPass);
  label->setTextProperties(tprop);
  label->setRadius(radius);
  label->setAnchor(pos);
  return label;
}
} // namespace

void LabelEditor::draw(Rendering::GroupNode& node)
{
  if (m_renderer == nullptr || !atomPicked()) {
    return;
  }
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  const auto atom = m_selectedAtom.atom();
  unsigned char atomicNumber = atom.atomicNumber();
  const Vector3f pos(atom.position3d().cast<float>());
  float radius = static_cast<float>(Elements::radiusVDW(atomicNumber)) * 0.6f;

  TextLabel3D* atomLabel = createLabel(m_text.toStdString(), pos, radius);
  geometry->addDrawable(atomLabel);
}
} // namespace Avogadro::QtPlugins
