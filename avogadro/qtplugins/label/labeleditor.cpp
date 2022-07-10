/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "labeleditor.h"

#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/primitive.h>
#include <avogadro/rendering/textlabel3d.h>

#include <QRegExp>
#include <QtGui/QKeyEvent>
#include <QtWidgets/QAction>

namespace Avogadro::QtPlugins {

using Core::Elements;
using QtGui::RWAtom;
using Rendering::GeometryNode;
using Rendering::Identifier;
using Rendering::TextLabel3D;

LabelEditor::LabelEditor(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_glWidget(nullptr), m_renderer(nullptr),
    m_selected(false), m_text("")
{
  m_activateAction->setText(tr("Edit Labels"));
  m_activateAction->setIcon(QIcon(":/icons/labeltool.png"));
  m_activateAction->setToolTip(
    tr("Atom Label Tool\n\n"
       "Left Mouse: \tClick on Atoms to add Custom Labels"));
}

LabelEditor::~LabelEditor() {}

QUndoCommand* LabelEditor::mouseReleaseEvent(QMouseEvent* e)
{
  return nullptr;
}

QUndoCommand* LabelEditor::mouseMoveEvent(QMouseEvent* e)
{
  return nullptr;
}

QUndoCommand* LabelEditor::keyPressEvent(QKeyEvent* e)
{
  if (m_selected && !e->text().isEmpty()) {
    e->accept();
    auto text = e->text()[0];
    if (text.isPrint()) {
      m_text.append(text);
    } else if (e->key() == Qt::Key_Backspace) {
      m_text.chop(1);
    } else if (e->key() == Qt::Key_Enter || e->key() == Qt::Key_Return) {
      save();
    }
    emit drawablesChanged();
  }
  return nullptr;
}

void LabelEditor::save()
{
  m_molecule->beginMergeMode(tr("Create Label"));
  m_selectedAtom.setLabel(m_text.toStdString());
  m_molecule->endMergeMode();
  m_text.clear();
  m_selectedAtom = RWAtom();
}

QUndoCommand* LabelEditor::mousePressEvent(QMouseEvent* e)
{
  if (!m_renderer || !m_molecule)
    return nullptr;

  if (e->buttons() & Qt::LeftButton) {
    e->accept();
    if (m_selectedAtom.isValid()) {
      save();
    }

    Identifier clickedObject = m_renderer->hit(e->pos().x(), e->pos().y());
    m_selected = (clickedObject.type == Rendering::AtomType);
    if (m_selected) {
      m_selectedAtom = m_molecule->atom(clickedObject.index);
      m_text = QString::fromStdString(m_selectedAtom.label());
    }
    emit drawablesChanged();
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
  if (m_renderer == nullptr || m_molecule == nullptr || !m_selected ||
      !m_selectedAtom.isValid()) {
    return;
  }
  auto* geometry = new GeometryNode;
  node.addChild(geometry);

  unsigned char atomicNumber = m_selectedAtom.atomicNumber();
  const Vector3f pos(m_selectedAtom.position3d().cast<float>());
  float radius = static_cast<float>(Elements::radiusVDW(atomicNumber)) * 0.6f;

  TextLabel3D* atomLabel = createLabel(m_text.toStdString(), pos, radius);
  geometry->addDrawable(atomLabel);
}
} // namespace Avogadro
