/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "aligntool.h"

#include <avogadro/core/contrastcolor.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <QAction>
#include <QtCore/QDebug>
#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>

#include <avogadro/qtgui/commandregistry.h>

using Avogadro::Core::contrastColor;
using Avogadro::Core::Elements;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;

namespace Avogadro::QtPlugins {

AlignTool::AlignTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_renderer(nullptr), m_axis(0), m_alignType(0),
    m_toolWidget(nullptr)
{
  registerAlignToolCommands();

  m_activateAction->setText(tr("Align"));
  m_activateAction->setToolTip(
    tr("Align Molecules\n\n"
       "Left Mouse:\tSelect up to two atoms.\n"
       "\tThe first atom is centered at the origin.\n"
       "\tThe second atom is aligned to the selected axis.\n"
       "Right Mouse:\tReset alignment.\n"
       "Double-Click:\tCenter the atom at the origin."));
  setIcon();
}

AlignTool::~AlignTool()
{
  if (m_toolWidget)
    m_toolWidget->deleteLater();
}

void AlignTool::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/align_dark.svg"));
  else
    m_activateAction->setIcon(QIcon(":/icons/align_light.svg"));
}

QWidget* AlignTool::toolWidget() const
{
  if (!m_toolWidget) {
    m_toolWidget = new QWidget;

    auto* labelAxis = new QLabel(tr("Axis:"), m_toolWidget);
    labelAxis->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    labelAxis->setMaximumHeight(15);

    // Combo box to select desired axis to align to
    auto* comboAxis = new QComboBox(m_toolWidget);
    comboAxis->addItem("x");
    comboAxis->addItem("y");
    comboAxis->addItem("z");
    comboAxis->setCurrentIndex(m_axis);

    // Button to actually perform actions
    auto* buttonAlign = new QPushButton(m_toolWidget);
    buttonAlign->setText(tr("Align"));
    connect(buttonAlign, SIGNAL(clicked()), this, SLOT(align()));

    auto* gridLayout = new QGridLayout();
    gridLayout->addWidget(labelAxis, 0, 0, 1, 1, Qt::AlignRight);
    auto* hLayout = new QHBoxLayout;
    hLayout->addWidget(comboAxis);
    hLayout->addStretch(1);
    gridLayout->addLayout(hLayout, 0, 1);

    auto* hLayout3 = new QHBoxLayout();
    hLayout3->addStretch(1);
    hLayout3->addWidget(buttonAlign);
    hLayout3->addStretch(1);
    auto* layout = new QVBoxLayout();
    layout->addLayout(gridLayout);
    layout->addLayout(hLayout3);
    layout->addStretch(1);
    m_toolWidget->setLayout(layout);

    connect(comboAxis, SIGNAL(currentIndexChanged(int)), this,
            SLOT(axisChanged(int)));

    connect(m_toolWidget, SIGNAL(destroyed()), this,
            SLOT(toolWidgetDestroyed()));
  }

  return m_toolWidget;
}

void AlignTool::axisChanged(int axis)
{
  // Axis to use - x=0, y=1, z=2
  m_axis = axis;
}

void AlignTool::alignChanged(int align)
{
  // Type of alignment - 0=everything, 1=molecule
  m_alignType = align;
}

bool AlignTool::align()
{
  if (!m_molecule || m_atomIds.isEmpty())
    return false;

  QVector<Index> indices;
  for (const auto id : m_atomIds) {
    const auto atom = m_molecule->atomByUniqueId(id);
    if (!atom.isValid())
      return false;
    indices.append(atom.index());
  }

  auto& undo = m_molecule->undoStack();
  undo.beginMacro(tr("Align Molecule"));
  shiftAtomToOrigin(indices[0]);
  if (indices.size() == 2)
    alignAtomToAxis(indices[1], m_axis);
  undo.endMacro();
  return true;
}

void AlignTool::shiftAtomToOrigin(Index atomIndex)
{
  if (m_molecule == nullptr)
    return;

  // Shift the atom to the origin
  Vector3 shift = m_molecule->atom(atomIndex).position3d();
  const Core::Array<Vector3>& coords = m_molecule->atomPositions3d();
  Core::Array<Vector3> newCoords(coords.size());
  for (Index i = 0; i < coords.size(); ++i)
    newCoords[i] = coords[i] - shift;

  m_molecule->setAtomPositions3d(newCoords, tr("Align at Origin"));
  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void AlignTool::alignAtomToAxis(Index atomIndex, int axis)
{
  if (m_molecule == nullptr)
    return;

  // Align the atom to the specified axis
  [[maybe_unused]] Vector3 align = m_molecule->atom(atomIndex).position3d();
  const Core::Array<Vector3>& coords = m_molecule->atomPositions3d();
  Core::Array<Vector3> newCoords(coords.size());

  [[maybe_unused]] double alpha;
  double beta, gamma;
  alpha = beta = gamma = 0.0;

  Vector3 pos = m_molecule->atom(atomIndex).position3d();
  // an atom at the origin has no direction to align
  if (pos.norm() < 1e-8)
    return;
  pos.normalize();
  Vector3 axisVector;

  if (axis == 0) // x-axis
    axisVector = Vector3(1., 0., 0.);
  else if (axis == 1) // y-axis
    axisVector = Vector3(0., 1., 0.);
  else if (axis == 2) // z-axis
    axisVector = Vector3(0., 0., 1.);
  else
    return;

  // Rotate the atom's direction onto the axis; FromTwoVectors also handles
  // an atom on the negative axis, where the cross product vanishes
  const Eigen::Quaterniond rotation =
    Eigen::Quaterniond::FromTwoVectors(pos, axisVector);

  // Now to rotate the fragment
  for (Index i = 0; i < coords.size(); ++i)
    newCoords[i] = rotation * coords[i];

  m_molecule->setAtomPositions3d(newCoords, tr("Align to Axis"));
  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void AlignTool::toolWidgetDestroyed()
{
  m_toolWidget = nullptr;
}

QUndoCommand* AlignTool::mousePressEvent(QMouseEvent* e)
{
  // If the click is released on an atom, add it to the list
  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());

  // Now add the atom on release.
  if (hit.type == Rendering::AtomType) {
    if (toggleAtom(hit))
      emit drawablesChanged();
    e->accept();
  }

  return nullptr;
}

QUndoCommand* AlignTool::mouseDoubleClickEvent(QMouseEvent* e)
{
  // Reset the atom list
  if (e->button() == Qt::LeftButton && !m_atomIds.isEmpty()) {
    m_atomIds.clear();
    emit drawablesChanged();
    e->accept();
  }
  return nullptr;
}

bool AlignTool::toggleAtom(const Rendering::Identifier& atom)
{
  if (!m_molecule || atom.type != Rendering::AtomType ||
      atom.molecule != &m_molecule->molecule() ||
      atom.index >= m_molecule->atomCount())
    return false;
  const auto id = m_molecule->atomUniqueId(atom.index);
  if (id == MaxIndex)
    return false;

  const auto index = m_atomIds.indexOf(id);
  if (index >= 0) {
    m_atomIds.remove(index);
    return true;
  }

  if (m_atomIds.size() >= 2)
    return false;

  m_atomIds.append(id);
  return true;
}

void AlignTool::draw(Rendering::GroupNode& node)
{
  if (!m_molecule || m_atomIds.isEmpty())
    return;

  auto* geo = new GeometryNode;
  node.addChild(geo);

  TextProperties atomLabelProp;
  atomLabelProp.setFontFamily(TextProperties::SansSerif);
  atomLabelProp.setAlign(TextProperties::HCenter, TextProperties::VCenter);

  for (qsizetype i = 0; i < m_atomIds.size(); ++i) {
    const auto atom = m_molecule->atomByUniqueId(m_atomIds[i]);
    if (!atom.isValid())
      continue;
    const auto atomicNumber = atom.atomicNumber();

    // get the color of the atom
    const unsigned char* color = Elements::color(atomicNumber);
    atomLabelProp.setColorRgb(contrastColor(Vector3ub(color)).data());

    auto* label = new TextLabel3D;
    label->setText(QString("#%1").arg(i + 1).toStdString());
    label->setTextProperties(atomLabelProp);
    label->setAnchor(atom.position3d().cast<float>());
    label->setRadius(
      static_cast<float>(Elements::radiusCovalent(atomicNumber)) + 0.1f);
    geo->addDrawable(label);
  }
}

void AlignTool::registerAlignToolCommands()
{
  using QtGui::CommandArgumentSpec;

  // Center Atom Command
  QtGui::CommandSpec CenterAtom;
  CenterAtom.name = "centerAtom";
  CenterAtom.description = tr("Center the atom at the origin.");
  CenterAtom.needsMolecule = true;
  CenterAtom.arguments = {
    CommandArgumentSpec::atomIndex("index", tr("Index of an atom"))
      .withAliases(QStringList({ "id" }))
      .withRequired(),
  };
  CenterAtom.handler = [this](const QtGui::CommandArguments& args) {
    shiftAtomToOrigin(args.atom("index"));
    emit commandFinished();
  };
  commandRegistry().add(std::move(CenterAtom));

  // Align Picked Atoms Command
  QtGui::CommandSpec AlignPickedAtoms;
  AlignPickedAtoms.name = "alignPickedAtoms";
  AlignPickedAtoms.description = tr("Align picked atoms.");
  AlignPickedAtoms.needsMolecule = true;
  AlignPickedAtoms.arguments = {
    CommandArgumentSpec::enumeration("axis", tr("Target Cartesian axis."),
                                     { "x", "y", "z" })
      .withRequired()

  };
  AlignPickedAtoms.handler = [this](const QtGui::CommandArguments& args) {
    const auto axis = QStringList{ "x", "y", "z" }.indexOf(args.string("axis"));
    axisChanged(axis);
    if (m_atomIds.isEmpty()) {
      emit commandFailed(tr(
        "No atoms have been picked for alignment. Pick 1 or 2 atoms first."));
      return;
    }
    if (!align()) {
      emit commandFailed(tr("Failed to align picked atoms."));
      return;
    }
    emit commandFinished();
  };
  commandRegistry().add(std::move(AlignPickedAtoms));

  // Align Atom Command
  QtGui::CommandSpec AlignAtom;
  AlignAtom.name = "alignAtom";
  AlignAtom.description =
    tr("Rotate the molecule to align the atom to the specified axis.");
  AlignAtom.needsMolecule = true;
  AlignAtom.arguments = {
    CommandArgumentSpec::enumeration("axis", tr("Target Cartesian axis."),
                                     { "x", "y", "z" })
      .withRequired(),
    CommandArgumentSpec::atomIndex("index", tr("Index of atom to be aligned."))
      .withAliases(QStringList({ "id" }))
      .withRequired(),
  };
  AlignAtom.handler = [this](const QtGui::CommandArguments& args) {
    const auto axis = QStringList{ "x", "y", "z" }.indexOf(args.string("axis"));
    Index atomIndex = args.atom("index");
    if (m_molecule) {
      Vector3 pos = m_molecule->atom(atomIndex).position3d();
      if (pos.norm() < 1e-8) {
        emit commandFailed(
          tr("Atom %1 is at the origin and cannot define an alignment axis.")
            .arg(atomIndex));
        return;
      }
    }
    alignAtomToAxis(atomIndex, axis);
    emit commandFinished();
  };
  // NOTE: The original implementation allowed the axis to be either 'x', 'y',
  // 'z' or 0, 1, 2. This implementation removes numeric axes in favor of
  // simplicity, only accepting 'x', 'y', or 'z'.
  commandRegistry().add(std::move(AlignAtom));
}

bool AlignTool::handleCommand(const QString& command,
                              const QVariantMap& options)
{
  return commandRegistry().handle(
    command, options, m_molecule ? &m_molecule->molecule() : nullptr);
}

} // namespace Avogadro::QtPlugins
