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

    // Combo box to select desired aixs to align to
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

void AlignTool::align()
{
  if (m_atoms.size() == 0)
    return;

  if (m_atoms.size() >= 1)
    shiftAtomToOrigin(m_atoms[0].index);
  if (m_atoms.size() == 2)
    alignAtomToAxis(m_atoms[1].index, m_axis);
}

void AlignTool::shiftAtomToOrigin(Index atomIndex)
{
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
  // Align the atom to the specified axis
  [[maybe_unused]] Vector3 align = m_molecule->atom(atomIndex).position3d();
  const Core::Array<Vector3>& coords = m_molecule->atomPositions3d();
  Core::Array<Vector3> newCoords(coords.size());

  [[maybe_unused]] double alpha;
  double beta, gamma;
  alpha = beta = gamma = 0.0;

  Vector3 pos = m_molecule->atom(atomIndex).position3d();
  pos.normalize();
  Vector3 axisVector;

  if (axis == 0) // x-axis
    axisVector = Vector3(1., 0., 0.);
  else if (axis == 1) // y-axis
    axisVector = Vector3(0., 1., 0.);
  else if (axis == 2) // z-axis
    axisVector = Vector3(0., 0., 1.);

  // Calculate the angle of the atom from the axis
  double angle = acos(axisVector.dot(pos));

  // Get the vector for the rotation
  axisVector = axisVector.cross(pos);
  axisVector.normalize();

  // Now to rotate the fragment
  for (Index i = 0; i < coords.size(); ++i)
    newCoords[i] = Eigen::AngleAxisd(-angle, axisVector) * coords[i];

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
  if (e->button() == Qt::LeftButton && !m_atoms.isEmpty()) {
    m_atoms.clear();
    emit drawablesChanged();
    e->accept();
  }
  return nullptr;
}

bool AlignTool::toggleAtom(const Rendering::Identifier& atom)
{
  int ind = m_atoms.indexOf(atom);
  if (ind >= 0) {
    m_atoms.remove(ind);
    return true;
  }

  if (m_atoms.size() >= 2)
    return false;

  m_atoms.push_back(atom);
  return true;
}

void AlignTool::draw(Rendering::GroupNode& node)
{
  if (m_atoms.size() == 0)
    return;

  auto* geo = new GeometryNode;
  node.addChild(geo);

  // Add labels, extract positions
  QVector<Vector3> positions(m_atoms.size(), Vector3());

  TextProperties atomLabelProp;
  atomLabelProp.setFontFamily(TextProperties::SansSerif);
  atomLabelProp.setAlign(TextProperties::HCenter, TextProperties::VCenter);

  for (int i = 0; i < m_atoms.size(); ++i) {
    Identifier& ident = m_atoms[i];
    Q_ASSERT(ident.type == Rendering::AtomType);
    Q_ASSERT(ident.molecule != nullptr);

    auto atom = m_molecule->atom(ident.index);
    Q_ASSERT(atom.isValid());
    unsigned char atomicNumber(atom.atomicNumber());
    positions[i] = atom.position3d();

    // get the color of the atom
    const unsigned char* color = Elements::color(atomicNumber);
    atomLabelProp.setColorRgb(contrastColor(Vector3ub(color)).data());

    auto* label = new TextLabel3D;
    label->setText(QString("#%1").arg(i + 1).toStdString());
    label->setTextProperties(atomLabelProp);
    label->setAnchor(positions[i].cast<float>());
    label->setRadius(
      static_cast<float>(Elements::radiusCovalent(atomicNumber)) + 0.1f);
    geo->addDrawable(label);
  }
}

void AlignTool::registerCommands()
{
  emit registerCommand("centerAtom", tr("Center the atom at the origin."));
  emit registerCommand(
    "alignAtom",
    tr("Rotate the molecule to align the atom to the specified axis."));
}

bool AlignTool::handleCommand(const QString& command,
                              const QVariantMap& options)
{
  if (m_molecule == nullptr)
    return false; // No molecule to handle the command.

  if (command == "centerAtom") {
    if (options.contains("id")) {
      Index atomIndex = options["id"].toInt();
      if (atomIndex < m_molecule->atomCount())
        shiftAtomToOrigin(atomIndex);
      return true;
    } else if (options.contains("index")) {
      Index atomIndex = options["index"].toInt();
      if (atomIndex < m_molecule->atomCount())
        shiftAtomToOrigin(atomIndex);
      return true;
    }
    return false;
  } else if (command == "alignAtom") {
    int axis = -1;
    if (options.contains("axis") && options["axis"].type() == QVariant::Int) {
      axis = options["axis"].toInt();
    } else if (options.contains("axis") &&
               options["axis"].type() == QVariant::String) {
      QString axisString = options["axis"].toString();
      if (axisString == "x")
        axis = 0;
      else if (axisString == "y")
        axis = 1;
      else if (axisString == "z")
        axis = 2;
    }

    if (axis >= 0 && axis < 3) {
      if (options.contains("id")) {
        Index atomIndex = options["id"].toInt();
        if (atomIndex < m_molecule->atomCount())
          alignAtomToAxis(atomIndex, axis);
        return true;
      } else if (options.contains("index")) {
        Index atomIndex = options["index"].toInt();
        if (atomIndex < m_molecule->atomCount())
          alignAtomToAxis(atomIndex, axis);
        return true;
      }
    }

    return false; // invalid options
  }

  return true; // nothing to handle
}

} // namespace Avogadro::QtPlugins
