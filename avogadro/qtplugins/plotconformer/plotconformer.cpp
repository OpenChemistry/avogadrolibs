/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plotconformer.h"

#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QEvent>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>
#include <vector>

#include <avogadro/core/angletools.h>
#include <avogadro/core/array.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/chartwidget.h>
#include <avogadro/qtgui/molecule.h>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

constexpr double HartreeToKcal = 627.5094740631;
constexpr double EvToKcal = 23.06054;
constexpr double KcalToKJ = 4.184; // by definition

using Core::Array;

// Atom numbers are 1-based here, matching the constraints dialog and the
// property tables.
static QString constraintLabel(const Core::Constraint& c)
{
  const int a = static_cast<int>(c.aIndex()) + 1;
  const int b = static_cast<int>(c.bIndex()) + 1;
  const int cc = static_cast<int>(c.cIndex()) + 1;
  const int d = static_cast<int>(c.dIndex()) + 1;

  switch (c.type()) {
    case Core::Constraint::DistanceConstraint:
      return PlotConformer::tr("Distance %1-%2").arg(a).arg(b);
    case Core::Constraint::AngleConstraint:
      return PlotConformer::tr("Angle %1-%2-%3").arg(a).arg(b).arg(cc);
    case Core::Constraint::TorsionConstraint:
      return PlotConformer::tr("Dihedral %1-%2-%3-%4")
        .arg(a)
        .arg(b)
        .arg(cc)
        .arg(d);
    default:
      return PlotConformer::tr("Constraint");
  }
}

static QString axisTitleForConstraint(const Core::Constraint& c)
{
  switch (c.type()) {
    case Core::Constraint::DistanceConstraint:
      // Not necessarily a bond -- any pair of atoms can be constrained.
      return PlotConformer::tr("Distance (Å)");
    case Core::Constraint::AngleConstraint:
      return PlotConformer::tr("Angle (°)");
    case Core::Constraint::TorsionConstraint:
      return PlotConformer::tr("Dihedral (°)");
    default:
      return PlotConformer::tr("Frame");
  }
}

// The selected atoms, in ascending index order. Molecule stores selection as a
// flag per atom, so the order the user clicked them in is not available.
static std::vector<Index> selectedAtoms(const QtGui::Molecule& molecule)
{
  std::vector<Index> selection;
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    if (molecule.atomSelected(i))
      selection.push_back(i);
  }
  return selection;
}

static bool bonded(const QtGui::Molecule& molecule, Index a, Index b)
{
  return molecule.bond(a, b).isValid();
}

// Put the selection in the order that names a chemically meaningful
// coordinate: the angle vertex in the middle, the torsion along its path.
// Ascending index order is the fallback when the atoms are not connected,
// which is legitimate for a distance between two ends of a molecule.
static bool orderSelection(const QtGui::Molecule& molecule,
                           std::vector<Index>& atoms)
{
  if (atoms.size() == 2)
    return true;

  if (atoms.size() == 3) {
    // Whichever atom is bonded to both others is the vertex.
    for (size_t i = 0; i < 3; ++i) {
      const Index vertex = atoms[i];
      const Index first = atoms[(i + 1) % 3];
      const Index second = atoms[(i + 2) % 3];
      if (bonded(molecule, vertex, first) && bonded(molecule, vertex, second)) {
        atoms = { first, vertex, second };
        return true;
      }
    }
    return false;
  }

  if (atoms.size() == 4) {
    // Look for the path a-b-c-d. Four atoms is 24 orderings, so just try them.
    std::vector<Index> candidate = atoms;
    std::sort(candidate.begin(), candidate.end());
    do {
      if (bonded(molecule, candidate[0], candidate[1]) &&
          bonded(molecule, candidate[1], candidate[2]) &&
          bonded(molecule, candidate[2], candidate[3])) {
        atoms = candidate;
        return true;
      }
    } while (std::next_permutation(candidate.begin(), candidate.end()));
    return false;
  }

  return false;
}

// Axis limits for a series: pad by a fraction of its range so the extreme
// points are not drawn on the frame, and fall back to a fixed pad when the
// series is flat and has no range to take a fraction of. The two axes pad
// differently because their units are not comparable -- an Angstrom on a
// distance axis is a wide margin, a kcal/mol on an energy axis is not.
static std::pair<float, float> paddedRange(const DataSeries& values,
                                           float fraction, float flatPad)
{
  const auto bounds = std::minmax_element(values.begin(), values.end());
  const float low = *bounds.first;
  const float high = *bounds.second;
  const float pad = (high > low) ? fraction * (high - low) : flatPad;
  return { low - pad, high + pad };
}

// One entry a combo can offer: what to call it, the quantity value the rest of
// the code works with, and a name for the thing itself.
struct PlotQuantity
{
  QString label;
  int quantity;
  QString identity;
};

// A combo item's identity, held in its own data role. The quantity value is
// only a position in m_coordinates, which moves when a constraint is added or
// an atom is deleted, so it cannot be what a selection is restored by.
constexpr int IdentityRole = Qt::UserRole + 1;

// Names a coordinate by the atoms it measures. Built-in quantities have no
// atoms, so they are named by their own value; the two cannot collide, since
// only these carry a separator.
static QString coordinateIdentity(const Core::Constraint& c)
{
  return QStringLiteral("%1:%2:%3:%4")
    .arg(c.aIndex())
    .arg(c.bIndex())
    .arg(c.cIndex())
    .arg(c.dIndex());
}

// Both axes offer the same quantities, so fill them from one list. Keeping the
// current selection matters here: the combos are rebuilt whenever a constraint
// is added, which should not throw away what the user was looking at, nor
// quietly move the axis to whatever coordinate inherited its old number.
static void fillQuantityCombo(QComboBox* combo,
                              const std::vector<PlotQuantity>& quantities,
                              int fallback)
{
  if (combo == nullptr)
    return;

  const QString previous = combo->currentData(IdentityRole).toString();

  QSignalBlocker blocker(combo);
  combo->clear();
  for (const auto& quantity : quantities) {
    combo->addItem(quantity.label, quantity.quantity);
    combo->setItemData(combo->count() - 1, quantity.identity, IdentityRole);
  }

  int index = previous.isEmpty() ? -1 : combo->findData(previous, IdentityRole);
  if (index < 0)
    index = combo->findData(fallback);
  combo->setCurrentIndex(index < 0 ? 0 : index);
}

PlotConformer::PlotConformer(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_displayDialogAction(new QAction(this)),
    m_chartWidget(nullptr), m_yAxisCombo(nullptr), m_xAxisCombo(nullptr),
    m_unitsCombo(nullptr), m_timeStepSpin(nullptr), m_targetUnitsCombo(nullptr),
    m_unwrapDihedralsCheck(nullptr), m_timeStepLabel(nullptr),
    m_addSelectionButton(nullptr), m_frameLabel(nullptr)
{
  m_displayDialogAction->setText(tr("Plot Conformer Data…"));
  connect(m_displayDialogAction, &QAction::triggered, this,
          &PlotConformer::displayDialog);
  m_actions.push_back(m_displayDialogAction);
  m_displayDialogAction->setProperty("menu priority", -890);

  updateActions();
}

PlotConformer::~PlotConformer() = default;

QList<QAction*> PlotConformer::actions() const
{
  return m_actions;
}

QStringList PlotConformer::menuPath(QAction*) const
{
  return QStringList() << tr("&Analyze");
}

void PlotConformer::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  if (m_molecule)
    connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

  // Follow whichever conformer the new molecule is already showing.
  m_currentFrame = m_molecule ? m_molecule->coordinate3d() : 0;

  // A different molecule brings its own trajectory, and may bring its own
  // idea of how far apart the frames are.
  m_estimatedVelocities = false;
  m_timeStepSeeded = false;
  seedTimeStepFromMolecule();

  if (m_dialog && m_dialog->isVisible()) {
    if (m_molecule && m_molecule->coordinate3dCount() > 1) {
      populateQuantityCombos();
      updatePlot();
    } else {
      m_dialog->hide();
    }
  }

  updateActions();
}

void PlotConformer::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  auto changes = static_cast<Molecule::MoleculeChanges>(c);

  const bool conformerChange = (changes & Molecule::Conformer) != 0;
  const bool constraintChange = (changes & Molecule::Constraints) != 0;
  const bool propertyChange = (changes & Molecule::Properties) != 0;
  const bool selectionChange = (changes & Molecule::Selection) != 0;
  const bool structural = (changes & Molecule::Added) ||
                          (changes & Molecule::Removed) ||
                          (changes & Molecule::Modified);
  if (structural)
    updateActions();

  // Velocities differenced from the trajectory go stale as soon as the atoms
  // move, change in number, or are renumbered. Selecting an atom or stepping
  // to another conformer does none of those, and those are the common cases.
  if (structural || (changes & Molecule::Moved) ||
      (changes & Molecule::Reordered))
    m_estimatedVelocities = false;

  if (!m_molecule || !m_dialog || !m_dialog->isVisible())
    return;

  if (conformerChange) {
    // Someone else - typically the player tool - moved to a different
    // conformer, so move the marker to match. Playback with dynamic bonding
    // also flags added/removed atoms, but the curve itself is unchanged, so
    // check this before the structural case and skip the expensive replot.
    int frame = m_molecule->coordinate3d();
    if (frame != m_currentFrame) {
      m_currentFrame = frame;
      drawChart();
    }
    return;
  }

  if (selectionChange && !structural && !constraintChange && !propertyChange) {
    // Selecting atoms changes nothing that is plotted, only whether a new
    // coordinate can be made from them.
    updateSelectionButton();
    return;
  }

  if (structural || constraintChange || propertyChange) {
    // Atoms, coordinate sets, energies, constraints or scan coordinates may
    // all have changed under us, and deleting atoms can invalidate the
    // coordinate currently driving an axis.
    m_currentFrame = m_molecule->coordinate3d();
    populateQuantityCombos();
    updatePlot();
  }
}

void PlotConformer::updateActions()
{
  // Disable everything for nullptr molecules.
  if (!m_molecule) {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
    return;
  }

  // Only display the actions if multimolecule.
  if (m_molecule->coordinate3dCount() > 1) {
    foreach (QAction* action, m_actions)
      action->setEnabled(true);
  } else {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
  }
}

void PlotConformer::clicked(float x, float, Qt::KeyboardModifiers)
{
  // switch to the closest conformer to x
  if (xQuantity() == FrameQuantity) {
    setFrame(static_cast<int>(std::lround(x)));
    return;
  }

  // Anything else is unevenly spaced and need not even be monotonic, so look
  // for the frame plotted nearest the click.
  int frame = -1;
  float best = std::numeric_limits<float>::max();
  for (size_t i = 0; i < m_xData.size(); ++i) {
    const float distance = std::fabs(m_xData[i] - x);
    if (distance < best) {
      best = distance;
      frame = static_cast<int>(i);
    }
  }

  if (frame >= 0)
    setFrame(frame);
}

void PlotConformer::setFrame(int frame)
{
  if (!m_molecule)
    return;

  auto count = static_cast<int>(m_molecule->coordinate3dCount());
  if (count < 1)
    return;

  frame = std::clamp(frame, 0, count - 1);
  if (frame == m_currentFrame && frame == m_molecule->coordinate3d())
    return;

  m_currentFrame = frame;
  m_molecule->setCoordinate3d(frame);
  drawChart();
  // Moved (rather than Modified) keeps derived data alive, and Conformer lets
  // the player tool pick the new frame up.
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Moved |
                          Molecule::Conformer);
}

bool PlotConformer::eventFilter(QObject* object, QEvent* event)
{
  if (!m_dialog || object != m_dialog.get() ||
      event->type() != QEvent::KeyPress)
    return QtGui::ExtensionPlugin::eventFilter(object, event);

  auto count =
    m_molecule ? static_cast<int>(m_molecule->coordinate3dCount()) : 0;
  if (count < 2)
    return QtGui::ExtensionPlugin::eventFilter(object, event);

  auto* keyEvent = static_cast<QKeyEvent*>(event);
  // Shift takes bigger strides through long trajectories.
  const int step = (keyEvent->modifiers() & Qt::ShiftModifier) ? 10 : 1;

  switch (keyEvent->key()) {
    case Qt::Key_Left:
    case Qt::Key_Down:
      setFrame(m_currentFrame - step);
      return true;
    case Qt::Key_Right:
    case Qt::Key_Up:
      setFrame(m_currentFrame + step);
      return true;
    case Qt::Key_PageDown:
      setFrame(m_currentFrame - 10);
      return true;
    case Qt::Key_PageUp:
      setFrame(m_currentFrame + 10);
      return true;
    case Qt::Key_Home:
      setFrame(0);
      return true;
    case Qt::Key_End:
      setFrame(count - 1);
      return true;
    default:
      break;
  }

  return QtGui::ExtensionPlugin::eventFilter(object, event);
}

void PlotConformer::collectCoordinates()
{
  m_coordinates.clear();
  if (!m_molecule)
    return;

  const Index atoms = m_molecule->atomCount();

  // Constraints first: they are what an optimizer was told to hold, so they
  // are the likeliest thing a relaxed scan stepped through.
  for (const auto& constraint : m_molecule->constraints()) {
    // An out-of-plane constraint has no single value, and one left over from
    // deleted atoms would measure to the origin.
    if (constraint.isValid(atoms))
      m_coordinates.push_back(constraint);
  }

  // Then coordinates the user asked to follow, which a file may also carry.
  for (const auto& coordinate : m_molecule->scanCoordinates()) {
    if (!coordinate.isValid(atoms))
      continue;

    const bool duplicate =
      std::any_of(m_coordinates.begin(), m_coordinates.end(),
                  [&coordinate](const Core::Constraint& existing) {
                    return existing.atoms() == coordinate.atoms();
                  });
    if (!duplicate)
      m_coordinates.push_back(coordinate);
  }
}

void PlotConformer::populateQuantityCombos()
{
  if (!m_molecule || !m_xAxisCombo || !m_yAxisCombo)
    return;

  collectCoordinates();

  const bool hasEnergies = m_molecule->hasData("energies");
  const bool hasForces = m_molecule->hasData("forces");
  // Velocities are differenced between neighbouring frames, so one geometry
  // has none, and the time step supplies what the file leaves out -- which
  // means these are on offer for any trajectory, not only one that stored
  // velocities.
  const bool isTrajectory = m_molecule->coordinate3dCount() > 1;
  // Temperature comes out of the kinetic energy once the drift of the whole
  // molecule is removed, and a single atom has nothing left after that.
  const bool hasTemperature = isTrajectory && m_molecule->atomCount() > 1;

  std::vector<PlotQuantity> quantities;
  const auto builtIn = [](const QString& label, int quantity) {
    return PlotQuantity{ label, quantity, QString::number(quantity) };
  };
  quantities.push_back(builtIn(tr("Frame"), FrameQuantity));
  if (isTrajectory)
    quantities.push_back(builtIn(tr("Time"), TimeQuantity));
  quantities.push_back(builtIn(tr("RMSD"), RmsdQuantity));
  if (hasEnergies)
    quantities.push_back(builtIn(tr("Energy"), EnergyQuantity));
  if (hasForces)
    quantities.push_back(builtIn(tr("Forces"), ForcesQuantity));
  if (isTrajectory)
    quantities.push_back(builtIn(tr("Mean Speed"), VelocitiesQuantity));
  if (hasTemperature)
    quantities.push_back(builtIn(tr("Temperature"), TemperatureQuantity));

  // One entry per coordinate, so a scanned coordinate can go on either axis.
  for (int i = 0; i < static_cast<int>(m_coordinates.size()); ++i) {
    const Core::Constraint& coordinate = m_coordinates[static_cast<size_t>(i)];
    quantities.push_back(PlotQuantity{ constraintLabel(coordinate), i,
                                       coordinateIdentity(coordinate) });
  }

  fillQuantityCombo(m_xAxisCombo, quantities, FrameQuantity);
  fillQuantityCombo(m_yAxisCombo, quantities,
                    hasEnergies ? EnergyQuantity : RmsdQuantity);

  updateSelectionButton();
  // updatePlot() runs after every call to this, and owns the unit combos.
}

void PlotConformer::updateSelectionButton()
{
  if (!m_addSelectionButton)
    return;

  if (!m_molecule) {
    m_addSelectionButton->setEnabled(false);
    return;
  }

  const size_t count = selectedAtoms(*m_molecule).size();
  m_addSelectionButton->setEnabled(count >= 2 && count <= 4);
  m_addSelectionButton->setToolTip(
    tr("Select 2, 3 or 4 atoms to follow a distance, angle or dihedral "
       "across the conformers."));
}

void PlotConformer::addCoordinateFromSelection()
{
  if (!m_molecule)
    return;

  std::vector<Index> atoms = selectedAtoms(*m_molecule);
  if (atoms.size() < 2 || atoms.size() > 4)
    return;

  // Connectivity decides the order where it can; otherwise the atoms are
  // taken as they are numbered, which is still a usable distance.
  orderSelection(*m_molecule, atoms);

  Core::Constraint coordinate(atoms[0], atoms[1],
                              atoms.size() > 2 ? atoms[2] : MaxIndex,
                              atoms.size() > 3 ? atoms[3] : MaxIndex);
  m_molecule->addScanCoordinate(coordinate);

  // Show what was just added rather than making the user find it, looking it
  // up by the atoms it measures: it is not necessarily the last entry, since a
  // coordinate matching an existing constraint is listed once, under the
  // constraint. Select it before announcing the change, with the combo's own
  // signal blocked, so that the replot below is the only one: generating the
  // series walks the whole trajectory.
  populateQuantityCombos();
  const int index =
    m_xAxisCombo->findData(coordinateIdentity(coordinate), IdentityRole);
  if (index >= 0) {
    QSignalBlocker blocker(m_xAxisCombo);
    m_xAxisCombo->setCurrentIndex(index);
  }

  // Stored in the property map, so this is a property change. Handling it
  // repopulates the combos and replots.
  m_molecule->emitChanged(Molecule::Properties);
}

int PlotConformer::xQuantity() const
{
  if (!m_xAxisCombo)
    return FrameQuantity;

  bool ok = false;
  const int quantity = m_xAxisCombo->currentData().toInt(&ok);
  return ok ? quantity : FrameQuantity;
}

int PlotConformer::yQuantity() const
{
  if (!m_yAxisCombo)
    return FrameQuantity;

  bool ok = false;
  const int quantity = m_yAxisCombo->currentData().toInt(&ok);
  return ok ? quantity : FrameQuantity;
}

bool PlotConformer::isTorsionQuantity(int quantity) const
{
  if (quantity < 0 || quantity >= static_cast<int>(m_coordinates.size()))
    return false;

  return m_coordinates[static_cast<size_t>(quantity)].type() ==
         Core::Constraint::TorsionConstraint;
}

bool PlotConformer::isDynamicsQuantity(int quantity)
{
  return quantity == VelocitiesQuantity || quantity == TemperatureQuantity;
}

void PlotConformer::displayDialog()
{
  if (!m_molecule)
    return;

  if (!m_dialog) {
    // Create the dialog
    m_dialog.reset(new QDialog(qobject_cast<QWidget*>(this->parent())));
    m_dialog->setWindowTitle(tr("Conformer Analysis"));
    m_dialog->resize(600, 500);

    // Create main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(m_dialog.get());

    // Create chart widget
    m_chartWidget = new QtGui::ChartWidget(m_dialog.get());
    // Take the focus so the arrow keys reach the dialog's event filter rather
    // than the combo boxes below.
    m_chartWidget->setFocusPolicy(Qt::StrongFocus);
    connect(m_chartWidget, &QtGui::ChartWidget::clicked, this,
            &PlotConformer::clicked);
    mainLayout->addWidget(m_chartWidget);

    // Current conformer, plus a reminder of the keyboard navigation
    m_frameLabel = new QLabel(m_dialog.get());
    m_frameLabel->setTextFormat(Qt::PlainText);
    mainLayout->addWidget(m_frameLabel);

    // Axis selection, reading as a sentence: "Plot Energy vs Dihedral 1-2-3-4"
    QHBoxLayout* axisLayout = new QHBoxLayout();
    QLabel* plotLabel = new QLabel(tr("Plot:"), m_dialog.get());
    m_yAxisCombo = new QComboBox(m_dialog.get());
    QLabel* versusLabel = new QLabel(tr("vs"), m_dialog.get());
    m_xAxisCombo = new QComboBox(m_dialog.get());

    axisLayout->addWidget(plotLabel);
    axisLayout->addWidget(m_yAxisCombo);
    axisLayout->addWidget(versusLabel);
    axisLayout->addWidget(m_xAxisCombo);
    axisLayout->addStretch();
    mainLayout->addLayout(axisLayout);

    m_addSelectionButton =
      new QPushButton(tr("Add from Selection"), m_dialog.get());
    axisLayout->addWidget(m_addSelectionButton);

    m_unwrapDihedralsCheck =
      new QCheckBox(tr("Unwrap dihedral scans"), m_dialog.get());
    m_unwrapDihedralsCheck->setChecked(true);
    mainLayout->addWidget(m_unwrapDihedralsCheck);

    // Create energy conversion layout
    QHBoxLayout* conversionLayout = new QHBoxLayout();
    QLabel* conversionLabel = new QLabel(tr("Energy Units:"), m_dialog.get());
    m_unitsCombo = new QComboBox(m_dialog.get());
    m_unitsCombo->addItem(QStringLiteral("Hartree"), HartreeToKcal);
    m_unitsCombo->addItem(QStringLiteral("eV"), EvToKcal);
    m_unitsCombo->addItem(QStringLiteral("kcal/mol"), 1.0);
    m_unitsCombo->addItem(QStringLiteral("kJ/mol"), KcalToKJ);

    QLabel* targetLabel = new QLabel(tr("to"), m_dialog.get());
    m_targetUnitsCombo = new QComboBox(m_dialog.get());
    m_targetUnitsCombo->addItem(QStringLiteral("kcal/mol"), 1.0);
    m_targetUnitsCombo->addItem(QStringLiteral("kJ/mol"), KcalToKJ);
    m_targetUnitsCombo->addItem(QStringLiteral("eV"), 1.0 / EvToKcal);
    m_targetUnitsCombo->addItem(QStringLiteral("Hartree"), 1.0 / HartreeToKcal);

    conversionLayout->addWidget(conversionLabel);
    conversionLayout->addWidget(m_unitsCombo);
    conversionLayout->addWidget(targetLabel);
    conversionLayout->addWidget(m_targetUnitsCombo);
    conversionLayout->addStretch();
    mainLayout->addLayout(conversionLayout);

    // How far apart the saved frames are. Velocities are differenced across
    // the trajectory, so nothing derived from them -- speed, temperature, the
    // time axis -- means anything without it, and few trajectory formats
    // record it: an XYZ or SDF trajectory carries no time at all, and a LAMMPS
    // dump carries the step number rather than a time. DCD is the one that
    // does, and seeds this below.
    QHBoxLayout* timeStepLayout = new QHBoxLayout();
    m_timeStepLabel = new QLabel(tr("Time between frames:"), m_dialog.get());
    m_timeStepSpin = new QDoubleSpinBox(m_dialog.get());
    m_timeStepSpin->setDecimals(4);
    m_timeStepSpin->setRange(0.0001, 1.0e6);
    m_timeStepSpin->setValue(1.0);
    m_timeStepSpin->setSingleStep(0.1);
    m_timeStepSpin->setSuffix(tr(" ps"));
    m_timeStepSpin->setToolTip(
      tr("The interval between saved frames, used to turn the trajectory into "
         "velocities and a temperature. Most trajectory files do not record "
         "it, so it starts at the value from the file where there is one and "
         "at 1 ps otherwise."));
    m_timeStepLabel->setBuddy(m_timeStepSpin);

    timeStepLayout->addWidget(m_timeStepLabel);
    timeStepLayout->addWidget(m_timeStepSpin);
    timeStepLayout->addStretch();
    mainLayout->addLayout(timeStepLayout);

    // Connect signals for updates
    connect(m_yAxisCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PlotConformer::updatePlot);
    connect(m_xAxisCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PlotConformer::updatePlot);
    connect(m_unitsCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PlotConformer::updatePlot);
    connect(m_targetUnitsCombo,
            QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &PlotConformer::updatePlot);
    connect(m_unwrapDihedralsCheck, &QCheckBox::toggled, this,
            &PlotConformer::updatePlot);
    connect(m_timeStepSpin,
            QOverload<double>::of(&QDoubleSpinBox::valueChanged), this,
            [this](double) {
              // A new time step invalidates whatever we differenced with the
              // old one.
              m_estimatedVelocities = false;
              updatePlot();
            });
    connect(m_addSelectionButton, &QPushButton::clicked, this,
            &PlotConformer::addCoordinateFromSelection);

    // Key presses that the chart and buttons ignore bubble up to the dialog,
    // where the filter turns them into conformer navigation. Filtering here
    // rather than with shortcuts leaves the combo boxes' own arrow handling
    // intact.
    m_dialog->installEventFilter(this);
  }

  seedTimeStepFromMolecule();
  populateQuantityCombos();
  m_currentFrame = m_molecule->coordinate3d();
  updatePlot();
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
  m_chartWidget->setFocus();
}

std::optional<PlotConformer::QuantitySeries> PlotConformer::evaluateQuantity(
  int quantity)
{
  if (!m_molecule)
    return std::nullopt;

  QString title;
  std::optional<DataSeries> values;
  DataSeries errors;

  if (quantity >= 0) {
    if (quantity >= static_cast<int>(m_coordinates.size()))
      return std::nullopt;
    title =
      axisTitleForConstraint(m_coordinates[static_cast<size_t>(quantity)]);
    values = generateCoordinateSeries(quantity);
  } else {
    switch (quantity) {
      case FrameQuantity:
        title = tr("Frame");
        values = generateFrameSeries();
        break;
      case TimeQuantity:
        title = tr("Time (ps)");
        values = generateTimeSeries();
        break;
      case RmsdQuantity:
        title = tr("RMSD (Å)");
        values = generateRmsdSeries();
        break;
      case EnergyQuantity:
        title = tr("Relative Energy (%1)")
                  .arg(m_targetUnitsCombo ? m_targetUnitsCombo->currentText()
                                          : QString());
        values = generateEnergySeries();
        break;
      case ForcesQuantity:
        // TODO: Add units - data("forces") holds the RMS gradient per set
        title = tr("RMS Gradient");
        values = generateStoredSeries("forces");
        break;
      case VelocitiesQuantity:
        // The mean over the atoms of how fast each one is moving. The spread
        // of that distribution rides along as error bars, since a mean speed
        // says very little on its own -- a cold molecule with one hot atom
        // and a uniformly warm one can share it.
        title = tr("Mean Speed (Å/ps)");
        if (ensureVelocities()) {
          values = generateStoredSeries("velocities");
          if (auto spread = generateStoredSeries("velocityDeviations"))
            errors = std::move(*spread);
        }
        break;
      case TemperatureQuantity:
        title = tr("Temperature (K)");
        if (ensureVelocities())
          values = generateStoredSeries("temperatures");
        break;
      default:
        return std::nullopt;
    }
  }

  if (!values)
    return std::nullopt;

  // An error bar per point or none at all -- a partial set would put bars on
  // the wrong frames.
  if (errors.size() != values->size())
    errors.clear();

  return QuantitySeries{ std::move(*values), std::move(errors), title };
}

void PlotConformer::updatePlot()
{
  if (!m_molecule || !m_chartWidget || !m_xAxisCombo || !m_yAxisCombo)
    return;

  m_xData.clear();
  m_yData.clear();
  m_yErrors.clear();

  const int xq = xQuantity();
  const int yq = yQuantity();

  // The units only apply while one of the axes is showing energies.
  const bool plottingEnergy = (xq == EnergyQuantity || yq == EnergyQuantity);
  if (m_unitsCombo)
    m_unitsCombo->setEnabled(plottingEnergy);
  if (m_targetUnitsCombo)
    m_targetUnitsCombo->setEnabled(plottingEnergy);

  // The time step only matters while something on the plot is measured
  // against time.
  const bool plottingTime = xq == TimeQuantity || yq == TimeQuantity ||
                            isDynamicsQuantity(xq) || isDynamicsQuantity(yq);
  if (m_timeStepSpin)
    m_timeStepSpin->setEnabled(plottingTime);
  if (m_timeStepLabel)
    m_timeStepLabel->setEnabled(plottingTime);

  // Nothing but a torsion wraps, so the option is meaningless otherwise.
  const bool xIsTorsion = isTorsionQuantity(xq);
  const bool yIsTorsion = isTorsionQuantity(yq);
  if (m_unwrapDihedralsCheck)
    m_unwrapDihedralsCheck->setEnabled(xIsTorsion || yIsTorsion);

  std::optional<QuantitySeries> xSeries = evaluateQuantity(xq);
  std::optional<QuantitySeries> ySeries = evaluateQuantity(yq);
  if (!xSeries || !ySeries) {
    drawChart();
    return;
  }

  DataSeries x = std::move(xSeries->values);
  DataSeries y = std::move(ySeries->values);
  DataSeries yErrors = std::move(ySeries->errors);

  // Every series is one value per coordinate set, in order from the first, so
  // a point's position in the array is its frame number -- which is what lets
  // the marker and the click handling below map between the two. A file can
  // still carry fewer energies or gradients than it has geometries, so keep
  // the leading frames both series have rather than handing the chart two
  // series of different lengths.
  const size_t points = std::min(x.size(), y.size());
  x.resize(points);
  y.resize(points);
  if (!yErrors.empty())
    yErrors.resize(points);

  const bool unwrap =
    m_unwrapDihedralsCheck && m_unwrapDihedralsCheck->isChecked();
  const auto unwrapTorsion = [unwrap](DataSeries& values, bool isTorsion) {
    if (!unwrap || !isTorsion)
      return;
    unwrapPeriodicValues(values, 360.0f);
    shiftValuesToWindow(values, 360.0f, -180.0f, 180.0f);
  };
  unwrapTorsion(x, xIsTorsion);
  unwrapTorsion(y, yIsTorsion);

  m_xData = std::move(x);
  m_yData = std::move(y);
  m_yErrors = std::move(yErrors);
  m_xTitle = xSeries->title;
  m_yTitle = ySeries->title;

  if (!m_xData.empty() && !m_yData.empty()) {
    // Frames are counted rather than measured, so that axis spans the whole
    // trajectory whatever the data does.
    m_xLimits =
      (xq == FrameQuantity)
        ? std::make_pair(
            -0.1f, static_cast<float>(m_molecule->coordinate3dCount()) - 0.9f)
        : paddedRange(m_xData, 0.02f, 1.0e-3f);
    // Error bars reach past the points they hang off, so the axis has to be
    // scaled to their ends rather than to the means.
    if (m_yErrors.empty()) {
      m_yLimits = paddedRange(m_yData, 0.05f, 1.0f);
    } else {
      DataSeries extremes;
      extremes.reserve(m_yData.size() * 2);
      for (size_t i = 0; i < m_yData.size(); ++i) {
        extremes.push_back(m_yData[i] - m_yErrors[i]);
        extremes.push_back(m_yData[i] + m_yErrors[i]);
      }
      m_yLimits = paddedRange(extremes, 0.05f, 1.0f);
    }
  }

  drawChart();
}

void PlotConformer::drawChart()
{
  if (!m_chartWidget)
    return;

  m_chartWidget->clearPlots();

  auto count =
    m_molecule ? static_cast<int>(m_molecule->coordinate3dCount()) : 0;
  if (m_frameLabel) {
    if (count > 0)
      m_frameLabel->setText(
        tr("Conformer %1 of %2 — use ← and → to step through them")
          .arg(m_currentFrame + 1)
          .arg(count));
    else
      m_frameLabel->clear();
  }

  if (m_xData.empty() || m_yData.empty())
    return;

  m_chartWidget->setShowPoints(true);
  m_chartWidget->setLegendLocation(QtGui::ChartWidget::LegendLocation::None);
  if (m_yErrors.size() == m_yData.size())
    m_chartWidget->addPlot(m_xData, m_yData, m_yErrors,
                           QtGui::color4ub{ 255, 0, 0, 255 });
  else
    m_chartWidget->addPlot(m_xData, m_yData, QtGui::color4ub{ 255, 0, 0, 255 });

  // Add a marker for the current frame
  if (m_currentFrame >= 0 &&
      m_currentFrame < static_cast<int>(m_xData.size())) {
    DataSeries markerX = { m_xData[m_currentFrame] };
    DataSeries markerY = { m_yData[m_currentFrame] };
    m_chartWidget->addPlot(markerX, markerY,
                           QtGui::color4ub{ 255, 165, 0, 255 });
  }

  // The limits arrived with the data: this runs on every arrow key, and
  // rescanning a long trajectory for its extremes each time is wasted work.
  m_chartWidget->setXAxisLimits(m_xLimits.first, m_xLimits.second);
  m_chartWidget->setYAxisLimits(m_yLimits.first, m_yLimits.second);
  m_chartWidget->setXAxisTitle(m_xTitle);
  m_chartWidget->setYAxisTitle(m_yTitle);
}

std::optional<DataSeries> PlotConformer::generateFrameSeries() const
{
  if (!m_molecule)
    return std::nullopt;

  const size_t count = m_molecule->coordinate3dCount();
  if (count == 0)
    return std::nullopt;

  DataSeries values;
  values.reserve(count);
  for (size_t i = 0; i < count; ++i)
    values.push_back(static_cast<float>(i));

  return values;
}

std::optional<DataSeries> PlotConformer::generateTimeSeries() const
{
  if (!m_molecule)
    return std::nullopt;

  const size_t count = m_molecule->coordinate3dCount();
  if (count < 2)
    return std::nullopt;

  // Evenly spaced by construction: the same step that the velocities were
  // differenced with, so the two axes agree about when each frame happened.
  const double step = timeStep();
  DataSeries values;
  values.reserve(count);
  for (size_t i = 0; i < count; ++i)
    values.push_back(static_cast<float>(i * step));

  return values;
}

double PlotConformer::timeStep() const
{
  return m_timeStepSpin ? m_timeStepSpin->value() : 1.0;
}

void PlotConformer::seedTimeStepFromMolecule()
{
  if (!m_molecule || !m_timeStepSpin || m_timeStepSeeded)
    return;

  m_timeStepSeeded = true;

  const size_t count = m_molecule->coordinate3dCount();
  if (count < 2)
    return;

  // A file that recorded when its frames were written is worth believing over
  // a default of 1 ps. DCD gives a real interval in picoseconds; a LAMMPS dump
  // records the step number instead, and has no dt anywhere in it to turn that
  // into a time, so what lands here is a step count for the user to correct.
  // Either way it is a number from their own file rather than a guess.
  bool haveFirst = false;
  bool haveLast = false;
  const double first = m_molecule->timeStep(0, haveFirst);
  const double last =
    m_molecule->timeStep(static_cast<int>(count) - 1, haveLast);
  if (!haveFirst || !haveLast)
    return;

  const double spacing = (last - first) / static_cast<double>(count - 1);
  if (spacing >= m_timeStepSpin->minimum() &&
      spacing <= m_timeStepSpin->maximum()) {
    QSignalBlocker blocker(m_timeStepSpin);
    m_timeStepSpin->setValue(spacing);
  }
}

bool PlotConformer::ensureVelocities()
{
  if (!m_molecule || m_molecule->coordinate3dCount() < 2)
    return false;

  // Already differenced, with nothing having moved since: setMolecule(), a
  // structural change and a new time step each clear the flag. Both axes ask
  // for this, so re-differencing the whole trajectory here would be done
  // twice over for nothing.
  if (m_estimatedVelocities)
    return !m_molecule->data("velocities").toList().empty();

  if (!m_molecule->velocities(0).empty()) {
    // Velocities that arrived with the file are the real thing, and must not
    // be differenced over. They may have come in without the derived scalars,
    // though, if whoever set them did not ask for them.
    if (m_molecule->data("velocities").toList().empty())
      m_molecule->updateVelocityProperties();
    return true;
  }

  // Ours, then: redo them, since the trajectory or the time step may have
  // moved under us since the last time.
  m_molecule->estimateVelocities(timeStep());
  m_estimatedVelocities = true;

  return !m_molecule->data("velocities").toList().empty();
}

std::optional<DataSeries> PlotConformer::generateCoordinateSeries(
  int coordinateIndex) const
{
  if (!m_molecule || coordinateIndex < 0 ||
      coordinateIndex >= static_cast<int>(m_coordinates.size()))
    return std::nullopt;

  const Core::Constraint& constraint =
    m_coordinates[static_cast<size_t>(coordinateIndex)];

  // coordinate3dRef() hands back the stored set rather than a copy of it, so
  // reading four atoms out of every frame does not copy the whole molecule
  // once per frame. It does not change the displayed set either, so this reads
  // the trajectory without disturbing the active conformer.
  const size_t count = m_molecule->coordinate3dCount();
  DataSeries values;
  values.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    Real value = 0.0;
    if (!constraint.evaluate(m_molecule->coordinate3dRef(i), value))
      return std::nullopt;
    values.push_back(static_cast<float>(value));
  }

  if (values.empty())
    return std::nullopt;

  return values;
}

std::optional<DataSeries> PlotConformer::generateRmsdSeries() const
{
  if (!m_molecule || m_molecule->coordinate3dCount() == 0)
    return std::nullopt;

  const Array<Vector3>& ref = m_molecule->coordinate3dRef(0);
  if (ref.empty())
    return std::nullopt;

  DataSeries values;
  values.reserve(m_molecule->coordinate3dCount());
  for (size_t i = 0; i < m_molecule->coordinate3dCount(); ++i) {
    const Array<Vector3>& positions = m_molecule->coordinate3dRef(i);
    // Coordinate sets should all describe the same atoms, but compare only as
    // far as both of them go rather than reading off the end of the reference.
    const size_t count = std::min(positions.size(), ref.size());

    double sum = 0.0;
    for (size_t j = 0; j < count; ++j)
      sum += (positions[j] - ref[j]).squaredNorm();

    // RMSD is the root *mean* square deviation over the atoms, so normalize by
    // the number of atoms compared -- not by the number of coordinate sets. An
    // empty set has no atoms to compare and so no deviation to report, but it
    // still gets a point: every series here is indexed by frame, and skipping
    // one would move each later point onto the wrong conformer.
    values.push_back(count > 0 ? static_cast<float>(std::sqrt(sum / count))
                               : 0.0f);
  }

  if (values.empty())
    return std::nullopt;

  return values;
}

std::optional<DataSeries> PlotConformer::generateEnergySeries() const
{
  // plot relative energies so get the minimum first
  if (m_molecule == nullptr || !m_molecule->hasData("energies"))
    return std::nullopt;

  const std::vector<double> energies = m_molecule->data("energies").toList();
  if (energies.empty())
    return std::nullopt;

  const double minEnergy = *std::min_element(energies.begin(), energies.end());

  // Get conversion factors
  const double fromFactor =
    m_unitsCombo ? m_unitsCombo->currentData().toDouble() : 1.0;
  const double toFactor =
    m_targetUnitsCombo ? m_targetUnitsCombo->currentData().toDouble() : 1.0;

  DataSeries values;
  values.reserve(energies.size());
  for (double energy : energies) {
    // Convert: first to kcal/mol, then to target units
    values.push_back(
      static_cast<float>((energy - minEnergy) * fromFactor * toFactor));
  }

  return values;
}

std::optional<DataSeries> PlotConformer::generateStoredSeries(
  const char* key) const
{
  if (m_molecule == nullptr || !m_molecule->hasData(key))
    return std::nullopt;

  const std::vector<double> stored = m_molecule->data(key).toList();
  if (stored.empty())
    return std::nullopt;

  DataSeries values;
  values.reserve(stored.size());
  for (double value : stored)
    values.push_back(static_cast<float>(value));

  return values;
}

} // namespace Avogadro::QtPlugins
