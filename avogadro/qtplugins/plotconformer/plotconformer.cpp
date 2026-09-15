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
#include <avogadro/core/conformerquantity.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/chartwidget.h>
#include <avogadro/qtgui/conformerquantitytranslator.h>
#include <avogadro/qtgui/energyunits.h>
#include <avogadro/qtgui/molecule.h>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

using QtGui::EnergyUnits;

// Fill @p combo with every energy unit, selecting @p current. The unit itself
// rides along in the item data, so the combo's order need not match the
// enum's.
static void fillUnitCombo(QComboBox* combo, EnergyUnits::Unit current)
{
  QSignalBlocker blocker(combo);
  combo->clear();
  for (EnergyUnits::Unit unit : EnergyUnits::units()) {
    combo->addItem(EnergyUnits::symbol(unit), static_cast<int>(unit));
    if (unit == current)
      combo->setCurrentIndex(combo->count() - 1);
  }
}

static EnergyUnits::Unit unitFromCombo(const QComboBox* combo,
                                       EnergyUnits::Unit fallback)
{
  bool ok = false;
  const int value = combo->currentData().toInt(&ok);
  if (!ok)
    return fallback;

  for (EnergyUnits::Unit unit : EnergyUnits::units()) {
    if (static_cast<int>(unit) == value)
      return unit;
  }
  return fallback;
}

using Core::Array;

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

// A combo item's identity, held in its own data role. The item's value is only
// a position in m_quantities, which moves when a constraint is added or an
// atom is deleted, so it cannot be what a selection is restored by -- the
// quantity's own identifier can.
constexpr int IdentityRole = Qt::UserRole + 1;

static QString quantityIdentity(const Core::ConformerQuantity& quantity)
{
  return QString::fromStdString(quantity.identifier());
}

// Both axes offer the same quantities, so fill them from one list. Keeping the
// current selection matters here: the combos are rebuilt whenever a constraint
// is added, which should not throw away what the user was looking at, nor
// quietly move the axis to whatever coordinate inherited its old number.
static void fillQuantityCombo(
  QComboBox* combo, const std::vector<Core::ConformerQuantity>& quantities,
  Core::ConformerQuantity::Type fallback)
{
  if (combo == nullptr)
    return;

  const QString previous = combo->currentData(IdentityRole).toString();

  QSignalBlocker blocker(combo);
  combo->clear();
  int fallbackIndex = -1;
  for (size_t i = 0; i < quantities.size(); ++i) {
    combo->addItem(QtGui::ConformerQuantityTranslator::name(quantities[i]),
                   static_cast<int>(i));
    combo->setItemData(combo->count() - 1, quantityIdentity(quantities[i]),
                       IdentityRole);
    if (fallbackIndex < 0 && quantities[i].type() == fallback)
      fallbackIndex = static_cast<int>(i);
  }

  int index = previous.isEmpty() ? -1 : combo->findData(previous, IdentityRole);
  if (index < 0)
    index = fallbackIndex;
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
  m_staleVelocities = true;
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
    m_staleVelocities = true;

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
  const Core::ConformerQuantity* xInfo = quantityAt(xQuantity());
  if (xInfo != nullptr &&
      xInfo->type() == Core::ConformerQuantity::Type::Frame) {
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

void PlotConformer::populateQuantityCombos()
{
  if (!m_molecule || !m_xAxisCombo || !m_yAxisCombo)
    return;

  // Core decides what this molecule can be measured for, so the conformer
  // property table offers exactly the same list.
  m_quantities = Core::conformerQuantities(*m_molecule);

  const bool hasEnergies = m_molecule->hasData("energies");
  using Type = Core::ConformerQuantity::Type;
  fillQuantityCombo(m_xAxisCombo, m_quantities, Type::Frame);
  fillQuantityCombo(m_yAxisCombo, m_quantities,
                    hasEnergies ? Type::Energy : Type::Rmsd);

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
  const int index = m_xAxisCombo->findData(
    quantityIdentity(Core::ConformerQuantity(coordinate)), IdentityRole);
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
    return -1;

  bool ok = false;
  const int index = m_xAxisCombo->currentData().toInt(&ok);
  return ok ? index : -1;
}

int PlotConformer::yQuantity() const
{
  if (!m_yAxisCombo)
    return -1;

  bool ok = false;
  const int index = m_yAxisCombo->currentData().toInt(&ok);
  return ok ? index : -1;
}

const Core::ConformerQuantity* PlotConformer::quantityAt(int index) const
{
  if (index < 0 || index >= static_cast<int>(m_quantities.size()))
    return nullptr;
  return &m_quantities[static_cast<size_t>(index)];
}

bool PlotConformer::isTorsionQuantity(int index) const
{
  const Core::ConformerQuantity* quantity = quantityAt(index);
  if (!quantity ||
      quantity->type() != Core::ConformerQuantity::Type::Coordinate)
    return false;

  return quantity->coordinate().type() == Core::Constraint::TorsionConstraint;
}

bool PlotConformer::isDynamicsQuantity(const Core::ConformerQuantity& quantity)
{
  using Type = Core::ConformerQuantity::Type;
  switch (quantity.type()) {
    case Type::Time:
    case Type::MeanSpeed:
    case Type::Temperature:
      return true;
    default:
      return false;
  }
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

    // Energy conversion, reading as a sentence: "Energy Units: Hartree to
    // kcal/mol". The pair is application-wide, so this is the same setting
    // the conformer property table's "Convert Energy Units…" edits.
    QHBoxLayout* conversionLayout = new QHBoxLayout();
    QLabel* conversionLabel = new QLabel(tr("Energy Units:"), m_dialog.get());
    m_unitsCombo = new QComboBox(m_dialog.get());
    QLabel* targetLabel = new QLabel(tr("to"), m_dialog.get());
    m_targetUnitsCombo = new QComboBox(m_dialog.get());
    syncUnitCombos();

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
    // The combos write the shared setting rather than keeping one of their
    // own; the signal below is what brings the plot back round, and it
    // reaches the property table at the same time.
    const auto unitsEdited = [this]() {
      auto* units = EnergyUnits::instance();
      // Where the file said what its units are, the source combo is only
      // reporting that -- it must not write it back as the user's answer for
      // every other file.
      const bool declared =
        m_molecule && EnergyUnits::declaresUnit(*m_molecule);
      units->setUnits(declared
                        ? units->sourceUnit()
                        : unitFromCombo(m_unitsCombo, units->sourceUnit()),
                      unitFromCombo(m_targetUnitsCombo, units->displayUnit()));
    };
    connect(m_unitsCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, unitsEdited);
    connect(m_targetUnitsCombo,
            QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            unitsEdited);

    // Changed here, or from the property table, or in another window: either
    // way the combos follow it and the plot is redrawn.
    connect(EnergyUnits::instance(), &EnergyUnits::unitsChanged, this,
            [this]() {
              syncUnitCombos();
              updatePlot();
            });
    connect(m_unwrapDihedralsCheck, &QCheckBox::toggled, this,
            &PlotConformer::updatePlot);
    connect(m_timeStepSpin,
            QOverload<double>::of(&QDoubleSpinBox::valueChanged), this,
            [this](double interval) {
              if (!m_molecule)
                return;
              // Onto the molecule, so that the conformer property table reads
              // the same interval rather than its own default, and is told to
              // go and read it. Handling that change replots this too.
              Core::setFrameInterval(*m_molecule, interval);
              m_molecule->emitChanged(Molecule::Properties);
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
  syncUnitCombos();
  populateQuantityCombos();
  m_currentFrame = m_molecule->coordinate3d();
  updatePlot();
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
  m_chartWidget->setFocus();
}

std::optional<PlotConformer::QuantitySeries> PlotConformer::evaluateQuantity(
  int index)
{
  using Type = Core::ConformerQuantity::Type;

  const Core::ConformerQuantity* quantity = quantityAt(index);
  if (!m_molecule || !quantity)
    return std::nullopt;

  // Speed and temperature are read back out of the molecule's properties, so
  // they have to have been worked out first.
  if (quantity->type() == Type::MeanSpeed ||
      quantity->type() == Type::Temperature) {
    if (!ensureVelocities())
      return std::nullopt;
  }

  std::vector<double> values =
    Core::evaluateConformerQuantity(*m_molecule, *quantity);
  if (values.empty())
    return std::nullopt;

  // Energies arrive relative to the lowest set but in the file's own unit,
  // which is the one thing here only the user can name.
  QString unit;
  if (quantity->type() == Type::Energy) {
    auto* units = EnergyUnits::instance();
    for (double& value : values)
      value = units->convert(value, *m_molecule);
    unit = units->displaySymbol();
  }

  DataSeries series;
  series.reserve(values.size());
  for (double value : values)
    series.push_back(static_cast<float>(value));

  DataSeries errors;
  for (double deviation : Core::conformerQuantitySpread(*m_molecule, *quantity))
    errors.push_back(static_cast<float>(deviation));

  // An error bar per point or none at all -- a partial set would put bars on
  // the wrong frames.
  if (errors.size() != series.size())
    errors.clear();

  return QuantitySeries{ std::move(series), std::move(errors),
                         QtGui::ConformerQuantityTranslator::label(*quantity,
                                                                   unit) };
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
  const Core::ConformerQuantity* xInfo = quantityAt(xq);
  const Core::ConformerQuantity* yInfo = quantityAt(yq);

  using Type = Core::ConformerQuantity::Type;
  const auto isType = [](const Core::ConformerQuantity* info, Type type) {
    return info != nullptr && info->type() == type;
  };

  // The units only apply while one of the axes is showing energies.
  const bool plottingEnergy =
    isType(xInfo, Type::Energy) || isType(yInfo, Type::Energy);
  if (m_unitsCombo)
    m_unitsCombo->setEnabled(plottingEnergy);
  if (m_targetUnitsCombo)
    m_targetUnitsCombo->setEnabled(plottingEnergy);

  // The time step only matters while something on the plot is measured
  // against time.
  const bool plottingTime = (xInfo != nullptr && isDynamicsQuantity(*xInfo)) ||
                            (yInfo != nullptr && isDynamicsQuantity(*yInfo));
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
      isType(xInfo, Type::Frame)
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

void PlotConformer::syncUnitCombos()
{
  if (!m_unitsCombo || !m_targetUnitsCombo)
    return;

  auto* units = EnergyUnits::instance();

  // A reader that knew what its program writes has already said so, and that
  // beats anything the user last picked for some other file -- so show what
  // the file said and take the choice away rather than letting a stale
  // setting look as though it were in force.
  const bool declared = m_molecule && EnergyUnits::declaresUnit(*m_molecule);
  fillUnitCombo(m_unitsCombo, m_molecule ? units->sourceUnit(*m_molecule)
                                         : units->sourceUnit());
  m_unitsCombo->setEnabled(!declared);
  m_unitsCombo->setToolTip(
    declared ? tr("This file records the units its energies are in.")
             : tr("The units the energies in this file are in, which the file "
                  "itself does not record."));

  fillUnitCombo(m_targetUnitsCombo, units->displayUnit());
}

double PlotConformer::timeStep() const
{
  if (m_timeStepSpin)
    return m_timeStepSpin->value();
  return m_molecule ? Core::frameInterval(*m_molecule) : 1.0;
}

void PlotConformer::seedTimeStepFromMolecule()
{
  if (!m_molecule || !m_timeStepSpin || m_timeStepSeeded)
    return;

  m_timeStepSeeded = true;

  // Whatever the molecule already goes by -- what the user set last time, or
  // the spacing the file recorded, or one picosecond. Nothing is written back
  // here: the molecule only takes a value the user actually chose.
  const double interval = Core::frameInterval(*m_molecule);
  if (interval >= m_timeStepSpin->minimum() &&
      interval <= m_timeStepSpin->maximum()) {
    QSignalBlocker blocker(m_timeStepSpin);
    m_timeStepSpin->setValue(interval);
  }
}

bool PlotConformer::ensureVelocities()
{
  if (!m_molecule)
    return false;

  // Core decides whether anything actually needs redoing -- the conformer
  // property table asks the same question, and the two must not answer it
  // differently. m_staleVelocities carries the one thing Core cannot see:
  // that the atoms moved without the trajectory changing length.
  const bool refreshed =
    Core::ensureConformerVelocities(*m_molecule, m_staleVelocities);
  m_staleVelocities = false;
  return refreshed;
}

} // namespace Avogadro::QtPlugins
