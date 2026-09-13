/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plotconformer.h"

#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
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
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/chartdialog.h>
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

// Both axes offer the same quantities, so fill them from one list. Keeping the
// current selection matters here: the combos are rebuilt whenever a constraint
// is added, which should not throw away what the user was looking at.
static void fillQuantityCombo(
  QComboBox* combo, const std::vector<std::pair<QString, int>>& quantities,
  int fallback)
{
  if (combo == nullptr)
    return;

  const QVariant current = combo->currentData();

  QSignalBlocker blocker(combo);
  combo->clear();
  for (const auto& quantity : quantities)
    combo->addItem(quantity.first, quantity.second);

  int index = combo->findData(current);
  if (index < 0)
    index = combo->findData(fallback);
  combo->setCurrentIndex(index < 0 ? 0 : index);
}

PlotConformer::PlotConformer(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_displayDialogAction(new QAction(this)),
    m_chartWidget(nullptr), m_yAxisCombo(nullptr), m_xAxisCombo(nullptr),
    m_unitsCombo(nullptr), m_targetUnitsCombo(nullptr),
    m_unwrapDihedralsCheck(nullptr), m_frameLabel(nullptr),
    m_xTitle(tr("Frame"))
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
  const bool structural = (changes & Molecule::Added) ||
                          (changes & Molecule::Removed) ||
                          (changes & Molecule::Modified);
  if (structural)
    updateActions();

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

  if (structural || constraintChange) {
    // Atoms, coordinate sets, energies or constraints may all have changed
    // under us, and deleting atoms can invalidate the coordinate currently
    // driving an axis.
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

void PlotConformer::populateQuantityCombos()
{
  if (!m_molecule || !m_xAxisCombo || !m_yAxisCombo)
    return;

  const bool hasEnergies = m_molecule->hasData("energies");
  const bool hasForces = m_molecule->hasData("forces");
  const bool hasVelocities = m_molecule->hasData("velocities");

  std::vector<std::pair<QString, int>> quantities;
  quantities.emplace_back(tr("Frame"), FrameQuantity);
  quantities.emplace_back(tr("RMSD"), RmsdQuantity);
  if (hasEnergies)
    quantities.emplace_back(tr("Energy"), EnergyQuantity);
  if (hasForces)
    quantities.emplace_back(tr("Forces"), ForcesQuantity);
  if (hasVelocities)
    quantities.emplace_back(tr("Velocities"), VelocitiesQuantity);

  // One entry per constraint, so a scanned coordinate can go on either axis.
  const auto& constraints = m_molecule->constraints();
  for (int i = 0; i < static_cast<int>(constraints.size()); ++i) {
    const auto& c = constraints[static_cast<size_t>(i)];
    // Out-of-plane constraints have no single value to scan, and one left
    // over from deleted atoms would plot zeros.
    if (c.isValid(m_molecule->atomCount()))
      quantities.emplace_back(constraintLabel(c), i);
  }

  fillQuantityCombo(m_xAxisCombo, quantities, FrameQuantity);
  fillQuantityCombo(m_yAxisCombo, quantities,
                    hasEnergies ? EnergyQuantity : RmsdQuantity);

  // updatePlot() runs after every call to this, and owns the unit combos.
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
  if (!m_molecule || quantity < 0)
    return false;

  const auto& constraints = m_molecule->constraints();
  if (quantity >= static_cast<int>(constraints.size()))
    return false;

  return constraints[static_cast<size_t>(quantity)].type() ==
         Core::Constraint::TorsionConstraint;
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

    // Key presses that the chart and buttons ignore bubble up to the dialog,
    // where the filter turns them into conformer navigation. Filtering here
    // rather than with shortcuts leaves the combo boxes' own arrow handling
    // intact.
    m_dialog->installEventFilter(this);
  }

  populateQuantityCombos();
  m_currentFrame = m_molecule->coordinate3d();
  updatePlot();
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
  m_chartWidget->setFocus();
}

bool PlotConformer::evaluateQuantity(int quantity, DataSeries& values,
                                     QString& title)
{
  if (!m_molecule)
    return false;

  values.clear();

  if (quantity >= 0) {
    const auto& constraints = m_molecule->constraints();
    if (quantity >= static_cast<int>(constraints.size()))
      return false;
    title = axisTitleForConstraint(constraints[static_cast<size_t>(quantity)]);
    return generateCoordinateSeries(quantity, values);
  }

  switch (quantity) {
    case FrameQuantity:
      title = tr("Frame");
      return generateFrameSeries(values);
    case RmsdQuantity:
      title = tr("RMSD (Å)");
      return generateRmsdSeries(values);
    case EnergyQuantity:
      title = tr("Relative Energy (%1)")
                .arg(m_targetUnitsCombo ? m_targetUnitsCombo->currentText()
                                        : QString());
      return generateEnergySeries(values);
    case ForcesQuantity:
      // TODO: Add units - data("forces") holds the RMS gradient per set
      title = tr("RMS Gradient");
      return generateForcesSeries(values);
    case VelocitiesQuantity:
      title = tr("Velocities (m/s)");
      return generateVelocitiesSeries(values);
    default:
      return false;
  }
}

void PlotConformer::updatePlot()
{
  if (!m_molecule || !m_chartWidget || !m_xAxisCombo || !m_yAxisCombo)
    return;

  m_xData.clear();
  m_yData.clear();

  const int xq = xQuantity();
  const int yq = yQuantity();

  // The units only apply while one of the axes is showing energies.
  const bool plottingEnergy = (xq == EnergyQuantity || yq == EnergyQuantity);
  if (m_unitsCombo)
    m_unitsCombo->setEnabled(plottingEnergy);
  if (m_targetUnitsCombo)
    m_targetUnitsCombo->setEnabled(plottingEnergy);

  // Nothing but a torsion wraps, so the option is meaningless otherwise.
  const bool xIsTorsion = isTorsionQuantity(xq);
  const bool yIsTorsion = isTorsionQuantity(yq);
  if (m_unwrapDihedralsCheck)
    m_unwrapDihedralsCheck->setEnabled(xIsTorsion || yIsTorsion);

  DataSeries x, y;
  QString xTitle, yTitle;
  if (!evaluateQuantity(xq, x, xTitle) || !evaluateQuantity(yq, y, yTitle)) {
    drawChart();
    return;
  }

  // A file can carry fewer energies or gradients than it has geometries, so
  // plot only the pairs that exist rather than handing the chart two series
  // of different lengths.
  const size_t points = std::min(x.size(), y.size());
  x.resize(points);
  y.resize(points);

  const bool unwrap =
    m_unwrapDihedralsCheck && m_unwrapDihedralsCheck->isChecked();
  if (unwrap && xIsTorsion) {
    unwrapPeriodicValues(x, 360.0f);
    shiftValuesToWindow(x, 360.0f, -180.0f, 180.0f);
  }
  if (unwrap && yIsTorsion) {
    unwrapPeriodicValues(y, 360.0f);
    shiftValuesToWindow(y, 360.0f, -180.0f, 180.0f);
  }

  m_xData = std::move(x);
  m_yData = std::move(y);
  m_xTitle = xTitle;
  m_yTitle = yTitle;

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

  float min = *std::min_element(m_yData.begin(), m_yData.end());
  float max = *std::max_element(m_yData.begin(), m_yData.end());
  // Pad the y axis so the extreme points are not clipped by the frame. A flat
  // curve has no range to scale, so fall back to a fixed margin.
  float pad = (max > min) ? 0.05f * (max - min) : 1.0f;

  m_chartWidget->setShowPoints(true);
  m_chartWidget->setLegendLocation(QtGui::ChartWidget::LegendLocation::None);
  m_chartWidget->addPlot(m_xData, m_yData, QtGui::color4ub{ 255, 0, 0, 255 });

  // Add a marker for the current frame
  if (m_currentFrame >= 0 &&
      m_currentFrame < static_cast<int>(m_xData.size())) {
    DataSeries markerX = { m_xData[m_currentFrame] };
    DataSeries markerY = { m_yData[m_currentFrame] };
    m_chartWidget->addPlot(markerX, markerY,
                           QtGui::color4ub{ 255, 165, 0, 255 });
  }

  // make sure to pad the axes slightly
  if (xQuantity() == FrameQuantity) {
    m_chartWidget->setXAxisLimits(-0.1f, static_cast<float>(count) - 0.9f);
  } else {
    // Everything else has no fixed range, and a scan that barely moves still
    // needs an axis wide enough to draw.
    const float xMin = *std::min_element(m_xData.begin(), m_xData.end());
    const float xMax = *std::max_element(m_xData.begin(), m_xData.end());
    const float xPad = std::max(1e-3f, (xMax - xMin) * 0.02f);
    m_chartWidget->setXAxisLimits(xMin - xPad, xMax + xPad);
  }
  m_chartWidget->setYAxisLimits(min - pad, max + pad);
  m_chartWidget->setXAxisTitle(m_xTitle);
  m_chartWidget->setYAxisTitle(m_yTitle);
}

bool PlotConformer::generateFrameSeries(DataSeries& values)
{
  if (!m_molecule)
    return false;

  const size_t count = m_molecule->coordinate3dCount();
  values.reserve(count);
  for (size_t i = 0; i < count; ++i)
    values.push_back(static_cast<float>(i));

  return !values.empty();
}

bool PlotConformer::generateCoordinateSeries(int constraintIndex,
                                             DataSeries& values)
{
  if (!m_molecule || constraintIndex < 0)
    return false;

  const auto& constraints = m_molecule->constraints();
  if (constraintIndex >= static_cast<int>(constraints.size()))
    return false;

  const Core::Constraint& constraint =
    constraints[static_cast<size_t>(constraintIndex)];

  // coordinate3d(i) returns a copy and does not change the displayed set, so
  // this reads the whole trajectory without disturbing the active conformer.
  const size_t count = m_molecule->coordinate3dCount();
  values.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    Real value = 0.0;
    if (!constraint.evaluate(m_molecule->coordinate3d(i), value))
      return false;
    values.push_back(static_cast<float>(value));
  }

  return !values.empty();
}

bool PlotConformer::generateRmsdSeries(DataSeries& values)
{
  if (!m_molecule || m_molecule->coordinate3dCount() == 0)
    return false;

  Array<Vector3> ref = m_molecule->coordinate3d(0);
  if (ref.empty())
    return false;

  for (size_t i = 0; i < m_molecule->coordinate3dCount(); ++i) {
    Array<Vector3> positions = m_molecule->coordinate3d(i);
    // Coordinate sets should all describe the same atoms, but compare only as
    // far as both of them go rather than reading off the end of the reference.
    size_t count = std::min(positions.size(), ref.size());
    if (count == 0)
      continue;

    double sum = 0.0;
    for (size_t j = 0; j < count; ++j)
      sum += (positions[j] - ref[j]).squaredNorm();

    // RMSD is the root *mean* square deviation over the atoms, so normalize by
    // the number of atoms compared -- not by the number of coordinate sets.
    values.push_back(static_cast<float>(std::sqrt(sum / count)));
  }

  return !values.empty();
}

bool PlotConformer::generateEnergySeries(DataSeries& values)
{
  // plot relative energies so get the minimum first
  if (m_molecule == nullptr || !m_molecule->hasData("energies"))
    return false;

  std::vector<double> energies = m_molecule->data("energies").toList();
  if (energies.empty())
    return false;

  // calculate the minimum
  double minEnergy = std::numeric_limits<double>::max();
  for (double e : energies)
    minEnergy = std::min(minEnergy, e);

  // Get conversion factors
  double fromFactor =
    m_unitsCombo ? m_unitsCombo->currentData().toDouble() : 1.0;
  double toFactor =
    m_targetUnitsCombo ? m_targetUnitsCombo->currentData().toDouble() : 1.0;

  // okay, now loop through to generate the curve
  values.reserve(energies.size());
  for (double energy : energies) {
    double relativeE = energy - minEnergy;
    // Convert: first to kcal/mol, then to target units
    relativeE = relativeE * fromFactor * toFactor;
    values.push_back(static_cast<float>(relativeE));
  }

  return true;
}

bool PlotConformer::generateForcesSeries(DataSeries& values)
{
  if (m_molecule == nullptr || !m_molecule->hasData("forces"))
    return false;

  std::vector<double> forces = m_molecule->data("forces").toList();
  values.reserve(forces.size());
  for (double force : forces)
    values.push_back(static_cast<float>(force));

  return !values.empty();
}

bool PlotConformer::generateVelocitiesSeries(DataSeries& values)
{
  if (m_molecule == nullptr || !m_molecule->hasData("velocities"))
    return false;

  std::vector<double> velocities = m_molecule->data("velocities").toList();
  values.reserve(velocities.size());
  for (double velocity : velocities)
    values.push_back(static_cast<float>(velocity));

  return !values.empty();
}

} // namespace Avogadro::QtPlugins
