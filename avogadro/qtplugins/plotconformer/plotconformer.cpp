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

// Constraints outlive the atoms they name: deleting an atom leaves the indices
// behind. Molecule::atomPosition3d() answers out-of-range indices with a zero
// vector rather than failing, so check before evaluating anything.
static bool constraintIsValid(const Core::Constraint& c, size_t atomCount)
{
  switch (c.type()) {
    case Core::Constraint::TorsionConstraint:
      if (c.dIndex() >= atomCount)
        return false;
      [[fallthrough]];
    case Core::Constraint::AngleConstraint:
      if (c.cIndex() >= atomCount)
        return false;
      [[fallthrough]];
    case Core::Constraint::DistanceConstraint:
      return c.aIndex() < atomCount && c.bIndex() < atomCount;
    default:
      return false;
  }
}

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

// Evaluate the constraint geometry for one coordinate set. Distances come back
// in Angstrom, angles and torsions in degrees.
static bool constraintValue(const Array<Vector3>& positions,
                            const Core::Constraint& c, float& value)
{
  if (!constraintIsValid(c, positions.size()))
    return false;

  const Vector3& a = positions[c.aIndex()];
  const Vector3& b = positions[c.bIndex()];

  switch (c.type()) {
    case Core::Constraint::DistanceConstraint:
      value = static_cast<float>((a - b).norm());
      return true;
    case Core::Constraint::AngleConstraint:
      value = static_cast<float>(calculateAngle(a, b, positions[c.cIndex()]));
      return true;
    case Core::Constraint::TorsionConstraint:
      value = static_cast<float>(
        calculateDihedral(a, b, positions[c.cIndex()], positions[c.dIndex()]));
      return true;
    default:
      return false;
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

// A scan that walks past +/-180 degrees comes back as a jump the width of the
// whole axis. Follow the shortest step between neighbours instead, so the scan
// reads as one continuous curve.
static void unwrapPeriodicSeries(DataSeries& values, float period)
{
  if (values.empty() || period <= 0.0f)
    return;

  const float halfPeriod = period * 0.5f;
  float offset = 0.0f;
  float previous = values[0];

  for (size_t i = 1; i < values.size(); ++i) {
    float current = values[i] + offset;
    const float delta = current - previous;
    if (delta > halfPeriod) {
      offset -= period;
      current -= period;
    } else if (delta < -halfPeriod) {
      offset += period;
      current += period;
    }

    values[i] = current;
    previous = current;
  }
}

// Unwrapping can leave the curve anywhere on the real line, so slide it by
// whole periods into the window that holds the most points -- the one a
// chemist expects to read off the axis.
static void shiftSeriesToPreferredWindow(DataSeries& values, float period,
                                         float minimum, float maximum)
{
  if (values.empty() || period <= 0.0f || minimum >= maximum)
    return;

  const float minShift =
    std::floor((*std::min_element(values.begin(), values.end()) - maximum) /
               period) *
    period;
  const float maxShift =
    std::ceil((*std::max_element(values.begin(), values.end()) - minimum) /
              period) *
    period;

  int bestCount = -1;
  float bestShift = 0.0f;
  float bestCenterDistance = std::numeric_limits<float>::max();
  const float preferredCenter = 0.5f * (minimum + maximum);

  for (float shift = minShift; shift <= maxShift; shift += period) {
    int count = 0;
    float centerDistance = 0.0f;
    for (float value : values) {
      const float shifted = value - shift;
      if (shifted >= minimum && shifted <= maximum) {
        ++count;
        centerDistance += std::fabs(shifted - preferredCenter);
      }
    }

    if (count > bestCount ||
        (count == bestCount && centerDistance < bestCenterDistance)) {
      bestCount = count;
      bestShift = shift;
      bestCenterDistance = centerDistance;
    }
  }

  for (float& value : values)
    value -= bestShift;
}

PlotConformer::PlotConformer(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_displayDialogAction(new QAction(this)),
    m_chartWidget(nullptr), m_propertyCombo(nullptr), m_unitsCombo(nullptr),
    m_targetUnitsCombo(nullptr), m_xAxisCombo(nullptr),
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
      populatePropertyCombo();
      updateXAxisOptions();
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
    // Atoms, coordinate sets or energies may all have changed under us.
    m_currentFrame = m_molecule->coordinate3d();
    populatePropertyCombo();
    // Constraints can be added or removed, and deleting atoms can invalidate
    // the one currently driving the x axis.
    updateXAxisOptions();
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
  if (xAxisMode() < 0) {
    setFrame(static_cast<int>(std::lround(x)));
    return;
  }

  // A geometric coordinate is not evenly spaced and need not even be
  // monotonic, so look for the frame plotted nearest the click.
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

void PlotConformer::populatePropertyCombo()
{
  if (!m_molecule || !m_propertyCombo)
    return;

  const bool hasEnergies = m_molecule->hasData("energies");
  const bool hasForces = m_molecule->hasData("forces");
  const bool hasVelocities = m_molecule->hasData("velocities");

  // Keep the current selection if the new molecule still offers it.
  const QString current = m_propertyCombo->currentData().toString();

  QSignalBlocker blocker(m_propertyCombo);
  m_propertyCombo->clear();
  m_propertyCombo->addItem(tr("RMSD"), "rmsd");
  if (hasEnergies)
    m_propertyCombo->addItem(tr("Energy"), "energy");
  if (hasForces)
    m_propertyCombo->addItem(tr("Forces"), "forces");
  if (hasVelocities)
    m_propertyCombo->addItem(tr("Velocities"), "velocities");

  int index = m_propertyCombo->findData(current);
  m_propertyCombo->setCurrentIndex(index < 0 ? 0 : index);

  if (m_unitsCombo)
    m_unitsCombo->setEnabled(hasEnergies);
  if (m_targetUnitsCombo)
    m_targetUnitsCombo->setEnabled(hasEnergies);
}

void PlotConformer::updateXAxisOptions()
{
  if (!m_xAxisCombo)
    return;

  // Keep the current coordinate selected if the molecule still has it.
  const QVariant current = m_xAxisCombo->currentData();

  QSignalBlocker blocker(m_xAxisCombo);
  m_xAxisCombo->clear();
  m_xAxisCombo->addItem(tr("Frame"), -1);

  if (m_molecule) {
    const auto& constraints = m_molecule->constraints();
    for (int i = 0; i < static_cast<int>(constraints.size()); ++i) {
      const auto& c = constraints[static_cast<size_t>(i)];
      // Out-of-plane constraints have no single value to scan, and a
      // constraint left over from deleted atoms would plot zeros.
      if (constraintIsValid(c, m_molecule->atomCount()))
        m_xAxisCombo->addItem(constraintLabel(c), i);
    }
  }

  int index = m_xAxisCombo->findData(current);
  m_xAxisCombo->setCurrentIndex(index < 0 ? 0 : index);
}

int PlotConformer::xAxisMode() const
{
  if (!m_xAxisCombo)
    return -1;

  bool ok = false;
  const int mode = m_xAxisCombo->currentData().toInt(&ok);
  return ok ? mode : -1;
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

    // Create property selection layout
    QHBoxLayout* propertyLayout = new QHBoxLayout();
    QLabel* propertyLabel = new QLabel(tr("Plot Type:"), m_dialog.get());
    m_propertyCombo = new QComboBox(m_dialog.get());

    propertyLayout->addWidget(propertyLabel);
    propertyLayout->addWidget(m_propertyCombo);
    propertyLayout->addStretch();
    mainLayout->addLayout(propertyLayout);

    // X axis selection (frame number, or a constrained coordinate so that a
    // relaxed scan plots against what was actually scanned)
    QHBoxLayout* xAxisLayout = new QHBoxLayout();
    QLabel* xAxisLabel = new QLabel(tr("X Axis:"), m_dialog.get());
    m_xAxisCombo = new QComboBox(m_dialog.get());

    xAxisLayout->addWidget(xAxisLabel);
    xAxisLayout->addWidget(m_xAxisCombo);
    xAxisLayout->addStretch();
    mainLayout->addLayout(xAxisLayout);

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
    connect(m_propertyCombo,
            QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &PlotConformer::updatePlot);
    connect(m_unitsCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PlotConformer::updatePlot);
    connect(m_targetUnitsCombo,
            QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &PlotConformer::updatePlot);
    connect(m_xAxisCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PlotConformer::updatePlot);
    connect(m_unwrapDihedralsCheck, &QCheckBox::toggled, this,
            &PlotConformer::updatePlot);

    // Key presses that the chart and buttons ignore bubble up to the dialog,
    // where the filter turns them into conformer navigation. Filtering here
    // rather than with shortcuts leaves the combo boxes' own arrow handling
    // intact.
    m_dialog->installEventFilter(this);
  }

  populatePropertyCombo();
  updateXAxisOptions();
  m_currentFrame = m_molecule->coordinate3d();
  updatePlot();
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
  m_chartWidget->setFocus();
}

void PlotConformer::updatePlot()
{
  if (!m_molecule || !m_chartWidget || !m_propertyCombo)
    return;

  m_xData.clear();
  m_yData.clear();

  QString plotType = m_propertyCombo->currentData().toString();

  if (plotType == "rmsd") {
    generateRmsdCurve(m_xData, m_yData);
    m_yTitle = tr("RMSD (Å)");
  } else if (plotType == "energy" && m_molecule->hasData("energies")) {
    generateEnergyCurve(m_xData, m_yData);
    QString targetUnit = m_targetUnitsCombo->currentText();
    m_yTitle = tr("Relative Energy (%1)").arg(targetUnit);
  } else if (plotType == "forces" && m_molecule->hasData("forces")) {
    generateForcesCurve(m_xData, m_yData);
    // TODO: Add units - data("forces") holds the RMS gradient per set
    m_yTitle = tr("RMS Gradient");
  } else if (plotType == "velocities" && m_molecule->hasData("velocities")) {
    generateVelocitiesCurve(m_xData, m_yData);
    m_yTitle = tr("Velocities (m/s)");
  }

  // The generators all count frames along x. Swapping in the geometric
  // coordinate here, once, keeps every plot type in step with the axis title.
  const Core::Constraint* coordinate = nullptr;
  const int mode = xAxisMode();
  if (mode >= 0) {
    const auto& constraints = m_molecule->constraints();
    if (mode < static_cast<int>(constraints.size()))
      coordinate = &constraints[static_cast<size_t>(mode)];
  }

  const bool isTorsion =
    coordinate != nullptr &&
    coordinate->type() == Core::Constraint::TorsionConstraint;
  // Nothing else wraps, so the option only means something for a torsion.
  if (m_unwrapDihedralsCheck)
    m_unwrapDihedralsCheck->setEnabled(isTorsion);

  m_xTitle = coordinate ? axisTitleForConstraint(*coordinate) : tr("Frame");

  if (coordinate != nullptr && !m_yData.empty()) {
    // A file can carry fewer energies or gradients than it has geometries, so
    // plot only the pairs that exist rather than handing the chart two
    // series of different lengths.
    const size_t frames =
      std::min(m_yData.size(), m_molecule->coordinate3dCount());

    m_xData.clear();
    m_xData.reserve(frames);
    for (size_t i = 0; i < frames; ++i) {
      float value = 0.0f;
      // Invalid constraints never reach the combo, so this should not fail.
      constraintValue(m_molecule->coordinate3d(i), *coordinate, value);
      m_xData.push_back(value);
    }
    m_yData.resize(frames);

    if (isTorsion && m_unwrapDihedralsCheck &&
        m_unwrapDihedralsCheck->isChecked()) {
      unwrapPeriodicSeries(m_xData, 360.0f);
      shiftSeriesToPreferredWindow(m_xData, 360.0f, -180.0f, 180.0f);
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
  if (xAxisMode() < 0) {
    m_chartWidget->setXAxisLimits(-0.1f, static_cast<float>(count) - 0.9f);
  } else {
    // Scan coordinates have no fixed range, and a scan that barely moves
    // still needs an axis wide enough to draw.
    const float xMin = *std::min_element(m_xData.begin(), m_xData.end());
    const float xMax = *std::max_element(m_xData.begin(), m_xData.end());
    const float xPad = std::max(1e-3f, (xMax - xMin) * 0.02f);
    m_chartWidget->setXAxisLimits(xMin - xPad, xMax + xPad);
  }
  m_chartWidget->setYAxisLimits(min - pad, max + pad);
  m_chartWidget->setXAxisTitle(m_xTitle);
  m_chartWidget->setYAxisTitle(m_yTitle);
}

void PlotConformer::generateRmsdCurve(DataSeries& x, DataSeries& y)
{
  if (!m_molecule)
    return;

  if (m_molecule->coordinate3dCount() == 0)
    return;

  // coordinate3d(i) returns a copy and does not change the displayed set, so
  // this reads the whole trajectory without disturbing the active conformer.
  Array<Vector3> ref = m_molecule->coordinate3d(0);
  if (ref.empty())
    return;

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
    x.push_back(static_cast<float>(i));
    y.push_back(static_cast<float>(std::sqrt(sum / count)));
  }
}

void PlotConformer::generateEnergyCurve(DataSeries& x, DataSeries& y)
{
  // plot relative energies so get the minimum first
  if (m_molecule == nullptr || !m_molecule->hasData("energies")) {
    return;
  }

  std::vector<double> energies = m_molecule->data("energies").toList();
  // calculate the minimum
  double minEnergy = std::numeric_limits<double>::max();
  for (double e : energies) {
    minEnergy = std::min(minEnergy, e);
  }

  // Get conversion factors
  double fromFactor = m_unitsCombo->currentData().toDouble();
  double toFactor = m_targetUnitsCombo->currentData().toDouble();

  // okay, now loop through to generate the curve
  for (int entry = 0; entry < energies.size(); entry++) {
    double relativeE = energies[entry] - minEnergy;
    // Convert: first to kcal/mol, then to target units
    relativeE = relativeE * fromFactor * toFactor;

    x.push_back(static_cast<double>(entry));
    y.push_back(relativeE);
  }
}

void PlotConformer::generateForcesCurve(DataSeries& x, DataSeries& y)
{
  if (m_molecule == nullptr || !m_molecule->hasData("forces")) {
    return;
  }

  std::vector<double> forces = m_molecule->data("forces").toList();

  // okay, now loop through to generate the curve
  for (int entry = 0; entry < forces.size(); entry++) {
    // TODO : Add units
    x.push_back(static_cast<double>(entry));
    y.push_back(forces[entry]);
  }
}

void PlotConformer::generateVelocitiesCurve(DataSeries& x, DataSeries& y)
{
  if (m_molecule == nullptr || !m_molecule->hasData("velocities")) {
    return;
  }

  std::vector<double> velocities = m_molecule->data("velocities").toList();

  // okay, now loop through to generate the curve
  for (int entry = 0; entry < velocities.size(); entry++) {
    // TODO : Add units
    x.push_back(static_cast<double>(entry));
    y.push_back(velocities[entry]);
  }
}

} // namespace Avogadro::QtPlugins
