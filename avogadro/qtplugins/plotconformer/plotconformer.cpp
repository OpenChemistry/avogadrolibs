/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plotconformer.h"

#include <QAction>
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

#include <avogadro/core/array.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/chartdialog.h>
#include <avogadro/qtgui/chartwidget.h>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

constexpr double HartreeToKcal = 627.5094740631;
constexpr double EvToKcal = 23.06054;
constexpr double KcalToKJ = 4.184; // by definition

using Core::Array;

PlotConformer::PlotConformer(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_displayDialogAction(new QAction(this)),
    m_chartWidget(nullptr), m_propertyCombo(nullptr), m_unitsCombo(nullptr),
    m_targetUnitsCombo(nullptr), m_frameLabel(nullptr)
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

  if (structural) {
    // Atoms, coordinate sets or energies may all have changed under us.
    m_currentFrame = m_molecule->coordinate3d();
    populatePropertyCombo();
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
  setFrame(static_cast<int>(std::lround(x)));
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

    // Key presses that the chart and buttons ignore bubble up to the dialog,
    // where the filter turns them into conformer navigation. Filtering here
    // rather than with shortcuts leaves the combo boxes' own arrow handling
    // intact.
    m_dialog->installEventFilter(this);
  }

  populatePropertyCombo();
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
  m_chartWidget->setXAxisLimits(-0.1f, static_cast<float>(count) - 0.9f);
  m_chartWidget->setYAxisLimits(min - pad, max + pad);
  m_chartWidget->setXAxisTitle(tr("Frame"));
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
