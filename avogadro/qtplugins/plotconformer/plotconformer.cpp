/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plotconformer.h"

#include <QAction>
#include <QMessageBox>
#include <QProcess>
#include <QString>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>

#include <avogadro/core/array.h>
#include <avogadro/core/angletools.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/chartdialog.h>
#include <avogadro/qtgui/chartwidget.h>
#include <avogadro/qtgui/molecule.h>
#include <cmath>
#include <limits>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

constexpr double HartreeToKcal = 627.5094740631;
constexpr double EvToKcal = 23.06054;
constexpr double KcalToKJ = 4.184; // by definition

using Core::Array;

static QString constraintLabel(const Core::Constraint& c)
{
  const int a = static_cast<int>(c.aIndex()) + 1;
  const int b = static_cast<int>(c.bIndex()) + 1;
  const int cc = static_cast<int>(c.cIndex()) + 1;
  const int d = static_cast<int>(c.dIndex()) + 1;

  switch (c.type()) {
    case Core::Constraint::DistanceConstraint:
      return QObject::tr("Distance %1-%2").arg(a).arg(b);
    case Core::Constraint::AngleConstraint:
      return QObject::tr("Angle %1-%2-%3").arg(a).arg(b).arg(cc);
    case Core::Constraint::TorsionConstraint:
      return QObject::tr("Dihedral %1-%2-%3-%4").arg(a).arg(b).arg(cc).arg(d);
    default:
      return QObject::tr("Constraint");
  }
}

static float constraintValue(QtGui::Molecule& mol, const Core::Constraint& c)
{
  const Vector3 a = mol.atomPosition3d(c.aIndex());
  const Vector3 b = mol.atomPosition3d(c.bIndex());

  switch (c.type()) {
    case Core::Constraint::DistanceConstraint:
      return static_cast<float>((a - b).norm());
    case Core::Constraint::AngleConstraint:
      return static_cast<float>(calculateAngle(a, b, mol.atomPosition3d(c.cIndex())));
    case Core::Constraint::TorsionConstraint:
      return static_cast<float>(calculateDihedral(
        a, b, mol.atomPosition3d(c.cIndex()), mol.atomPosition3d(c.dIndex())));
    default:
      return 0.0f;
  }
}

static QString xAxisTitleForConstraint(const Core::Constraint& c)
{
  switch (c.type()) {
    case Core::Constraint::DistanceConstraint:
      return QObject::tr("Bond length (Å)");
    case Core::Constraint::AngleConstraint:
      return QObject::tr("Angle (°)");
    case Core::Constraint::TorsionConstraint:
      return QObject::tr("Dihedral (°)");
    default:
      return QObject::tr("Frame");
  }
}

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

int PlotConformer::currentConformerIndex() const
{
  if (!m_molecule || m_molecule->coordinate3dCount() == 0)
    return -1;

  const Array<Vector3>& current = m_molecule->atomPositions3d();
  if (current.empty())
    return -1;

  constexpr double tolerance = 1.0e-10;
  int bestIndex = -1;
  double bestDistance = std::numeric_limits<double>::max();

  for (int i = 0; i < static_cast<int>(m_molecule->coordinate3dCount()); ++i) {
    const Array<Vector3> coords = m_molecule->coordinate3d(i);
    if (coords.size() != current.size())
      continue;

    double sum = 0.0;
    bool exactMatch = true;
    for (size_t j = 0; j < current.size(); ++j) {
      const double distance = (coords[j] - current[j]).squaredNorm();
      sum += distance;
      if (distance > tolerance)
        exactMatch = false;
    }

    if (exactMatch)
      return i;

    if (sum < bestDistance) {
      bestDistance = sum;
      bestIndex = i;
    }
  }

  return bestIndex;
}

void PlotConformer::updateXAxisOptions()
{
  if (!m_xAxisCombo)
    return;

  const QVariant currentData = m_xAxisCombo->currentData();

  m_xAxisCombo->blockSignals(true);
  m_xAxisCombo->clear();
  m_xAxisCombo->addItem(tr("Frame"), -1);

  if (m_molecule) {
    const auto& constraints = m_molecule->constraints();
    for (int i = 0; i < static_cast<int>(constraints.size()); ++i) {
      const auto& c = constraints[static_cast<size_t>(i)];
      if (c.type() == Core::Constraint::DistanceConstraint ||
          c.type() == Core::Constraint::AngleConstraint ||
          c.type() == Core::Constraint::TorsionConstraint) {
        m_xAxisCombo->addItem(constraintLabel(c), i);
      }
    }
  }

  int index = m_xAxisCombo->findData(currentData);
  if (index < 0)
    index = 0;
  m_xAxisCombo->setCurrentIndex(index);
  m_xAxisCombo->blockSignals(false);
}

PlotConformer::PlotConformer(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_displayDialogAction(new QAction(this))
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

  updateActions();
}

void PlotConformer::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  auto changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::Added || changes & Molecule::Removed ||
      changes & Molecule::Modified)
    updateActions();

  if (m_dialog &&
      (changes & Molecule::Atoms || changes & Molecule::Constraints ||
       changes & Molecule::Properties)) {
    if (changes & Molecule::Constraints)
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

void PlotConformer::clicked(float x, float y, Qt::KeyboardModifiers modifiers)
{
//  // switch to the closest conformer to x
//  int conformer = static_cast<int>(x);
//  if (conformer < 0)
//    conformer = 0;
//  if (conformer >= m_molecule->coordinate3dCount())
//    conformer = m_molecule->coordinate3dCount() - 1;
//  m_molecule->setCoordinate3d(conformer);
//  m_molecule->emitChanged(Molecule::Atoms);
  if (!m_molecule)
    return;
  
  const int xMode = (m_xAxisCombo ? m_xAxisCombo->currentData().toInt() : -1);
  
  int conformer = 0;
  if (xMode < 0) {
    conformer = static_cast<int>(x);
  } else if (!m_lastXData.empty()) {
    float best = std::numeric_limits<float>::max();
    for (int i = 0; i < static_cast<int>(m_lastXData.size()); ++i) {
      const float d = std::fabs(m_lastXData[static_cast<size_t>(i)] - x);
      if (d < best) {
        best = d;
        conformer = i;
      }
    }
  }
  
  if (conformer < 0)
    conformer = 0;
  const int maxIdx = static_cast<int>(m_molecule->coordinate3dCount()) - 1;
  if (conformer > maxIdx)
    conformer = maxIdx;
  
  m_molecule->setCoordinate3d(conformer);
  m_molecule->emitChanged(Molecule::Atoms);
  updatePlot();
}

void PlotConformer::displayDialog()
{
  bool hasEnergies = (m_molecule->hasData("energies"));
  // RMSD forces for each coordinate set
  bool hasForces = (m_molecule->hasData("forces"));
  // and velocities for MD
  bool hasVelocities = (m_molecule->hasData("velocities"));

  if (!m_dialog) {
    // Create the dialog
    m_dialog.reset(new QDialog(qobject_cast<QWidget*>(this->parent())));
    m_dialog->setWindowTitle(tr("Conformer Analysis"));
    m_dialog->resize(600, 500);

    // Create main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(m_dialog.get());

    // Create chart widget
    m_chartWidget = new QtGui::ChartWidget(m_dialog.get());
    connect(m_chartWidget, &QtGui::ChartWidget::clicked, this,
            &PlotConformer::clicked);
    mainLayout->addWidget(m_chartWidget);

    // Create property selection layout
    QHBoxLayout* propertyLayout = new QHBoxLayout();
    QLabel* propertyLabel = new QLabel(tr("Plot Type:"), m_dialog.get());
    m_propertyCombo = new QComboBox(m_dialog.get());
    m_propertyCombo->addItem(tr("RMSD"), "rmsd");
    if (hasEnergies)
      m_propertyCombo->addItem(tr("Energy"), "energy");
    if (hasForces)
      m_propertyCombo->addItem(tr("Forces"), "forces");
    if (hasVelocities)
      m_propertyCombo->addItem(tr("Velocities"), "velocities");

    propertyLayout->addWidget(propertyLabel);
    propertyLayout->addWidget(m_propertyCombo);
    propertyLayout->addStretch();
    mainLayout->addLayout(propertyLayout);

    // X axis selection (Frame or constraint coordinate)
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
    if (!hasEnergies)
      m_unitsCombo->setEnabled(false);

    QLabel* targetLabel = new QLabel(tr("to"), m_dialog.get());
    m_targetUnitsCombo = new QComboBox(m_dialog.get());
    m_targetUnitsCombo->addItem(QStringLiteral("kcal/mol"), 1.0);
    m_targetUnitsCombo->addItem(QStringLiteral("kJ/mol"), KcalToKJ);
    m_targetUnitsCombo->addItem(QStringLiteral("eV"), 1.0 / EvToKcal);
    m_targetUnitsCombo->addItem(QStringLiteral("Hartree"), 1.0 / HartreeToKcal);
    if (!hasEnergies)
      m_targetUnitsCombo->setEnabled(false);

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
  }

  updateXAxisOptions();
  updatePlot();
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void PlotConformer::updatePlot()
{
  if (!m_molecule || !m_chartWidget)
    return;

  DataSeries xData, yData;
  const Array<Vector3> originalPositions = m_molecule->atomPositions3d();
  const int currentIndex = currentConformerIndex();
  const int xMode = (m_xAxisCombo ? m_xAxisCombo->currentData().toInt() : -1);

  QString plotType = m_propertyCombo->currentData().toString();

  if (plotType == "rmsd") {
    generateRmsdCurve(xData, yData);
  } else if (plotType == "energy" && m_molecule->hasData("energies")) {
    generateEnergyCurve(xData, yData);
  } else if (plotType == "forces" && m_molecule->hasData("forces")) {
    generateForcesCurve(xData, yData);
  } else if (plotType == "velocities" && m_molecule->hasData("velocities")) {
    generateVelocitiesCurve(xData, yData);
  }

  if (xData.empty() || yData.empty())
    return;

  bool isDihedralConstraint = false;
  if (xMode >= 0) {
    const auto& constraints = m_molecule->constraints();
    if (xMode < static_cast<int>(constraints.size()) &&
        constraints[static_cast<size_t>(xMode)].type() ==
          Core::Constraint::TorsionConstraint) {
      isDihedralConstraint = true;
      if (m_unwrapDihedralsCheck && m_unwrapDihedralsCheck->isChecked()) {
        unwrapPeriodicSeries(xData, 360.0f);
        shiftSeriesToPreferredWindow(xData, 360.0f, -180.0f, 180.0f);
      }
    }
  }

  if (m_unwrapDihedralsCheck)
    m_unwrapDihedralsCheck->setEnabled(isDihedralConstraint);

  m_molecule->setAtomPositions3d(originalPositions);
  m_lastXData = xData;

  // Now generate a plot with the data
  float min = *std::min_element(yData.begin(), yData.end());
  float max = *std::max_element(yData.begin(), yData.end());

  QString xTitle = tr("Frame");
  if (xMode >= 0) {
    const auto& constraints = m_molecule->constraints();
    if (xMode < static_cast<int>(constraints.size()))
      xTitle = xAxisTitleForConstraint(constraints[static_cast<size_t>(xMode)]);
  }
  QString yTitle;

  if (plotType == "rmsd") {
    yTitle = tr("RMSD (Å)");
  } else if (plotType == "energy" && m_molecule->hasData("energies")) {
    QString targetUnit = m_targetUnitsCombo->currentText();
    yTitle = tr("Relative Energy (%1)").arg(targetUnit);
  } else if (plotType == "forces" && m_molecule->hasData("forces")) {
    // TODO: Add units
    yTitle = tr("Forces (N)");
  } else if (plotType == "velocities" && m_molecule->hasData("velocities")) {
    yTitle = tr("Velocities (m/s)");
  }

  m_chartWidget->clearPlots();
  m_chartWidget->setShowPoints(true);
  m_chartWidget->setLegendLocation(QtGui::ChartWidget::LegendLocation::None);
  m_chartWidget->addPlot(xData, yData, QtGui::color4ub{ 255, 0, 0, 255 });
  if (currentIndex >= 0 && currentIndex < static_cast<int>(xData.size()) &&
      currentIndex < static_cast<int>(yData.size())) {
    DataSeries highlightX{ xData[static_cast<size_t>(currentIndex)] };
    DataSeries highlightY{ yData[static_cast<size_t>(currentIndex)] };
    m_chartWidget->addPlot(highlightX, highlightY,
                           QtGui::color4ub{ 0, 102, 204, 255 });
  }
  // make sure to pad the axes slightly
  m_chartWidget->setXAxisLimits(
    -0.1, static_cast<float>(m_molecule->coordinate3dCount()) - 0.9);
  m_chartWidget->setYAxisLimits(min, max * 1.1f);
  if (xMode < 0) {
    m_chartWidget->setXAxisLimits(
      -0.1f, static_cast<float>(m_molecule->coordinate3dCount()) - 0.9f);
  } else {
    const float xmin = *std::min_element(xData.begin(), xData.end());
    const float xmax = *std::max_element(xData.begin(), xData.end());
    const float pad = std::max(1e-3f, (xmax - xmin) * 0.02f);
    m_chartWidget->setXAxisLimits(xmin - pad, xmax + pad);
  }
  m_chartWidget->setXAxisTitle(xTitle);
  m_chartWidget->setYAxisTitle(yTitle);
}

void PlotConformer::generateRmsdCurve(DataSeries& x, DataSeries& y)
{
  if (!m_molecule)
    return;

  const Array<Vector3> ref = m_molecule->coordinate3d(0);
  const Array<Vector3> originalPositions = m_molecule->atomPositions3d();
  const int xMode = (m_xAxisCombo ? m_xAxisCombo->currentData().toInt() : -1);
  const auto& constraints = m_molecule->constraints();

  for (int i = 0; i < m_molecule->coordinate3dCount(); ++i) {
    const Array<Vector3> positions = m_molecule->coordinate3d(i);
    double sum = 0;
    for (size_t j = 0; j < positions.size(); ++j) {
      sum += (positions[j][0] - ref[j][0]) * (positions[j][0] - ref[j][0]) +
             (positions[j][1] - ref[j][1]) * (positions[j][1] - ref[j][1]) +
             (positions[j][2] - ref[j][2]) * (positions[j][2] - ref[j][2]);
    }
    sum = sqrt(sum / m_molecule->coordinate3dCount());

    float xVal = static_cast<float>(i);
    if (xMode >= 0 && xMode < static_cast<int>(constraints.size())) {
      m_molecule->setCoordinate3d(i);
      xVal = constraintValue(*m_molecule, constraints[static_cast<size_t>(xMode)]);
    }

    x.push_back(xVal);
    y.push_back(sum);
  }

  m_molecule->setAtomPositions3d(originalPositions);
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

    float xVal = static_cast<float>(entry); // default: frame
    const int xMode = (m_xAxisCombo ? m_xAxisCombo->currentData().toInt() : -1);
    const auto& constraints = m_molecule->constraints();
    if (xMode >= 0 && xMode < static_cast<int>(constraints.size())) {
      const Array<Vector3> originalPositions = m_molecule->atomPositions3d();
      m_molecule->setCoordinate3d(entry);
      xVal = constraintValue(*m_molecule, constraints[static_cast<size_t>(xMode)]);
      m_molecule->setAtomPositions3d(originalPositions);
    }

    x.push_back(xVal);
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
