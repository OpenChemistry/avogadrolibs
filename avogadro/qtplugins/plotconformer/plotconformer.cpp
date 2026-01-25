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
#include <QComboBox>
#include <QLineEdit>

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

  if (changes & Molecule::Added || changes & Molecule::Removed)
    updateActions();
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
  // switch to the closest conformer to x
  int conformer = static_cast<int>(x);
  if (conformer < 0)
    conformer = 0;
  if (conformer >= m_molecule->coordinate3dCount())
    conformer = m_molecule->coordinate3dCount() - 1;
  m_molecule->setCoordinate3d(conformer);
  m_molecule->emitChanged(Molecule::Atoms);
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

    // Create energy conversion layout
    QHBoxLayout* conversionLayout = new QHBoxLayout();
    QLabel* conversionLabel = new QLabel(tr("Energy Units:"), m_dialog.get());
    m_unitsCombo = new QComboBox(m_dialog.get());
    m_unitsCombo->addItem(tr("Hartree"), HartreeToKcal);
    m_unitsCombo->addItem(tr("eV"), EvToKcal);
    m_unitsCombo->addItem(tr("kcal/mol"), 1.0);
    m_unitsCombo->addItem(tr("kJ/mol"), KcalToKJ);
    if (!hasEnergies)
      m_unitsCombo->setEnabled(false);

    QLabel* targetLabel = new QLabel(tr("to"), m_dialog.get());
    m_targetUnitsCombo = new QComboBox(m_dialog.get());
    m_targetUnitsCombo->addItem(tr("kcal/mol"), 1.0);
    m_targetUnitsCombo->addItem(tr("kJ/mol"), KcalToKJ);
    m_targetUnitsCombo->addItem(tr("eV"), 1.0 / EvToKcal);
    m_targetUnitsCombo->addItem(tr("Hartree"), 1.0 / HartreeToKcal);
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
  }

  updatePlot();
  m_dialog->show();
}

void PlotConformer::updatePlot()
{
  if (!m_molecule || !m_chartWidget)
    return;

  DataSeries xData, yData;

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

  // Now generate a plot with the data
  float min = *std::min_element(yData.begin(), yData.end());
  float max = *std::max_element(yData.begin(), yData.end());

  const char* xTitle = "Frame";
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
  // make sure to pad the axes slightly
  m_chartWidget->setXAxisLimits(
    -0.1, static_cast<float>(m_molecule->coordinate3dCount()) - 0.9);
  m_chartWidget->setYAxisLimits(min, max * 1.1f);
  m_chartWidget->setXAxisTitle(xTitle);
  m_chartWidget->setYAxisTitle(yTitle);
}

void PlotConformer::generateRmsdCurve(DataSeries& x, DataSeries& y)
{
  if (!m_molecule)
    return;

  m_molecule->setCoordinate3d(0);
  Array<Vector3> ref = m_molecule->atomPositions3d();

  for (int i = 0; i < m_molecule->coordinate3dCount(); ++i) {
    m_molecule->setCoordinate3d(i);
    Array<Vector3> positions = m_molecule->atomPositions3d();
    double sum = 0;
    for (size_t j = 0; j < positions.size(); ++j) {
      sum += (positions[j][0] - ref[j][0]) * (positions[j][0] - ref[j][0]) +
             (positions[j][1] - ref[j][1]) * (positions[j][1] - ref[j][1]) +
             (positions[j][2] - ref[j][2]) * (positions[j][2] - ref[j][2]);
    }
    sum = sqrt(sum / m_molecule->coordinate3dCount());
    x.push_back(i);
    y.push_back(sum);
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
