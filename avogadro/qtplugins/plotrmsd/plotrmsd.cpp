/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <QAction>
#include <QDialog>
#include <QMessageBox>
#include <QProcess>
#include <QString>

#include <avogadro/core/array.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/vtk/vtkplot.h>

#include "plotrmsd.h"

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

using Core::Array;

PlotRmsd::PlotRmsd(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_)
  , m_actions(QList<QAction*>())
  , m_molecule(nullptr)
  , m_displayDialogAction(new QAction(this))
{
  m_displayDialogAction->setText(tr("Plot RMSD curve..."));
  connect(m_displayDialogAction.get(), &QAction::triggered, this,
          &PlotRmsd::displayDialog);
  m_actions.push_back(m_displayDialogAction.get());
  m_displayDialogAction->setProperty("menu priority", 80);

  updateActions();
}

PlotRmsd::~PlotRmsd() = default;

QList<QAction*> PlotRmsd::actions() const
{
  return m_actions;
}

QStringList PlotRmsd::menuPath(QAction*) const
{
  return QStringList() << tr("&Crystal");
}

void PlotRmsd::setMolecule(QtGui::Molecule* mol)
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

void PlotRmsd::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void PlotRmsd::updateActions()
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

void PlotRmsd::displayDialog()
{
  RmsdData results;
  generateRmsdPattern(results);

  // Now generate a plot with the data
  std::vector<double> xData;
  std::vector<double> yData;
  for (const auto& item : results) {
    xData.push_back(item.first);
    yData.push_back(item.second);
  }
  std::vector<std::vector<double>> data{ xData, yData };

  std::vector<std::string> lineLabels{ "RmsdData" };

  std::array<double, 4> color = { 255, 0, 0, 255 };
  std::vector<std::array<double, 4>> lineColors{ color };

  const char* xTitle = "Frame";
  const char* yTitle = "RMSD (Angstrom)";
  const char* windowName = "RMSD Curve";

  if (!m_plot)
    m_plot.reset(new VTK::VtkPlot);

  m_plot->setData(data);
  m_plot->setWindowName(windowName);
  m_plot->setXTitle(xTitle);
  m_plot->setYTitle(yTitle);
  m_plot->setLineLabels(lineLabels);
  m_plot->setLineColors(lineColors);
  m_plot->show();
}

void PlotRmsd::generateRmsdPattern(RmsdData& results)
{
  m_molecule->setCoordinate3d(0);
  Array<Vector3> ref = m_molecule->atomPositions3d();

  for (size_t i = 0; i < m_molecule->coordinate3dCount(); ++i) {
    m_molecule->setCoordinate3d(i);
    Array<Vector3> positions = m_molecule->atomPositions3d();
    double sum = 0;
    for (size_t j = 0; j < positions.size(); ++j) {
      sum += (positions[j][0] - ref[j][0]) * (positions[j][0] - ref[j][0]) +
             (positions[j][1] - ref[j][1]) * (positions[j][1] - ref[j][1]) +
             (positions[j][2] - ref[j][2]) * (positions[j][2] - ref[j][2]);
    }
    sum = sqrt(sum / m_molecule->coordinate3dCount());
    results.push_back(std::make_pair(static_cast<double>(i), sum));
  }
}

} // namespace QtPlugins
} // namespace Avogadro
