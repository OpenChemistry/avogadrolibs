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
#include <QString>

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/vtk/vtkplot.h>

#include "pdfoptionsdialog.h"
#include "plotpdf.h"

using Avogadro::Core::CrystalTools;
using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

using std::map;

namespace Avogadro {
namespace QtPlugins {

using Core::Array;

PlotPdf::PlotPdf(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_)
  , m_actions(QList<QAction*>())
  , m_molecule(nullptr)
  , m_pdfOptionsDialog(new PdfOptionsDialog(qobject_cast<QWidget*>(parent())))
  , m_displayDialogAction(new QAction(this))
{
  m_displayDialogAction->setText(tr("Plot Pair Distribution Function..."));
  connect(m_displayDialogAction.data(), &QAction::triggered, this,
          &PlotPdf::displayDialog);
  m_actions.push_back(m_displayDialogAction.data());
  m_displayDialogAction->setProperty("menu priority", 70);

  updateActions();
}

PlotPdf::~PlotPdf() = default;

QList<QAction*> PlotPdf::actions() const
{
  return m_actions;
}

QStringList PlotPdf::menuPath(QAction*) const
{
  return QStringList() << tr("&Crystal");
}

void PlotPdf::setMolecule(QtGui::Molecule* mol)
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

void PlotPdf::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void PlotPdf::updateActions()
{
  // Disable everything for nullptr molecules.
  if (!m_molecule) {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
    return;
  }

  // Only display the actions if there is a unit cell
  if (m_molecule->unitCell()) {
    foreach (QAction* action, m_actions)
      action->setEnabled(true);
  } else {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
  }
}

void PlotPdf::displayDialog()
{
  // Do nothing if the user cancels
  if (m_pdfOptionsDialog->exec() != QDialog::Accepted)
    return;

  // Otherwise, fetch the options and perform the run
  double maxRadius = m_pdfOptionsDialog->maxRadius();
  double step = m_pdfOptionsDialog->step();
  // size_t numpoints = m_pdfOptionsDialog->numDataPoints();
  // double max2theta = m_pdfOptionsDialog->max2Theta();

  PdfData results;
  QString err;
  if (!generatePdfPattern(*m_molecule, results, err, maxRadius, step)) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Failed to generate PDF pattern"),
                          tr("Error message: ") + err);
    return;
  }

  // Now generate a plot with the data
  std::vector<double> xData;
  std::vector<double> yData;
  for (const auto& item : results) {
    xData.push_back(item.first);
    yData.push_back(item.second);
  }
  std::vector<std::vector<double>> data{ xData, yData };

  std::vector<std::string> lineLabels{ "PdfData" };

  std::array<double, 4> color = { 255, 0, 0, 255 };
  std::vector<std::array<double, 4>> lineColors{ color };

  const char* xTitle = "r (Å)";
  const char* yTitle = "g(r)";
  const char* windowName = "Pair Distribution Function";

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

bool PlotPdf::generatePdfPattern(QtGui::Molecule& mol, PdfData& results,
                                 QString& err, double maxRadius, double step)
{
  Array<Vector3> refAtomCoords = mol.atomPositions3d();

  size_t i, j;

  UnitCell* uc = mol.unitCell();
  if (!uc) {
    err = "No unit cell found.";
    return false;
  }

  size_t a = static_cast<size_t>(maxRadius / uc->a()) + 1;
  size_t b = static_cast<size_t>(maxRadius / uc->b()) + 1;
  size_t c = static_cast<size_t>(maxRadius / uc->c()) + 1;

  Vector3 disp = a * uc->aVector() + b * uc->bVector() + c * uc->cVector();
  for (i = 0; i < refAtomCoords.size(); ++i) {
    refAtomCoords[i] += disp;
  }

  Molecule newMolecule = mol;
  CrystalTools::buildSupercell(newMolecule, 2 * a + 1, 2 * b + 1, 2 * c + 1);

  Array<Vector3> newAtomCoords = newMolecule.atomPositions3d();

  map<size_t, size_t> pdfCount;
  double dist, rStep = step;
  size_t k, binIdx;

  for (i = 0; i < refAtomCoords.size(); ++i) {
    for (j = 0; j < newAtomCoords.size(); ++j) {
      dist = (refAtomCoords.at(i) - newAtomCoords.at(j)).norm();
      binIdx = static_cast<size_t>(dist / rStep);
      if (pdfCount.find(binIdx) == pdfCount.end()) {
        pdfCount.insert(std::make_pair(binIdx, 1));
      } else {
        pdfCount[binIdx]++;
      }
    }
  }

  for (k = 0; k < static_cast<size_t>(maxRadius / rStep); k++) {
    if (pdfCount.find(k) == pdfCount.end()) {
      results.push_back(std::make_pair(k * rStep, 0.0));
    } else {
      results.push_back(std::make_pair(
        k * rStep, pdfCount[k] * newMolecule.unitCell()->volume() /
                     (4 * M_PI * pow(k * rStep, 2) * rStep *
                      refAtomCoords.size() * newAtomCoords.size())));
    }
  }

  return true;
}

} // namespace QtPlugins
} // namespace Avogadro
