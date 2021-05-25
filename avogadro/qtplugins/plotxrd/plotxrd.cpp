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
#include <QByteArray>
#include <QCoreApplication>
#include <QDebug>
#include <QDialog>
#include <QFile>
#include <QMessageBox>
#include <QProcess>
#include <QString>

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/vtk/vtkplot.h>

#include "plotxrd.h"
#include "xrdoptionsdialog.h"

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

PlotXrd::PlotXrd(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr),
    m_xrdOptionsDialog(new XrdOptionsDialog(qobject_cast<QWidget*>(parent()))),
    m_displayDialogAction(new QAction(this))
{
  m_displayDialogAction->setText(tr("Plot Theoretical XRD Pattern..."));
  connect(m_displayDialogAction.get(), &QAction::triggered, this,
          &PlotXrd::displayDialog);
  m_actions.push_back(m_displayDialogAction.get());
  m_displayDialogAction->setProperty("menu priority", 90);

  updateActions();
}

PlotXrd::~PlotXrd() = default;

QList<QAction*> PlotXrd::actions() const
{
  return m_actions;
}

QStringList PlotXrd::menuPath(QAction*) const
{
  return QStringList() << tr("&Crystal");
}

void PlotXrd::setMolecule(QtGui::Molecule* mol)
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

void PlotXrd::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void PlotXrd::updateActions()
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

void PlotXrd::displayDialog()
{
  // Do nothing if the user cancels
  if (m_xrdOptionsDialog->exec() != QDialog::Accepted)
    return;

  // Otherwise, fetch the options and perform the run
  double wavelength = m_xrdOptionsDialog->wavelength();
  double peakwidth = m_xrdOptionsDialog->peakWidth();
  size_t numpoints = m_xrdOptionsDialog->numDataPoints();
  double max2theta = m_xrdOptionsDialog->max2Theta();

  XrdData results;
  QString err;
  if (!generateXrdPattern(*m_molecule, results, err, wavelength, peakwidth,
                          numpoints, max2theta)) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Failed to generate XRD pattern"),
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

  std::vector<std::string> lineLabels{ "XrdData" };

  std::array<double, 4> color = { 255, 0, 0, 255 };
  std::vector<std::array<double, 4>> lineColors{ color };

  const char* xTitle = "2 Theta";
  const char* yTitle = "Intensity";
  const char* windowName = "Theoretical XRD Pattern";

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

bool PlotXrd::generateXrdPattern(const QtGui::Molecule& mol, XrdData& results,
                                 QString& err, double wavelength,
                                 double peakwidth, size_t numpoints,
                                 double max2theta)
{
  // Get the molecule as a cif file
  std::string cifData;
  if (!Io::FileFormatManager::instance().writeString(mol, cifData, "cif")) {
    err = tr("Failed to convert molecule to CIF format.");
    qDebug() << "Error in" << __FUNCTION__ << ":" << err;
    return false;
  }

  // Now, execute genXrdPattern with the given inputs
  QStringList args;
  args << "--read-from-stdin"
       << "--wavelength=" + QString::number(wavelength)
       << "--peakwidth=" + QString::number(peakwidth)
       << "--numpoints=" + QString::number(numpoints)
       << "--max2theta=" + QString::number(max2theta);

  QByteArray output;
  if (!executeGenXrdPattern(args, cifData.c_str(), output, err)) {
    qDebug() << "Error in" << __FUNCTION__ << ":" << err;
    return false;
  }

  // Store the results
  results.clear();

  // Find the section of data in the output
  bool dataStarted = false;
  QStringList lines =
    QString(output).split(QRegExp("[\r\n]"), QString::SkipEmptyParts);
  for (const auto& line : lines) {
    if (!dataStarted && line.contains("#    2Theta/TOF    ICalc")) {
      dataStarted = true;
      continue;
    }

    if (dataStarted) {
      QStringList rowData = line.split(" ", QString::SkipEmptyParts);
      if (rowData.size() != 2) {
        err = tr("Data read from genXrdPattern appears to be corrupt!");
        qDebug() << "Error in" << __FUNCTION__ << err;
        qDebug() << "Data is:";
        for (const auto& lineTmp : lines)
          qDebug() << lineTmp;
        return false;
      }
      results.push_back(
        std::make_pair(rowData[0].toDouble(), rowData[1].toDouble()));
    }
  }

  return true;
}

bool PlotXrd::executeGenXrdPattern(const QStringList& args,
                                   const QByteArray& input, QByteArray& output,
                                   QString& err)
{
  QString program;
  // If the GENXRDPATTERN_EXECUTABLE environment variable is set, then
  // use that
  QByteArray xrdExec = qgetenv("GENXRDPATTERN_EXECUTABLE");
  if (!xrdExec.isEmpty()) {
    program = xrdExec;
  } else {
// Otherwise, search in the current directory, and then ../bin
#ifdef _WIN32
    QString executable = "genXrdPattern.exe";
#else
    QString executable = "genXrdPattern";
#endif
    QString path = QCoreApplication::applicationDirPath();
    if (QFile::exists(path + "/" + executable))
      program = path + "/" + executable;
    else if (QFile::exists(path + "/../bin/" + executable))
      program = path + "/../bin/" + executable;
    else {
      err = tr("Error: could not find genXrdPattern executable!");
      qDebug() << err;
      return false;
    }
  }

  QProcess p;
  p.start(program, args);

  if (!p.waitForStarted()) {
    err = tr("Error: " + program.toLocal8Bit() + " failed to start");
    qDebug() << err;
    return false;
  }

  // Give it the input!
  p.write(input.data());

  // Close the write channel
  p.closeWriteChannel();

  if (!p.waitForFinished()) {
    err = tr("Error: " + program.toLocal8Bit() + " failed to finish");
    qDebug() << err;
    output = p.readAll();
    qDebug() << "Output is as follows:\n" << output;
    return false;
  }

  int exitStatus = p.exitStatus();
  output = p.readAll();

  if (exitStatus == QProcess::CrashExit) {
    err = tr("Error: " + program.toLocal8Bit() + " crashed!");
    qDebug() << err;
    qDebug() << "Output is as follows:\n" << output;
    return false;
  }

  if (exitStatus != QProcess::NormalExit) {
    err = tr("Error: " + program.toLocal8Bit() +
             " finished abnormally with exit code " +
             QString::number(exitStatus).toLocal8Bit());
    qDebug() << err;
    qDebug() << "Output is as follows:\n" << output;
    return false;
  }

  // We did it!
  return true;
}

} // namespace QtPlugins
} // namespace Avogadro
