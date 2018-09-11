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
#include <QSettings>
#include <QString>
#include <QTextEdit>
#include <QVBoxLayout>

#include <avogadro/core/array.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/vtk/vtkplot.h>

#include "banddialog.h"
#include "specialkpoints.h"
#include "yaehmopout.h"

#include "yaehmop.h"

using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Core::Array;
using Avogadro::Core::Elements;
using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

Yaehmop::Yaehmop(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_actions(QList<QAction*>()),
    m_molecule(nullptr), m_yaehmopSettings(),
    m_bandDialog(
      new BandDialog(qobject_cast<QWidget*>(parent()), m_yaehmopSettings)),
    m_displayBandDialogAction(new QAction(this))
{
  m_displayBandDialogAction->setText(tr("Calculate band structure..."));
  connect(m_displayBandDialogAction.get(), &QAction::triggered, this,
          &Yaehmop::displayBandDialog);
  m_actions.push_back(m_displayBandDialogAction.get());
  m_displayBandDialogAction->setProperty("menu priority", 90);

  updateActions();

  readSettings();
}

Yaehmop::~Yaehmop() = default;

QList<QAction*> Yaehmop::actions() const
{
  return m_actions;
}

QStringList Yaehmop::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions") << tr("&Yaehmop");
}

void Yaehmop::setMolecule(QtGui::Molecule* mol)
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

void Yaehmop::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void Yaehmop::updateActions()
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

void Yaehmop::readSettings()
{
  QSettings settings;
  m_yaehmopSettings.numBandKPoints =
    settings.value("yaehmop/bandOptions/numBandKPoints", 40).toUInt();
  m_yaehmopSettings.displayYaehmopInput =
    settings.value("yaehmop/general/displayYaehmopInput", false).toBool();
  m_yaehmopSettings.limitY =
    settings.value("yaehmop/general/limitY", false).toBool();
  m_yaehmopSettings.minY =
    settings.value("yaehmop/general/minY", 0.0).toDouble();
  m_yaehmopSettings.maxY =
    settings.value("yaehmop/general/maxY", 0.0).toDouble();
  m_yaehmopSettings.plotFermi =
    settings.value("yaehmop/general/plotFermi", false).toBool();
  m_yaehmopSettings.fermi =
    settings.value("yaehmop/general/fermi", 0.0).toDouble();
  m_yaehmopSettings.zeroFermi =
    settings.value("yaehmop/general/zeroFermi", false).toBool();
  m_yaehmopSettings.numDim =
    settings.value("yaehmop/general/numDim", 3).toUInt();
}

void Yaehmop::writeSettings()
{
  QSettings settings;
  settings.setValue("yaehmop/bandOptions/numBandKPoints",
                    m_yaehmopSettings.numBandKPoints);
  settings.setValue("yaehmop/general/displayYaehmopInput",
                    m_yaehmopSettings.displayYaehmopInput);
  settings.setValue("yaehmop/general/limitY", m_yaehmopSettings.limitY);
  settings.setValue("yaehmop/general/minY", m_yaehmopSettings.minY);
  settings.setValue("yaehmop/general/maxY", m_yaehmopSettings.maxY);
  settings.setValue("yaehmop/general/plotFermi", m_yaehmopSettings.plotFermi);
  settings.setValue("yaehmop/general/fermi", m_yaehmopSettings.fermi);
  settings.setValue("yaehmop/general/zeroFermi", m_yaehmopSettings.zeroFermi);
  settings.setValue("yaehmop/general/numDim", m_yaehmopSettings.numDim);
}

void Yaehmop::displayBandDialog()
{
  if (!m_molecule) {
    qDebug() << "Error in " << __FUNCTION__ << ": the molecule is not set";
    return;
  }

  if (!m_molecule->unitCell()) {
    QMessageBox::warning(nullptr, tr("Avogadro2"),
                         tr("Cannot calculate band structure: no unit cell!"));
    qDebug() << "Error in " << __FUNCTION__ << ": there is no unit cell";
    return;
  }

  // Generate the special k points before displaying the dialog
  m_yaehmopSettings.specialKPoints =
    SpecialKPoints::getSpecialKPoints(*m_molecule);

  if (m_yaehmopSettings.specialKPoints.isEmpty())
    m_yaehmopSettings.specialKPoints = YAEHMOP_DEFAULT_SPECIAL_KPOINTS;

  // Do nothing if the user cancels
  if (m_bandDialog->exec() != QDialog::Accepted)
    return;

  // Save the settings for future use
  writeSettings();

  calculateBandStructure();
}

// Get the distance between two k points
double Yaehmop::kpointDistance(const Vector3& a, const Vector3& b)
{
  if (!m_molecule) {
    qDebug() << "Error in" << __FUNCTION__ << ": the molecule is not set";
    return -1.0;
  }

  UnitCell* cell = m_molecule->unitCell();
  if (!cell) {
    qDebug() << "Error in " << __FUNCTION__ << ": there is no unit cell";
    return -1.0;
  }

  // We need to find the reciprocal space basis vectors, and we
  // need to find the actual k point location in reciprocal space.
  const Vector3& aVec = cell->aVector();
  const Vector3& bVec = cell->bVector();
  const Vector3& cVec = cell->cVector();

  Vector3 b1 = bVec.cross(cVec);
  Vector3 b2 = cVec.cross(aVec);
  Vector3 b3 = aVec.cross(bVec);

  // This is how VASP does it.
  // If it's good enough for VASP, it's good enough for me!
  double omega = aVec[0] * b1[0] + aVec[1] * b1[1] + aVec[2] * b1[2];

  b1 /= omega;
  b2 /= omega;
  b3 /= omega;

  // Calculate the reciprocal points
  const Vector3& recA(a[0] * b1 + a[1] * b2 + a[2] * b3);
  const Vector3& recB(b[0] * b1 + b[1] * b2 + b[2] * b3);
  return (recA - recB).norm();
}

void Yaehmop::calculateBandStructure()
{
  // First, create the input
  QString input;
  input += "Title\n"; // Title
  input += createGeometryAndLatticeInput();

  // Here we describe the number of k points connecting each special
  // k point, the number of special k points, and their locations
  // in reciprocal space. This is something we will let the user change
  input += "Band\n";

  // This is the number of kpoints connecting each special k point
  input += (QString::number(m_yaehmopSettings.numBandKPoints) + "\n");

  // Num special k points
  int numSK = m_yaehmopSettings.specialKPoints
                .split(QRegExp("[\r\n]"), QString::SkipEmptyParts)
                .size();
  input += (QString::number(numSK) + "\n"); // num special k points

  // Add the whole string from user input
  input += m_yaehmopSettings.specialKPoints;

  // Perform the yaehmop calculation
  QByteArray output;
  QString err;
  if (!executeYaehmop(input.toLocal8Bit(), output, err)) {
    QMessageBox::warning(
      nullptr, tr("Avogadro2"),
      tr("Yaehmop execution failed with the following error:\n") + err);
    qDebug() << "Yaehmop execution failed with the following error:\n" << err;
    return;
  }

  // Now, read the output
  QVector<QVector<double>> bands;
  QVector<Vector3> kpoints;
  QVector<specialKPoint> specialKPoints;
  if (!YaehmopOut::readBandData(output, bands, kpoints, specialKPoints)) {
    QString message = tr("Failed to read band structure output from Yaehmop!");
    QMessageBox::warning(nullptr, tr("Avogadro2"), message);
    qDebug() << message;
  }

  int numKPoints = kpoints.size();
  int numOrbitals = bands.size();
  int numSpecialKPoints = specialKPoints.size();

  // If there is only one special k point, there is nothing to graph. Just
  // return.
  if (numSpecialKPoints <= 1) {
    QString message =
      tr("Only one special k point was found in Yaehmop output! Two or more "
         "are required!");
    QMessageBox::warning(nullptr, tr("Avogadro2"), message);
    qDebug() << message;
    return;
  }

  // Calculate the k-space distances
  std::vector<double> xVals{ 0.0 };
  for (int i = 1; i < numKPoints; ++i)
    xVals.push_back(kpointDistance(kpoints[i - 1], kpoints[i]) + xVals.back());

  // Calculate the special k point distances
  std::vector<double> specialKPointVals{ 0.0 };
  for (int i = 1; i < numSpecialKPoints; ++i) {
    specialKPointVals.push_back(
      kpointDistance(specialKPoints[i - 1].coords, specialKPoints[i].coords) +
      specialKPointVals.back());
  }

  // This is to make sure vtk shows the symbols on the far left and right
  specialKPointVals.front() += 0.0001;
  specialKPointVals.back() -= 0.0001;

  // Make a vector of labels for the special k points
  std::vector<std::string> specialKPointLabels;
  for (int i = 0; i < numSpecialKPoints; ++i) {
    std::string label = specialKPoints[i].label.toStdString();
    specialKPointLabels.push_back(label);
  }

  // Now generate a plot with the data
  std::vector<std::vector<double>> data;
  data.push_back(xVals);

  using VtkPlot = VTK::VtkPlot;

  // Make some labels
  std::vector<std::string> lineLabels;

  // Set the color
  std::array<double, 4> color = { 255, 0, 0, 255 };
  std::vector<std::array<double, 4>> lineColors;

  // Set the line styles. Most should be solid
  VtkPlot::LineStyle style = VtkPlot::LineStyle::solidLine;
  std::vector<VtkPlot::LineStyle> lineStyles;

  size_t curBandNum = 1;
  for (const auto& band : bands) {
    data.push_back(band.toStdVector());
    lineLabels.push_back("Band " + std::to_string(curBandNum));
    lineColors.push_back(color);
    lineStyles.push_back(style);
    ++curBandNum;
  }

  // Should we plot the fermi level?
  if (m_yaehmopSettings.plotFermi) {
    // Adjust all the energies if we are to zero the fermi level
    double fermi = m_yaehmopSettings.fermi;
    if (m_yaehmopSettings.zeroFermi) {
      // Skip the first vector because that is the x values
      for (size_t i = 1; i < data.size(); ++i) {
        for (auto& datum : data[i])
          datum -= fermi;
      }
      // Fermi is now zero
      fermi = 0.0;
    }

    // Create a horizontal, black, dashed line for the fermi level
    lineLabels.push_back("Fermi Level");
    lineColors.push_back({ 0, 0, 0, 255 });
    lineStyles.push_back(VtkPlot::LineStyle::dashLine);

    std::vector<double> fermiVals(xVals.size(), fermi);
    data.push_back(std::move(fermiVals));
  }

  const char* xTitle = "";
  const char* yTitle = "Energy (eV)";
  const char* windowName = "YAeHMOP Band Structure";

  m_bandPlot.reset(new VtkPlot);
  m_bandPlot->setData(data);
  m_bandPlot->setWindowName(windowName);
  m_bandPlot->setXTitle(xTitle);
  m_bandPlot->setYTitle(yTitle);
  m_bandPlot->setLineLabels(lineLabels);
  m_bandPlot->setLineColors(lineColors);
  m_bandPlot->setLineStyles(lineStyles);
  m_bandPlot->setCustomTickLabels(VtkPlot::Axis::xAxis, specialKPointVals,
                                  specialKPointLabels);

  // It makes more sense to stop the x axis exactly at its limits
  m_bandPlot->setAxisLimits(VtkPlot::Axis::xAxis, xVals.front(), xVals.back());

  if (m_yaehmopSettings.limitY) {
    m_bandPlot->setAxisLimits(VtkPlot::Axis::yAxis, m_yaehmopSettings.minY,
                              m_yaehmopSettings.maxY);
  }

  m_bandPlot->show();

  // Show the yaehmop input if we are to do so
  if (m_yaehmopSettings.displayYaehmopInput)
    showYaehmopInput(input);
}

QString Yaehmop::createGeometryAndLatticeInput() const
{
  if (!m_molecule) {
    qDebug() << "Error in " << __FUNCTION__ << ": the molecule is not set";
    return "";
  }

  UnitCell* cell = m_molecule->unitCell();
  if (!cell) {
    QMessageBox::warning(nullptr, tr("Avogadro2"),
                         tr("Cannot calculate band structure: no unit cell!"));
    qDebug() << "Error in " << __FUNCTION__ << ": there is no unit cell";
    return "";
  }

  const Array<unsigned char>& atomicNumbers = m_molecule->atomicNumbers();
  const Array<Vector3>& atomicPositions = m_molecule->atomPositions3d();

  // This is the minimum number we allow doubles. If a number's float
  // absolute value is smaller than this, we will round it to 0.
  double minNum = 1e-8;

  QString input;
  input += "Geometry\n"; // Begin geometry section
  int numAtoms = atomicNumbers.size();
  // Num atoms plus (numDimensions + 1) dummies.
  // Dummies are for defining the lattice
  unsigned short numDim = m_yaehmopSettings.numDim;
  input += (QString::number(numAtoms + numDim + 1) + QString("\n"));

  // Now loop through atom positions and add them
  for (int i = 0; i < numAtoms; ++i) {
    QString symbol = Elements::symbol(atomicNumbers[i]);
    const Vector3& pos = atomicPositions[i];
    input += (QString::number(i + 1) + " ");
    input += (symbol + " ");
    for (size_t j = 0; j < 3; ++j)
      // If the position is small, just use 0
      input += (QString::number((fabs(pos[j]) > 1e-8 ? pos[j] : 0)) + " ");
    input += "\n";
  }

  // Get the cell matrix
  const Matrix3& cellMatrix = cell->cellMatrix();

  // Add the dummy atoms - these tell the program where the lattice is
  for (unsigned short i = 0; i <= numDim; ++i) {
    input += (QString::number(numAtoms + i + 1) + " ");
    // Symbol for dummy atoms
    input += "& ";
    // First dummy is at 0,0,0, the other dummies are at the ends of the
    // lattice
    if (i == 0) {
      input += "0 0 0\n";
    } else {
      // We only get here if i > 0.
      // i - 1 is equal to the index of the vector we are looking at.
      for (unsigned short j = 0; j < 3; ++j) {
        double val = cellMatrix(i - 1, j);
        if (fabs(val) < minNum)
          val = 0.0;
        input += (QString::number(val) + " ");
      }
      input += "\n";
    }
  }

  // Let's calculate the number of overlaps to use
  // The manual says that numOverlaps * latticeVecLength should be between
  // 10 and 20 Angstroms. Let's always use a numOverlaps of at least 3 and
  // then use more if numOverlaps * latticeVecLength < 20.
  Vector3i overlaps(3, 3, 3);
  Vector3 latticeLengths(cell->a(), cell->b(), cell->c());

  for (unsigned short i = 0; i < 3; ++i) {
    while (overlaps[i] * latticeLengths[i] < 20)
      ++overlaps[i];
  }

  // Lattice section to define the lattice
  input += "lattice\n";
  input += QString::number(numDim) + "\n";
  // Add numbers of overlaps
  for (size_t i = 0; i < numDim; ++i)
    input += (QString::number(overlaps[i]) + " ");
  input += "\n";
  // If we have "4 5" here, that means the vector is defined
  // from atom 4 to atom 5. We use dummy atoms for this. The first dummy
  // atom (numAtoms + 1) is always at the origin, and the other dummy atoms
  // are at the ends of the a, b, and c axes.
  for (size_t i = 0; i < numDim; ++i) {
    input += (QString::number(numAtoms + 1) + " " +
              QString::number(numAtoms + i + 2) + "\n");
  }

  return input;
}

// Uncomment this for executeYaehmop debugging
//#define AVOGADRO_YAEHMOP_EXECUTE_DEBUG

bool Yaehmop::executeYaehmop(const QByteArray& input, QByteArray& output,
                             QString& err)
{
#ifdef AVOGADRO_YAEHMOP_EXECUTE_DEBUG
  qDebug() << "executeYaehmop() input is:\n" << qPrintable(input);
#endif

  QString program;
  // If the YAEHMOP_EXECUTABLE environment variable is set, then
  // use that
  QByteArray yaehmopExec = qgetenv("YAEHMOP_EXECUTABLE");
  if (!yaehmopExec.isEmpty()) {
    program = yaehmopExec;
  } else {
// Otherwise, search in the current directory, and then ../bin
#ifdef _WIN32
    QString executable = "yaehmop.exe";
#else
    QString executable = "yaehmop";
#endif
    QString path = QCoreApplication::applicationDirPath();
    if (QFile::exists(path + "/" + executable))
      program = path + "/" + executable;
    else if (QFile::exists(path + "/../bin/" + executable))
      program = path + "/../bin/" + executable;
    else {
      err = tr("Error: could not find yaehmop executable!");
      qDebug() << err;
      return false;
    }
  }

  QStringList args;
  args << "--use_stdin_stdout";

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
    qDebug() << "Output is as follows:\n" << qPrintable(output);
    return false;
  }

  int exitStatus = p.exitStatus();
  output = p.readAll();

  if (exitStatus == QProcess::CrashExit) {
    err = tr("Error: " + program.toLocal8Bit() + " crashed!");
    qDebug() << err;
    qDebug() << "Output is as follows:\n" << qPrintable(output);
    return false;
  }

  if (exitStatus != QProcess::NormalExit) {
    err = tr("Error: " + program.toLocal8Bit() +
             " finished abnormally with exit code " +
             QString::number(exitStatus).toLocal8Bit());
    qDebug() << err;
    qDebug() << "Output is as follows:\n" << qPrintable(output);
    return false;
  }

#ifdef AVOGADRO_YAEHMOP_EXECUTE_DEBUG
  qDebug() << "executeYaehmop() output is:\n" << qPrintable(output);
#endif

  // We did it!
  return true;
}

void Yaehmop::showYaehmopInput(const QString& input)
{
  QDialog* dialog = new QDialog;

  // Make sure this gets deleted upon closing
  dialog->setAttribute(Qt::WA_DeleteOnClose);

  QVBoxLayout* layout = new QVBoxLayout(dialog);
  dialog->setLayout(layout);
  dialog->setWindowTitle(tr("Yaehmop Input"));
  QTextEdit* edit = new QTextEdit(dialog);
  layout->addWidget(edit);
  dialog->resize(500, 500);

  edit->setText(input);

  dialog->show();
}

} // namespace QtPlugins
} // namespace Avogadro
