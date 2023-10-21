/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "openbabel.h"

#include "obcharges.h"
#include "obfileformat.h"
#include "obforcefielddialog.h"
#include "obprocess.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

#include <QAction>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

#include <QRegularExpression>

#include <string>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

OpenBabel::OpenBabel(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_process(new OBProcess(this)),
    m_readFormatsPending(true), m_writeFormatsPending(true),
    m_defaultFormat("cjson"), m_progress(nullptr)
{
  auto* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Optimize Geometry"));
  action->setShortcut(QKeySequence("Ctrl+Alt+O"));
  connect(action, SIGNAL(triggered()), SLOT(onOptimizeGeometry()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Configure Force Field…"));
  connect(action, SIGNAL(triggered()), SLOT(onConfigureGeometryOptimization()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Perceive Bonds"));
  connect(action, SIGNAL(triggered()), SLOT(onPerceiveBonds()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Add Hydrogens"));
  connect(action, SIGNAL(triggered()), SLOT(onAddHydrogens()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Add Hydrogens for pH…"));
  connect(action, SIGNAL(triggered()), SLOT(onAddHydrogensPh()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Remove Hydrogens"));
  connect(action, SIGNAL(triggered()), SLOT(onRemoveHydrogens()));
  m_actions.push_back(action);

  refreshReadFormats();
  refreshWriteFormats();
  refreshForceFields();
  refreshCharges();

  QString info = openBabelInfo();
  /*
  if (info.isEmpty()) {
    qWarning() << tr("%1 not found! Disabling Open Babel plugin actions.")
                    .arg(OBProcess().obabelExecutable());
    foreach (QAction* a, m_actions)
      a->setEnabled(false);
  } else {
  */
  qDebug() << OBProcess().obabelExecutable() << " found: " << info;
  // }
}

OpenBabel::~OpenBabel() {}

QList<QAction*> OpenBabel::actions() const
{
  return m_actions;
}

QStringList OpenBabel::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions") << tr("&Open Babel");
}

QList<Io::FileFormat*> OpenBabel::fileFormats() const
{
  // Return empty list if not ready yet, and print a warning.
  if (m_readFormatsPending || m_writeFormatsPending) {
    qDebug() << tr("The Open Babel file formats are not ready to be added.");
    return QList<Io::FileFormat*>();
  }

  QList<Io::FileFormat*> result;

  std::string mapDesc;
  std::string fname;
  std::string fidentifier;
  std::string fdescription;
  std::string fspecificationUrl("http://openbabel.org/wiki/Category:Formats");
  std::vector<std::string> fexts;
  std::vector<std::string> fmime;

  // Simple lambda to replace toSet in QList
  auto toSet = [&](const QList<QString>& list) {
    return QSet<QString>(list.begin(), list.end());
  };

  QSet<QString> formatDescriptions;
  formatDescriptions.unite(toSet(m_readFormats.uniqueKeys()));
  formatDescriptions.unite(toSet(m_writeFormats.uniqueKeys()));

  QSet<QString> formatExtensions;

  // These can only be read directly from file:
  QList<QString> multifileFormatDescriptions;
  multifileFormatDescriptions << "VASP format";
  multifileFormatDescriptions << "Gaussian Output";            // Issue #571
  multifileFormatDescriptions << "Generic Output file format"; // #571 and 827

  foreach (const QString& qdesc, formatDescriptions) {
    mapDesc = qdesc.toStdString();
    fname = mapDesc;
    fidentifier = std::string("OpenBabel: ") + mapDesc;
    fdescription = mapDesc;
    fexts.clear();
    fmime.clear();
    bool fileOnly = multifileFormatDescriptions.contains(qdesc);

    formatExtensions.clear();
    Io::FileFormat::Operations rw = Io::FileFormat::None;

    if (m_readFormats.contains(qdesc)) {
      formatExtensions.unite(toSet(m_readFormats.values(qdesc)));
      rw |= Io::FileFormat::Read;
    }
    if (m_writeFormats.contains(qdesc)) {
      formatExtensions.unite(toSet(m_writeFormats.values(qdesc)));
      rw |= Io::FileFormat::Write;
    }

    foreach (const QString& ext, formatExtensions)
      fexts.push_back(ext.toStdString());

    auto* fmt =
      new OBFileFormat(fname, fidentifier, fdescription, fspecificationUrl,
                       fexts, fmime, m_defaultFormat, fileOnly);

    fmt->setReadWriteFlags(rw);
    result.append(fmt);
  }

  qDebug() << "Open Babel formats ready: " << result.size();

  return result;
}

QString OpenBabel::openBabelInfo() const
{
  OBProcess proc;
  QString version = proc.version();
  if (version.isEmpty())
    return QString();
  return QString("%1: %2").arg(proc.obabelExecutable(), version);
}

void OpenBabel::setMolecule(QtGui::Molecule* mol)
{
  if (mol != m_molecule)
    m_molecule = mol;
}

bool OpenBabel::readMolecule(QtGui::Molecule& mol)
{
  m_progress->setLabelText(tr("Loading molecule from Open Babel…"));

  bool result = false;

  if (m_moleculeQueue.isEmpty()) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("An internal error occurred: "
                             "OpenBabel::readMolecule called, but no obabel "
                             "output is available to parse!"),
                          QMessageBox::Ok);
  } else {
    QByteArray output = m_moleculeQueue.takeFirst();
    // Empty output means openbabel crashed, etc.
    if (output.isEmpty()) {
      QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                            tr("An error occurred while running Open Babel "
                               "(%1).")
                              .arg(m_process->obabelExecutable()),
                            QMessageBox::Ok);
    } else {
      result = Io::FileFormatManager::instance().readString(
        mol, output.constData(), m_defaultFormat);
      if (!result) {
        qWarning() << "Error parsing OpenBabel output:\n" << output;
        QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                              tr("Error parsing openbabel output."),
                              QMessageBox::Ok);
      }
    }
  }

  m_progress->reset();
  return result;
}

void OpenBabel::refreshReadFormats()
{
  // No need to check if the member process is in use -- we use a temporary
  // process for the refresh methods.
  auto* proc = new OBProcess(this);

  connect(proc, SIGNAL(queryReadFormatsFinished(QMultiMap<QString, QString>)),
          SLOT(handleReadFormatUpdate(QMultiMap<QString, QString>)));

  proc->queryReadFormats();
}

void OpenBabel::handleReadFormatUpdate(const QMultiMap<QString, QString>& fmts)
{
  m_readFormatsPending = false;

  auto* proc = qobject_cast<OBProcess*>(sender());
  if (proc)
    proc->deleteLater();

  m_readFormats = fmts;

  // Emit a signal indicating the file formats are ready if read and write
  // formats have both returned their results.
  if (!m_readFormatsPending && !m_writeFormatsPending) {
    emit fileFormatsReady();

    // Update the default format if cjson is available
    if (!m_readFormats.contains("Chemical JSON") &&
        !m_writeFormats.contains("Chemical JSON")) {
      m_defaultFormat = "cml";
    }
  }
}

void OpenBabel::refreshWriteFormats()
{
  // No need to check if the member process is in use -- we use a temporary
  // process for the refresh methods.
  auto* proc = new OBProcess(this);

  connect(proc, SIGNAL(queryWriteFormatsFinished(QMultiMap<QString, QString>)),
          SLOT(handleWriteFormatUpdate(QMultiMap<QString, QString>)));

  proc->queryWriteFormats();
}

void OpenBabel::handleWriteFormatUpdate(const QMultiMap<QString, QString>& fmts)
{
  m_writeFormatsPending = false;

  auto* proc = qobject_cast<OBProcess*>(sender());
  if (proc)
    proc->deleteLater();

  m_writeFormats = fmts;

  // Emit a signal indicating the file formats are ready if read and write
  // formats have both returned their results.
  if (!m_readFormatsPending && !m_writeFormatsPending) {
    emit fileFormatsReady();

    // Update the default format if cjson is available
    if (!m_readFormats.contains("Chemical JSON") &&
        !m_writeFormats.contains("Chemical JSON")) {
      m_defaultFormat = "cml";
    }
  }
}

void OpenBabel::refreshForceFields()
{
  // No need to check if the member process is in use -- we use a temporary
  // process for the refresh methods.
  auto* proc = new OBProcess(this);

  connect(proc, SIGNAL(queryForceFieldsFinished(QMultiMap<QString, QString>)),
          SLOT(handleForceFieldsUpdate(QMultiMap<QString, QString>)));

  proc->queryForceFields();
}

void OpenBabel::handleForceFieldsUpdate(
  const QMultiMap<QString, QString>& ffMap)
{
  auto* proc = qobject_cast<OBProcess*>(sender());
  if (proc)
    proc->deleteLater();

  m_forceFields = ffMap;
}

void OpenBabel::refreshCharges()
{
  // No need to check if the member process is in use -- we use a temporary
  // process for the refresh methods.
  auto* proc = new OBProcess(this);

  connect(proc, SIGNAL(queryChargesFinished(QMultiMap<QString, QString>)),
          SLOT(handleChargesUpdate(QMultiMap<QString, QString>)));

  proc->queryCharges();
}

void OpenBabel::handleChargesUpdate(
  const QMultiMap<QString, QString>& chargeMap)
{
  auto* proc = qobject_cast<OBProcess*>(sender());
  if (proc)
    proc->deleteLater();

  m_charges = chargeMap;
  // register the charge models
  foreach (const QString& key, m_charges.keys()) {
    // we're only picking a few select models for now
    if (key == "eem" || key == "eem2015ba" || key == "eqeq" ||
        key == "gasteiger" || key == "mmff94") {
      auto* model = new OBCharges(key.toStdString());
      Calc::ChargeManager::instance().registerModel(model);
    }
  }
}

void OpenBabel::onConfigureGeometryOptimization()
{
  // If the force field map is empty, there is probably a problem with the
  // obabel executable. Warn the user and return.
  if (m_forceFields.isEmpty()) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("An error occurred while retrieving the list of "
                             "supported forcefields. (using '%1').")
                            .arg(m_process->obabelExecutable()),
                          QMessageBox::Ok);
    return;
  }

  QSettings settings;
  QStringList options =
    settings.value("openbabel/optimizeGeometry/lastOptions").toStringList();

  options = OBForceFieldDialog::prompt(qobject_cast<QWidget*>(parent()),
                                       m_forceFields.keys(), options,
                                       autoDetectForceField());

  // User cancel
  if (options.isEmpty())
    return;

  settings.setValue("openbabel/optimizeGeometry/lastOptions", options);
}

void OpenBabel::onOptimizeGeometry()
{
  if (!m_molecule || m_molecule->atomCount() == 0) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Molecule invalid. Cannot optimize geometry."),
                          QMessageBox::Ok);
    return;
  }

  // If the force field map is empty, there is probably a problem with the
  // obabel executable. Warn the user and return.
  if (m_forceFields.isEmpty()) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("An error occurred while retrieving the list of "
                             "supported forcefields. (using '%1').")
                            .arg(m_process->obabelExecutable()),
                          QMessageBox::Ok);
    return;
  }

  // Fail here if the process is already in use
  if (m_process->inUse()) {
    showProcessInUseError(tr("Cannot optimize geometry with Open Babel."));
    return;
  }

  QSettings settings;
  QStringList options =
    settings.value("openbabel/optimizeGeometry/lastOptions").toStringList();
  bool autoDetect =
    settings.value("openbabel/optimizeGeometry/autoDetect", true).toBool();

  if (autoDetect) {
    QString ff = autoDetectForceField();
    int ffIndex = options.indexOf("--ff");
    if (ffIndex >= 0) {
      // Shouldn't happen, but just to be safe...
      if (ffIndex + 1 == options.size())
        options << ff;
      else
        options[ffIndex + 1] = ff;
    } else {
      options << "--ff" << ff;
    }
  }

  // Setup progress dialog
  initializeProgressDialog(tr("Optimizing Geometry (Open Babel)"),
                           tr("Generating MDL…"), 0, 0, 0);

  // Connect process
  disconnect(m_process);
  m_process->disconnect(this);
  connect(m_progress, SIGNAL(canceled()), m_process, SLOT(abort()));
  connect(m_process,
          SIGNAL(optimizeGeometryStatusUpdate(int, int, double, double)),
          SLOT(onOptimizeGeometryStatusUpdate(int, int, double, double)));
  connect(m_process, SIGNAL(optimizeGeometryFinished(QByteArray)),
          SLOT(onOptimizeGeometryFinished(QByteArray)));

  // Generate CML
  std::string mol;
  if (!Io::FileFormatManager::instance().writeString(*m_molecule, mol,
                                                     m_defaultFormat)) {
    m_progress->reset();
    QMessageBox::critical(
      qobject_cast<QWidget*>(parent()), tr("Error"),
      tr("An internal error occurred while generating an "
         "Open Babel representation of the current molecule."),
      QMessageBox::Ok);
    return;
  }

  m_progress->setLabelText(tr("Starting %1…", "arg is an executable file.")
                             .arg(m_process->obabelExecutable()));

  // Run obabel
  m_process->optimizeGeometry(QByteArray(mol.c_str()), options,
                              m_defaultFormat);
}

void OpenBabel::onOptimizeGeometryStatusUpdate(int step, int numSteps,
                                               double energy, double lastEnergy)
{
  QString status;

  if (step == 0) {
    status = tr("Step %1 of %2\nCurrent energy: %3\ndE: %4")
               .arg(step)
               .arg(numSteps)
               .arg(fabs(energy) > 1e-10 ? QString::number(energy, 'g', 5)
                                         : QString("(pending)"))
               .arg("(pending)");
  } else {
    double dE = energy - lastEnergy;
    status = tr("Step %1 of %2\nCurrent energy: %3\ndE: %4")
               .arg(step)
               .arg(numSteps)
               .arg(energy, 0, 'g', 5)
               .arg(dE, 0, 'g', 5);
  }

  m_progress->setRange(0, numSteps);
  m_progress->setValue(step);
  m_progress->setLabelText(status);
}

void OpenBabel::onOptimizeGeometryFinished(const QByteArray& output)
{
  m_progress->setLabelText(tr("Updating molecule…"));

  // CML --> molecule
  Core::Molecule mol;
  if (!Io::FileFormatManager::instance().readString(mol, output.constData(),
                                                    m_defaultFormat)) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error interpreting Open Babel output."),
                          QMessageBox::Ok);
    qDebug() << "Open Babel:" << output;
    return;
  }

  /// @todo cache a pointer to the current molecule in the above slot, and
  /// verify that we're still operating on the same molecule.

  // Check that the atom count hasn't changed:
  if (mol.atomCount() != m_molecule->atomCount()) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Number of atoms in obabel output (%1) does not "
                             "match the number of atoms in the original "
                             "molecule (%2).")
                            .arg(mol.atomCount())
                            .arg(m_molecule->atomCount()),
                          QMessageBox::Ok);
    return;
  }

  m_molecule->undoMolecule()->setAtomPositions3d(mol.atomPositions3d(),
                                                 tr("Optimize Geometry"));
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Modified);
  m_progress->reset();
}

void OpenBabel::onPerceiveBonds()
{
  // Fail here if the process is already in use
  if (m_process->inUse()) {
    showProcessInUseError(tr("Cannot open file with Open Babel."));
    return;
  }

  if (!m_molecule || m_molecule->atomCount() < 2) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Invalid molecule: Cannot perceive bonds."),
                          QMessageBox::Ok);
    return;
  }

  // Setup progress dialog
  initializeProgressDialog(tr("Perceiving Bonds (Open Babel)"),
                           tr("Generating XYZ representation…"), 0, 0, 0);

  // Generate XYZ
  std::string xyz;
  if (!Io::FileFormatManager::instance().writeString(*m_molecule, xyz, "xyz")) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error generating XYZ string."), QMessageBox::Ok);
    return;
  }

  // Connect process
  disconnect(m_process);
  m_process->disconnect(this);
  connect(m_progress, SIGNAL(canceled()), m_process, SLOT(abort()));
  connect(m_process, SIGNAL(convertFinished(QByteArray)),
          SLOT(onPerceiveBondsFinished(QByteArray)));

  m_progress->setLabelText(tr("Converting XYZ to Open Babel with %1…")
                             .arg(m_process->obabelExecutable()));

  // Run process
  m_process->convert(QByteArray(xyz.c_str(), xyz.size()), "xyz",
                     m_defaultFormat.c_str());
}

void OpenBabel::onPerceiveBondsFinished(const QByteArray& output)
{
  m_progress->setLabelText(tr("Updating molecule from Open Babel…"));

  // CML --> molecule
  Core::Molecule mol;
  if (!Io::FileFormatManager::instance().readString(mol, output.constData(),
                                                    m_defaultFormat)) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error interpreting Open Babel output."),
                          QMessageBox::Ok);
    return;
  }

  /// @todo cache a pointer to the current molecule in the above slot, and
  /// verify that we're still operating on the same molecule.

  // Check that the atom count hasn't changed:
  if (mol.atomCount() != m_molecule->atomCount()) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Number of atoms in obabel output (%1) does not "
                             "match the number of atoms in the original "
                             "molecule (%2).")
                            .arg(mol.atomCount())
                            .arg(m_molecule->atomCount()),
                          QMessageBox::Ok);
    return;
  }

  // Update the undo stack
  Molecule newMolecule = *m_molecule;
  newMolecule.clearBonds();
  for (size_t i = 0; i < mol.bondCount(); ++i) {
    Avogadro::Core::Bond bond = mol.bond(i);
    newMolecule.addBond(newMolecule.atom(bond.atom1().index()),
                        newMolecule.atom(bond.atom2().index()), bond.order());
  }

  Molecule::MoleculeChanges changes =
    Molecule::Bonds | Molecule::Added | Molecule::Removed | Molecule::Modified;
  m_molecule->undoMolecule()->modifyMolecule(newMolecule, changes,
                                             "Perceive Bonds");
  m_progress->reset();
}

void OpenBabel::onAddHydrogens()
{
  if (!m_molecule || m_molecule->atomCount() == 0)
    return; // Nothing to do.

  // Fail here if the process is already in use
  if (m_process->inUse()) {
    showProcessInUseError(tr("Cannot add hydrogens with Open Babel."));
    return;
  }

  // Setup progress dialog
  initializeProgressDialog(tr("Adding Hydrogens (Open Babel)"),
                           tr("Generating Open Babel input…"), 0, 0, 0);

  // Generate MDL
  std::string mol;
  if (!Io::FileFormatManager::instance().writeString(*m_molecule, mol,
                                                     m_defaultFormat)) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error generating Open Babel input."),
                          QMessageBox::Ok);
    return;
  }

  // Connect process
  disconnect(m_process);
  m_process->disconnect(this);
  connect(m_progress, SIGNAL(canceled()), m_process, SLOT(abort()));
  connect(m_process, SIGNAL(convertFinished(QByteArray)),
          SLOT(onHydrogenOperationFinished(QByteArray)));

  m_progress->setLabelText(
    tr("Running %1…").arg(m_process->obabelExecutable()));

  // Run process
  m_process->convert(QByteArray(mol.c_str(), mol.size()),
                     m_defaultFormat.c_str(), m_defaultFormat.c_str(),
                     QStringList() << "-h");
}

void OpenBabel::onAddHydrogensPh()
{
  if (!m_molecule || m_molecule->atomCount() == 0)
    return; // Nothing to do.

  // Fail here if the process is already in use
  if (m_process->inUse()) {
    showProcessInUseError(tr("Cannot add hydrogens with Open Babel."));
    return;
  }

  // Prompt for pH
  bool ok = false;
  double pH = QInputDialog::getDouble(qobject_cast<QWidget*>(parent()),
                                      tr("Add hydrogens for pH"), tr("pH:"),
                                      7.4, 0, 14, 2, &ok);
  if (!ok) // user cancel
    return;

  // Setup progress dialog
  initializeProgressDialog(tr("Adding Hydrogens (Open Babel)"),
                           tr("Generating obabel input…"), 0, 0, 0);

  // Generate MDL
  std::string mol;
  if (!Io::FileFormatManager::instance().writeString(*m_molecule, mol,
                                                     m_defaultFormat)) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error generating Open Babel input."),
                          QMessageBox::Ok);
    return;
  }

  // Connect process
  disconnect(m_process);
  m_process->disconnect(this);
  connect(m_progress, SIGNAL(canceled()), m_process, SLOT(abort()));
  connect(m_process, SIGNAL(convertFinished(QByteArray)),
          SLOT(onHydrogenOperationFinished(QByteArray)));

  m_progress->setLabelText(
    tr("Running %1…").arg(m_process->obabelExecutable()));

  // Run process
  m_process->convert(QByteArray(mol.c_str(), mol.size()),
                     m_defaultFormat.c_str(), m_defaultFormat.c_str(),
                     QStringList() << "-p" << QString::number(pH));
}

void OpenBabel::onRemoveHydrogens()
{
  if (!m_molecule || m_molecule->atomCount() == 0)
    return; // Nothing to do.

  // Fail here if the process is already in use
  if (m_process->inUse()) {
    showProcessInUseError(tr("Cannot remove hydrogens with Open Babel."));
    return;
  }

  // Setup progress dialog
  initializeProgressDialog(tr("Removing Hydrogens (Open Babel)"),
                           tr("Generating obabel input…"), 0, 0, 0);

  // Generate MDL
  std::string mol;
  if (!Io::FileFormatManager::instance().writeString(*m_molecule, mol,
                                                     m_defaultFormat)) {
    m_progress->reset();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error generating Open Babel data."),
                          QMessageBox::Ok);
    return;
  }

  // Connect process
  disconnect(m_process);
  m_process->disconnect(this);
  connect(m_progress, SIGNAL(canceled()), m_process, SLOT(abort()));
  connect(m_process, SIGNAL(convertFinished(QByteArray)),
          SLOT(onHydrogenOperationFinished(QByteArray)));

  m_progress->setLabelText(
    tr("Running %1…").arg(m_process->obabelExecutable()));

  // Run process
  m_process->convert(QByteArray(mol.c_str(), mol.size()),
                     m_defaultFormat.c_str(), m_defaultFormat.c_str(),
                     QStringList() << "-d");
}

void OpenBabel::onHydrogenOperationFinished(const QByteArray& mdl)
{
  m_progress->setLabelText(tr("Reading obabel output…"));

  // MDL --> molecule
  Core::Molecule mol;
  if (!Io::FileFormatManager::instance().readString(mol, mdl.constData(),
                                                    m_defaultFormat)) {
    m_progress->reset();
    qWarning() << "Open Babel error: " << mdl;
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                          tr("Error interpreting Open Babel output."),
                          QMessageBox::Ok);
    qDebug() << "Open Babel:" << mdl;
    return;
  }

  /// @todo cache a pointer to the current molecule in the above slot, and
  /// verify that we're still operating on the same molecule.

  // Update the undo stack
  Molecule newMolecule;
  for (Index i = 0; i < mol.atomCount(); ++i) {
    Core::Atom atom = mol.atom(i);
    newMolecule.addAtom(atom.atomicNumber()).setPosition3d(atom.position3d());
  }
  for (Index i = 0; i < mol.bondCount(); ++i) {
    Core::Bond bond = mol.bond(i);
    newMolecule.addBond(newMolecule.atom(bond.atom1().index()),
                        newMolecule.atom(bond.atom2().index()), bond.order());
  }

  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Bonds |
                                      Molecule::Added | Molecule::Removed |
                                      Molecule::Modified;

  // If the number of atoms is greater, we added hydrogens. Else, we removed
  // them!
  QString undoString = "Add Hydrogens";
  if (m_molecule->atomCount() > newMolecule.atomCount())
    undoString = "Remove Hydrogens";

  m_molecule->undoMolecule()->modifyMolecule(newMolecule, changes, undoString);
  m_progress->reset();
}

void OpenBabel::initializeProgressDialog(const QString& title,
                                         const QString& label, int min, int max,
                                         int value, bool showDialog)
{
  if (!m_progress)
    m_progress = new QProgressDialog(qobject_cast<QWidget*>(parent()));

  m_progress->setWindowTitle(title);
  m_progress->setLabelText(label);
  m_progress->setRange(min, max);
  m_progress->setValue(value);
  m_progress->setMinimumDuration(0);
  if (showDialog)
    m_progress->show();
}

void OpenBabel::showProcessInUseError(const QString& title) const
{
  QMessageBox::critical(qobject_cast<QWidget*>(parent()), title,
                        tr("Already running Open Babel. Wait for the other "
                           "operation to complete and try again."),
                        QMessageBox::Ok);
}

QString OpenBabel::autoDetectForceField() const
{
  // Guess forcefield based on molecule. Preference is GAFF, MMFF94, then UFF.
  // See discussion at
  // http://forums.openbabel.org/Heuristic-for-selecting-best-forcefield-td4655917.html
  QString formula = QString::fromStdString(m_molecule->formula());
  QStringList elementTypes =
    formula.split(QRegularExpression("\\d+"), Qt::SkipEmptyParts);
  bool mmff94Valid = true;
  bool gaffValid = true;
  QStringList::const_iterator eleIter = elementTypes.constBegin();
  while (eleIter != elementTypes.constEnd() && (mmff94Valid || gaffValid)) {
    // These are supported by GAFF and MMFF94s
    if (*eleIter != "C" && *eleIter != "H" && *eleIter != "F" &&
        *eleIter != "Cl" && *eleIter != "Br" && *eleIter != "I" &&
        *eleIter != "N" && *eleIter != "O" && *eleIter != "P" &&
        *eleIter != "S") {
      gaffValid = false;
      mmff94Valid = false;

      // MMFF94 supports isolated metal ions but it's safer to use UFF
      // Fixes #1324
    }
    ++eleIter;
  }

  QStringList ffs = m_forceFields.keys();
  QString result;
  if (gaffValid && ffs.contains("GAFF"))
    result = "GAFF";
  else if (mmff94Valid && ffs.contains("MMFF94"))
    result = "MMFF94";
  // MMFF94 handles nitrogens more correctly than MMFF94s, but this
  // can be used in a pinch.
  else if (mmff94Valid && ffs.contains("MMFF94s"))
    result = "MMFF94s";
  else if (ffs.contains("UFF"))
    result = "UFF";

  return result;
}
} // namespace Avogadro::QtPlugins
