/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "symmetry.h"

#include "symmetrywidget.h"

#include "symmetryutil.h"

// #include <avogadro/core/unitcell.h>
// #include <avogadro/core/crystaltools.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QAction>
#include <QtWidgets/QMessageBox>

#include <QtCore/QDebug>
#include <QtCore/QStringList>

// using Avogadro::Core::CrystalTools;
// using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

using namespace msym;
using namespace Avogadro::QtPlugins::SymmetryUtil;

namespace Avogadro::QtPlugins {

Symmetry::Symmetry(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_symmetryWidget(nullptr), m_viewSymmetryAction(new QAction(this))
{

  m_ctx = msymCreateContext();

  m_viewSymmetryAction->setText(tr("Symmetry…"));
  m_viewSymmetryAction->setProperty("menu priority", -50);
  connect(m_viewSymmetryAction, SIGNAL(triggered()), SLOT(viewSymmetry()));
  m_actions.push_back(m_viewSymmetryAction);

  /*
  connect(m_symmetryWidget, SIGNAL(clicked()), this, SLOT(detectSymmetry()));
  connect(m_ui->symmetrizeButton, SIGNAL(clicked()), this, SLOT(symmetrize()));
  connect(m_ui->toleranceCombo, SIGNAL(currentIndexChanged(int)), this,
  SLOT(toleranceChanged(int)));*/

  /*
    m_standardOrientationAction->setText(tr("Rotate to Standard &Orientation"));
    connect(m_standardOrientationAction, SIGNAL(triggered()),
            SLOT(standardOrientation()));
    m_actions.push_back(m_standardOrientationAction);
    m_standardOrientationAction->setProperty("menu priority", -250);*/

  updateActions();
}

Symmetry::~Symmetry()
{
  if (m_symmetryWidget)
    m_symmetryWidget->deleteLater();

  qDeleteAll(m_actions);
  m_actions.clear();

  if (m_ctx != nullptr) {
    msymReleaseContext(m_ctx);
  }
}

QList<QAction*> Symmetry::actions() const
{
  return m_actions;
}

QStringList Symmetry::menuPath(QAction*) const
{
  return QStringList() << tr("&Analyze") << tr("&Properties");
}

void Symmetry::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;
  if (m_symmetryWidget)
    m_symmetryWidget->setMolecule(m_molecule);

  if (m_molecule)
    connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

  updateActions();
  m_dirty = true;
}

void Symmetry::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  auto changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::Added || changes & Molecule::Removed)
    updateActions();
  /*
    if (changes & Molecule::UnitCell) {
      if (changes & Molecule::Added || changes & Molecule::Removed)
        updateActions();
    }*/

  if ((changes & Molecule::Atoms) &&
      (changes & Molecule::Modified || changes & Molecule::Added ||
       changes & Molecule::Removed)) {
    m_dirty = true;
  }
}

void Symmetry::updateActions()
{
  // Disable everything for NULL molecules.
  if (!m_molecule) {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
    return;
  } else {
    foreach (QAction* action, m_actions)
      action->setEnabled(true);
  }
  /*
    if (m_molecule->unitCell()) {
      foreach (QAction *action, m_actions)
        action->setEnabled(true);

      m_toggleUnitCellAction->setText(tr("Remove &Unit Cell"));
    }
    else {
      foreach (QAction *action, m_actions)
        action->setEnabled(false);

      m_toggleUnitCellAction->setEnabled(true);
      m_toggleUnitCellAction->setText(tr("Add &Unit Cell"));
    }*/
}

void Symmetry::viewSymmetry()
{
  if (!m_symmetryWidget) {
    m_symmetryWidget = new SymmetryWidget(qobject_cast<QWidget*>(parent()));
    m_symmetryWidget->setMolecule(m_molecule);
    connect(m_symmetryWidget, SIGNAL(detectSymmetry()), SLOT(detectSymmetry()));
    connect(m_symmetryWidget, SIGNAL(symmetrizeMolecule()),
            SLOT(symmetrizeMolecule()));
  }

  if (m_dirty) {
    detectSymmetry();
  }
  m_symmetryWidget->show();
  m_symmetryWidget->raise();
  m_symmetryWidget->activateWindow();
}

void Symmetry::clearSymmetryResults()
{
  if (m_symmetryWidget == nullptr)
    return;

  m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
  m_symmetryWidget->setEquivalenceSets(0, nullptr);
  m_symmetryWidget->setSymmetryOperations(0, nullptr);
  m_symmetryWidget->setSubgroups(0, nullptr);
}

msym_thresholds_t* Symmetry::thresholdsForName(const QString& name)
{
  const QString wanted = name.trimmed().toLower();

  if (wanted == QLatin1String("tight"))
    return &tight_thresholds;
  if (wanted == QLatin1String("normal") || wanted == QLatin1String("medium"))
    return &medium_thresholds;
  if (wanted == QLatin1String("loose"))
    return &loose_thresholds;
  if (wanted == QLatin1String("veryloose") ||
      wanted == QLatin1String("very loose") ||
      wanted == QLatin1String("sloppy"))
    return &sloppy_thresholds;

  return nullptr;
}

void Symmetry::detectSymmetry()
{
  runSymmetryDetection(nullptr, nullptr, nullptr);
}

bool Symmetry::runSymmetryDetection(msym_thresholds_t* thresholds,
                                    QString* pointGroup, QString* error)
{
  auto fail = [error](const QString& message) {
    if (error != nullptr)
      *error = message;
    return false;
  };

  // Note the order: this used to call atomCount() and only then test the
  // pointer, so a command arriving with no molecule would have crashed.
  if (m_molecule == nullptr) {
    clearSymmetryResults();
    return fail(tr("There is no molecule to analyze."));
  }

  const unsigned int length = m_molecule->atomCount();

  if (m_molecule->atomPositions3d().size() != length) {
    clearSymmetryResults();
    return fail(tr("The molecule has no 3D coordinates."));
  }

  if (length == 0) {
    clearSymmetryResults();
    return fail(tr("The molecule has no atoms."));
  }

  // A lone atom is spherically symmetric. This test used to sit below a
  // "length < 2" early return, so it could never run: a single atom left
  // whatever the previous molecule had detected on screen instead.
  if (length == 1) {
    // Clear first: libmsym is never consulted on this path, so the panel
    // would otherwise keep the previous molecule's equivalence sets,
    // operations and subgroups next to a Kh label. Order matters -- clearing
    // resets the point group to C1, so the label is written afterwards.
    clearSymmetryResults();
    if (m_symmetryWidget != nullptr)
      m_symmetryWidget->setPointGroupSymbol(QStringLiteral("K<sub>h</sub>"));
    if (pointGroup != nullptr)
      *pointGroup = QStringLiteral("Kh");
    m_dirty = false;
    return true;
  }

  // interface with libmsym
  msym_error_t ret = MSYM_SUCCESS;
  msym_element_t* elements = nullptr;
  char point_group[6];
  double cm[3], radius = 0.0;

  /* Do not free these variables */
  const msym_symmetry_operation_t* msops = nullptr;
  const msym_subgroup_t* msg = nullptr;
  const msym_equivalence_set_t* mes = nullptr;
  int mesl = 0, msgl = 0, msopsl = 0;

  // Every libmsym step below fails the same way. Collapsing the seven
  // copies of it is also what makes a run without the panel safe: each of
  // them used to set four fields on m_symmetryWidget with no null check,
  // and the widget only exists once the panel has been opened.
  auto libmsymFailed = [&](msym_error_t code) {
    clearSymmetryResults();
    const QString message =
      QStringLiteral("%1 %2").arg(QString::fromLatin1(msymErrorString(code)),
                                  QString::fromLatin1(msymGetErrorDetails()));
    qDebug() << "Symmetry error:" << message;
    return fail(message);
  };

  // initialize the c-style array of atom names and coordinates
  msym_element_t* a;
  a = (msym_element_t*)malloc(length * sizeof(msym_element_t));
  memset(a, 0, length * sizeof(msym_element_t));

  for (Index i = 0; i < length; ++i) {
    Vector3 ipos = m_molecule->atomPositions3d()[i];
    // this is yucky, but msym uses type <void*> for id :-(
    a[i].id = reinterpret_cast<void*>(i);
    a[i].n = m_molecule->atomicNumbers()[i];
    if (a[i].n < 1 || a[i].n > 118)
      a[i].n = 1; // pretend to be an H atom for libmsym
    a[i].v[0] = ipos[0];
    a[i].v[1] = ipos[1];
    a[i].v[2] = ipos[2];
  }
  elements = a;

  if (m_ctx != nullptr) {
    msymReleaseContext(m_ctx);
    m_ctx = msymCreateContext();
  }

  // Set the thresholds: the caller's preset, else the panel's combo, else
  // the value that combo starts on.
  msym_thresholds_t* activeThresholds = thresholds;
  if (activeThresholds == nullptr) {
    activeThresholds = m_symmetryWidget != nullptr
                         ? m_symmetryWidget->getThresholds()
                         : &tight_thresholds;
  }
  msymSetThresholds(m_ctx, activeThresholds);

  // At any point, we'll set the text to NULL which will use C1 instead

  if (MSYM_SUCCESS != (ret = msymSetElements(m_ctx, length, elements))) {
    free(elements);
    return libmsymFailed(ret);
  }

  if (MSYM_SUCCESS != (ret = msymFindSymmetry(m_ctx))) {
    free(elements);
    return libmsymFailed(ret);
  }

  /* Get the point group name */
  if (MSYM_SUCCESS !=
      (ret = msymGetPointGroupName(m_ctx, sizeof(char[6]), point_group))) {
    free(elements);
    return libmsymFailed(ret);
  }

  if (MSYM_SUCCESS !=
      (ret = msymGetSymmetryOperations(m_ctx, &msopsl, &msops))) {
    free(elements);
    return libmsymFailed(ret);
  }

  if (MSYM_SUCCESS != (ret = msymGetEquivalenceSets(m_ctx, &mesl, &mes))) {
    free(elements);
    return libmsymFailed(ret);
  }

  if (MSYM_SUCCESS != (ret = msymGetCenterOfMass(m_ctx, cm))) {
    free(elements);
    return libmsymFailed(ret);
  }

  if (MSYM_SUCCESS != (ret = msymGetRadius(m_ctx, &radius))) {
    free(elements);
    return libmsymFailed(ret);
  }

  if (point_group[1] != '0') {
    if (MSYM_SUCCESS != (ret = msymGetSubgroups(m_ctx, &msgl, &msg))) {
      free(elements);
      return libmsymFailed(ret);
    }
  }

  if (m_symmetryWidget != nullptr) {
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(point_group));
    m_symmetryWidget->setEquivalenceSets(mesl, mes);
    m_symmetryWidget->setSymmetryOperations(msopsl, msops);
    m_symmetryWidget->setSubgroups(msgl, msg);
    m_symmetryWidget->setCenterOfMass(cm);
    m_symmetryWidget->setRadius(radius);
  }

  if (pointGroup != nullptr)
    *pointGroup = pointGroupPlainText(point_group);

  qDebug() << "detected symmetry" << point_group;

  free(elements);
  m_dirty = false;
  return true;
}

void Symmetry::symmetrizeMolecule()
{
  runSymmetrize(nullptr, nullptr);
}

bool Symmetry::runSymmetrize(double* symmetryError, QString* error)
{
  auto fail = [error](const QString& message) {
    if (error != nullptr)
      *error = message;
    return false;
  };

  if (m_molecule == nullptr)
    return fail(tr("There is no molecule to symmetrize."));

  const unsigned int length = m_molecule->atomCount();

  if (m_molecule->atomPositions3d().size() != length)
    return fail(tr("The molecule has no 3D coordinates."));

  if (length < 2)
    return fail(tr("A single atom is already symmetric."));

  // The libmsym context carries the point group the atoms are snapped onto,
  // and only detection fills it in. The panel detects when it opens, but the
  // geometry can have changed since -- and a command may not have detected
  // at all, in which case the context is empty and libmsym would fail.
  if (m_dirty && !runSymmetryDetection(nullptr, nullptr, error))
    return false;

  msym_element_t* melements = nullptr;
  int mlength = 0;
  double symerr = 0.0;
  msym_error_t ret = MSYM_SUCCESS;

  if (MSYM_SUCCESS != (ret = msymSymmetrizeElements(m_ctx, &symerr)))
    return fail(QString::fromLatin1(msymErrorString(ret)));

  if (MSYM_SUCCESS != (ret = msymGetElements(m_ctx, &mlength, &melements)))
    return fail(QString::fromLatin1(msymErrorString(ret)));

  if (mlength != static_cast<int>(length))
    return fail(tr("libmsym returned %1 atoms for a molecule of %2.")
                  .arg(mlength)
                  .arg(length));

  Core::Array<Vector3> positions(length);
  for (Index i = 0; i < length; ++i)
    positions[i] = Vector3(melements[i].v);

  // Route the change through RWMolecule so it is one undo step, as the
  // ground rules for commands require. This used to assign the positions
  // directly, which left the user no way back.
  m_molecule->undoMolecule()->setAtomPositions3d(positions, tr("Symmetrize"));
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Modified);

  if (symmetryError != nullptr)
    *symmetryError = symerr;

  return true;
}

void Symmetry::registerCommands()
{
  emit registerCommand("detectSymmetry",
                       tr("Detect the point group of the molecule."));
  emit registerCommand("symmetrize",
                       tr("Snap the molecule onto its detected point group."));
}

bool Symmetry::handleCommand(const QString& command, const QVariantMap& options)
{
  const bool symmetrizeRequested = (command == "symmetrize");
  if (!symmetrizeRequested && command != "detectSymmetry")
    return false;

  // The panel offers four named tolerances rather than a number, and
  // libmsym wants a whole struct of seven thresholds, so the command names
  // a preset instead of inventing a scalar the GUI has no equivalent for.
  msym_thresholds_t* thresholds = nullptr;
  if (options.contains("tolerance")) {
    const QString name = options.value("tolerance").toString();
    thresholds = thresholdsForName(name);
    if (thresholds == nullptr) {
      emit commandFailed(tr("Unknown tolerance \"%1\": expected tight, "
                            "normal, loose or veryloose.")
                           .arg(name));
      return true;
    }
  }

  emit commandStarted();

  // Detection is the first half of both commands: it is what fills the
  // libmsym context that symmetrize then works from.
  QString pointGroup;
  QString error;
  if (!runSymmetryDetection(thresholds, &pointGroup, &error)) {
    emit commandFailed(error);
    return true;
  }

  QVariantMap result;
  result["pointGroup"] = pointGroup;

  if (!symmetrizeRequested) {
    emit commandFinished(tr("Detected %1").arg(pointGroup), result);
    return true;
  }

  double symmetryError = 0.0;
  if (!runSymmetrize(&symmetryError, &error)) {
    emit commandFailed(error);
    return true;
  }

  result["symmetryError"] = symmetryError;
  emit commandFinished(tr("Symmetrized to %1").arg(pointGroup), result);
  return true;
}

/*
void Symmetry::standardOrientation()
{
  CrystalTools::rotateToStandardOrientation(*m_molecule,
                                            CrystalTools::TransformAtoms);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);
}*/

} // namespace Avogadro::QtPlugins
