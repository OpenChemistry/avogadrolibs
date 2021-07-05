/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "symmetry.h"

#include "symmetrywidget.h"

#include "symmetryutil.h"

//#include <avogadro/core/unitcell.h>
//#include <avogadro/core/crystaltools.h>

#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

#include <QtCore/QDebug>
#include <QtCore/QStringList>

// using Avogadro::Core::CrystalTools;
// using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

using namespace msym;
using namespace Avogadro::QtPlugins::SymmetryUtil;

namespace Avogadro {
namespace QtPlugins {

Symmetry::Symmetry(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_)
  , m_molecule(nullptr)
  , m_symmetryWidget(nullptr)
  , m_viewSymmetryAction(new QAction(this))
{

  m_ctx = msymCreateContext();

  m_viewSymmetryAction->setText(tr("Symmetry..."));
  connect(m_viewSymmetryAction, SIGNAL(triggered()), SLOT(viewSymmetry()));
  m_actions.push_back(m_viewSymmetryAction);
  m_viewSymmetryAction->setProperty("menu priority", -50);

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
  return QStringList() << tr("&Analysis") << tr("&Properties");
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

  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);

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
    connect(m_symmetryWidget,
            SIGNAL(symmetrizeMolecule()),
            SLOT(symmetrizeMolecule()));
  }

  if (m_dirty) {
    detectSymmetry();
  }
  m_symmetryWidget->show();
}

void Symmetry::detectSymmetry()
{

  unsigned int length = m_molecule->atomCount();

  if (m_molecule == nullptr || m_molecule->atomPositions3d().size() != length ||
      length < 2)
    return; // if one atom = Kh

  if (length == 1) {
    m_symmetryWidget->setPointGroupSymbol(QString("K<sub>h</sub>"));
    return;
  }

  // interface with libmsym
  msym_error_t ret = MSYM_SUCCESS;
  msym_element_t* elements = nullptr;
  const char* error = nullptr;
  char point_group[6];
  double cm[3], radius = 0.0, symerr = 0.0;

  /* Do not free these variables */
  const msym_symmetry_operation_t* msops = nullptr;
  const msym_subgroup_t* msg = nullptr;
  const msym_equivalence_set_t* mes = nullptr;
  int mesl = 0, msgl = 0, msopsl = 0, mlength = 0;

  // initialize the c-style array of atom names and coordinates
  msym_element_t* a;
  a = (msym_element_t*)malloc(length * sizeof(msym_element_t));
  memset(a, 0, length * sizeof(msym_element_t));

  for (Index i = 0; i < length; ++i) {
    Vector3 ipos = m_molecule->atomPositions3d()[i];
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

  // Set the thresholds
  // switch (m_dock->toleranceCombo->currentIndex()) {
  msym_thresholds_t* thresholds = m_symmetryWidget->getThresholds();
  msymSetThresholds(m_ctx, thresholds);

  // At any point, we'll set the text to NULL which will use C1 instead

  if (MSYM_SUCCESS != (ret = msymSetElements(m_ctx, length, elements))) {
    free(elements);
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
    m_symmetryWidget->setEquivalenceSets(0, nullptr);
    m_symmetryWidget->setSymmetryOperations(0, nullptr);
    m_symmetryWidget->setSubgroups(0, nullptr);
    qDebug() << "Error:" << msymErrorString(ret) << " "
             << msymGetErrorDetails();
    return;
  }

  if (MSYM_SUCCESS != (ret = msymFindSymmetry(m_ctx))) {
    free(elements);
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
    m_symmetryWidget->setEquivalenceSets(0, nullptr);
    m_symmetryWidget->setSymmetryOperations(0, nullptr);
    m_symmetryWidget->setSubgroups(0, nullptr);
    qDebug() << "Error:" << msymErrorString(ret) << " "
             << msymGetErrorDetails();
    return;
  }

  /* Get the point group name */
  if (MSYM_SUCCESS !=
      (ret = msymGetPointGroupName(m_ctx, sizeof(char[6]), point_group))) {
    free(elements);
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
    m_symmetryWidget->setEquivalenceSets(0, nullptr);
    m_symmetryWidget->setSymmetryOperations(0, nullptr);
    m_symmetryWidget->setSubgroups(0, nullptr);
    qDebug() << "Error:" << msymErrorString(ret) << " "
             << msymGetErrorDetails();
    return;
  }

  if (MSYM_SUCCESS !=
      (ret = msymGetSymmetryOperations(m_ctx, &msopsl, &msops))) {
    free(elements);
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
    m_symmetryWidget->setEquivalenceSets(0, nullptr);
    m_symmetryWidget->setSymmetryOperations(0, nullptr);
    m_symmetryWidget->setSubgroups(0, nullptr);
    qDebug() << "Error:" << msymErrorString(ret) << " "
             << msymGetErrorDetails();
    return;
  }

  if (MSYM_SUCCESS != (ret = msymGetEquivalenceSets(m_ctx, &mesl, &mes))) {
    free(elements);
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
    m_symmetryWidget->setEquivalenceSets(0, nullptr);
    m_symmetryWidget->setSymmetryOperations(0, nullptr);
    m_symmetryWidget->setSubgroups(0, nullptr);
    qDebug() << "Error:" << msymErrorString(ret) << " "
             << msymGetErrorDetails();
    return;
  }

  if (MSYM_SUCCESS != (ret = msymGetCenterOfMass(m_ctx, cm))) {
    free(elements);
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
    m_symmetryWidget->setEquivalenceSets(0, nullptr);
    m_symmetryWidget->setSymmetryOperations(0, nullptr);
    m_symmetryWidget->setSubgroups(0, nullptr);
    qDebug() << "Error:" << msymErrorString(ret) << " "
             << msymGetErrorDetails();
    return;
  }

  if (MSYM_SUCCESS != (ret = msymGetRadius(m_ctx, &radius))) {
    free(elements);
    m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
    m_symmetryWidget->setEquivalenceSets(0, nullptr);
    m_symmetryWidget->setSymmetryOperations(0, nullptr);
    m_symmetryWidget->setSubgroups(0, nullptr);
    qDebug() << "Error:" << msymErrorString(ret) << " "
             << msymGetErrorDetails();
    return;
  }

  if (point_group[1] != '0') {
    if (MSYM_SUCCESS != (ret = msymGetSubgroups(m_ctx, &msgl, &msg))) {
      free(elements);
      m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(nullptr));
      m_symmetryWidget->setEquivalenceSets(0, nullptr);
      m_symmetryWidget->setSymmetryOperations(0, nullptr);
      m_symmetryWidget->setSubgroups(0, nullptr);
      qDebug() << "Error:" << msymErrorString(ret) << " "
               << msymGetErrorDetails();
      return;
    }
  } else {
    m_symmetryWidget->setSubgroups(0, nullptr);
  }

  // TODO: Subgroups
  // if(MSYM_SUCCESS != (ret = msymGetSubgroups(ctx, &msgl, &msg))) goto err;
  //    printf("Found point group [0] %s select subgroup\n",point_group);
  // for(int i = 0; i < msgl;i++) printf("\t [%d] %s\n",i+1,msg[i].name);

  m_symmetryWidget->setPointGroupSymbol(pointGroupSymbol(point_group));
  m_symmetryWidget->setEquivalenceSets(mesl, mes);
  m_symmetryWidget->setSymmetryOperations(msopsl, msops);
  m_symmetryWidget->setSubgroups(msgl, msg);
  m_symmetryWidget->setCenterOfMass(cm);
  m_symmetryWidget->setRadius(radius);
  // m_symmetryWidget->m_ui->pointGroupLabel->setText(pgSymbol(point_group));

  qDebug() << "detected symmetry" << point_group;

  free(elements);
  m_dirty = false;
}

void Symmetry::symmetrizeMolecule()
{
  qDebug() << "symmetrize";
  unsigned int length = m_molecule->atomCount();

  if (m_molecule == nullptr || m_molecule->atomPositions3d().size() != length ||
      length < 2)
    return; // if one atom = Kh

  msym_element_t* melements = nullptr;
  int mlength = 0;
  double symerr = 0.0;
  msym_error_t ret = MSYM_SUCCESS;

  // detectSymmetry();
  if (MSYM_SUCCESS != (ret = msymSymmetrizeElements(m_ctx, &symerr)))
    return;

  if (MSYM_SUCCESS != (ret = msymGetElements(m_ctx, &mlength, &melements)))
    return;

  if (mlength != length)
    return;

  for (Index i = 0; i < length; ++i) {
    m_molecule->atomPositions3d()[i] = Vector3(melements[i].v);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Modified);
}

/*
void Symmetry::standardOrientation()
{
  CrystalTools::rotateToStandardOrientation(*m_molecule,
                                            CrystalTools::TransformAtoms);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);
}*/

} // namespace QtPlugins
} // namespace Avogadro
