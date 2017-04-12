/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "unitcelldialog.h"
#include "ui_unitcelldialog.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/unitcell.h>

#include <QtWidgets/QPlainTextEdit>

#include <QtCore/QRegExp>

using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace {
// Matrix formatting:
const int MATRIX_WIDTH = 9;
const int MATRIX_PREC = 5;
const char MATRIX_FMT = 'f';

// Valid value separators in matrix editors:
const static QRegExp MATRIX_SEP(
  "\\s|,|;|\\||\\[|\\]|\\{|\\}|\\(|\\)|\\&|/|<|>");
}

namespace Avogadro {
namespace QtPlugins {

UnitCellDialog::UnitCellDialog(QWidget* p)
  : QDialog(p), m_ui(new Ui::UnitCellDialog), m_molecule(nullptr),
    m_mode(Invalid)
{
  m_ui->setupUi(this);

  connect(m_ui->a, SIGNAL(valueChanged(double)), SLOT(parametersEdited()));
  connect(m_ui->b, SIGNAL(valueChanged(double)), SLOT(parametersEdited()));
  connect(m_ui->c, SIGNAL(valueChanged(double)), SLOT(parametersEdited()));
  connect(m_ui->alpha, SIGNAL(valueChanged(double)), SLOT(parametersEdited()));
  connect(m_ui->beta, SIGNAL(valueChanged(double)), SLOT(parametersEdited()));
  connect(m_ui->gamma, SIGNAL(valueChanged(double)), SLOT(parametersEdited()));

  connect(m_ui->cellMatrix, SIGNAL(textChanged()), SLOT(cellMatrixEdited()));

  connect(m_ui->fractionalMatrix, SIGNAL(textChanged()),
          SLOT(fractionalMatrixEdited()));

  connect(m_ui->apply, SIGNAL(clicked()), SLOT(apply()));
  connect(m_ui->revert, SIGNAL(clicked()), SLOT(revert()));
}

UnitCellDialog::~UnitCellDialog()
{
  delete m_ui;
}

void UnitCellDialog::setMolecule(QtGui::Molecule* molecule)
{
  if (molecule != m_molecule) {
    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = molecule;

    if (m_molecule)
      connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

    revert();
  }
}

void UnitCellDialog::moleculeChanged(unsigned int changes)
{
  if (changes & Molecule::UnitCell)
    revert();
}

void UnitCellDialog::parametersEdited()
{
  setMode(Parameters);
  updateParameters();
  revertCellMatrix();
  revertFractionalMatrix();
}

void UnitCellDialog::cellMatrixEdited()
{
  setMode(CellMatrix);
  if (validateCellMatrix()) {
    updateCellMatrix();
    revertParameters();
    revertFractionalMatrix();
    enableApply(true);
  } else {
    enableApply(false);
  }
}

void UnitCellDialog::fractionalMatrixEdited()
{
  setMode(FractionalMatrix);
  if (validateFractionalMatrix()) {
    updateFractionalMatrix();
    revertParameters();
    revertCellMatrix();
    enableApply(true);
  } else {
    enableApply(false);
  }
}

void UnitCellDialog::apply()
{
  if (!isCrystal()) {
    revert();
    return;
  }

  switch (m_mode) {
    case Invalid:
    case Clean:
      revert();
      break;
    default: {
      Core::CrystalTools::Options options = Core::CrystalTools::None;
      if (m_ui->transformAtoms->isChecked())
        options |= Core::CrystalTools::TransformAtoms;
      m_molecule->undoMolecule()->editUnitCell(m_tempCell.cellMatrix(),
                                               options);
      break;
    }
  }
}

void UnitCellDialog::revert()
{
  if (isCrystal())
    m_tempCell = *m_molecule->unitCell();

  revertParameters();
  revertCellMatrix();
  validateCellMatrix();
  revertFractionalMatrix();
  validateFractionalMatrix();

  setMode(isCrystal() ? Clean : Invalid);
}

bool UnitCellDialog::isCrystal() const
{
  return m_molecule && m_molecule->unitCell();
}

void UnitCellDialog::setMode(UnitCellDialog::Mode m)
{
  if (m != m_mode) {
    m_mode = m;
    enableParameters(m == Clean || m == Parameters);
    enableCellMatrix(m == Clean || m == CellMatrix);
    enableFractionalMatrix(m == Clean || m == FractionalMatrix);
    enableApply(m != Clean && m != Invalid);
    enableRevert(m != Clean && m != Invalid);
  }
}

void UnitCellDialog::enableParameters(bool e)
{
  m_ui->a->setEnabled(e);
  m_ui->b->setEnabled(e);
  m_ui->c->setEnabled(e);
  m_ui->alpha->setEnabled(e);
  m_ui->beta->setEnabled(e);
  m_ui->gamma->setEnabled(e);
}

void UnitCellDialog::enableCellMatrix(bool e)
{
  m_ui->cellMatrix->setEnabled(e);
}

void UnitCellDialog::enableFractionalMatrix(bool e)
{
  m_ui->fractionalMatrix->setEnabled(e);
}

void UnitCellDialog::enableApply(bool e)
{
  m_ui->apply->setEnabled(e);
}

void UnitCellDialog::enableRevert(bool e)
{
  m_ui->revert->setEnabled(e);
}

void UnitCellDialog::blockParametersSignals(bool e)
{
  m_ui->a->blockSignals(e);
  m_ui->b->blockSignals(e);
  m_ui->c->blockSignals(e);
  m_ui->alpha->blockSignals(e);
  m_ui->beta->blockSignals(e);
  m_ui->gamma->blockSignals(e);
}

void UnitCellDialog::blockCellMatrixSignals(bool e)
{
  m_ui->cellMatrix->blockSignals(e);
}

void UnitCellDialog::blockFractionalMatrixSignals(bool e)
{
  m_ui->fractionalMatrix->blockSignals(e);
}

void UnitCellDialog::revertParameters()
{
  blockParametersSignals(true);
  if (isCrystal()) {
    m_ui->a->setValue(static_cast<double>(m_tempCell.a()));
    m_ui->b->setValue(static_cast<double>(m_tempCell.b()));
    m_ui->c->setValue(static_cast<double>(m_tempCell.c()));
    m_ui->alpha->setValue(static_cast<double>(m_tempCell.alpha() * RAD_TO_DEG));
    m_ui->beta->setValue(static_cast<double>(m_tempCell.beta() * RAD_TO_DEG));
    m_ui->gamma->setValue(static_cast<double>(m_tempCell.gamma() * RAD_TO_DEG));
  } else {
    enableParameters(false);
    m_ui->a->setValue(3.);
    m_ui->b->setValue(3.);
    m_ui->c->setValue(3.);
    m_ui->alpha->setValue(90.);
    m_ui->beta->setValue(90.);
    m_ui->gamma->setValue(90.);
  }
  blockParametersSignals(false);
}

void UnitCellDialog::revertCellMatrix()
{
  blockCellMatrixSignals(true);
  if (isCrystal()) {
    m_ui->cellMatrix->setPlainText(matrixToString(m_tempCell.cellMatrix()));
  } else {
    enableCellMatrix(false);
    m_ui->cellMatrix->setPlainText(tr("No unit cell present."));
  }
  blockCellMatrixSignals(false);
}

void UnitCellDialog::revertFractionalMatrix()
{
  blockFractionalMatrixSignals(true);
  if (isCrystal()) {
    m_ui->fractionalMatrix->setPlainText(
      matrixToString(m_tempCell.fractionalMatrix()));
  } else {
    enableFractionalMatrix(false);
    m_ui->fractionalMatrix->setPlainText(tr("No unit cell present."));
  }
  blockFractionalMatrixSignals(false);
}

void UnitCellDialog::updateParameters()
{
  m_tempCell.setCellParameters(
    static_cast<Real>(m_ui->a->value()), static_cast<Real>(m_ui->b->value()),
    static_cast<Real>(m_ui->c->value()),
    static_cast<Real>(m_ui->alpha->value()) * DEG_TO_RAD,
    static_cast<Real>(m_ui->beta->value()) * DEG_TO_RAD,
    static_cast<Real>(m_ui->gamma->value()) * DEG_TO_RAD);
}

void UnitCellDialog::updateCellMatrix()
{
  m_tempCell.setCellMatrix(stringToMatrix(m_ui->cellMatrix->toPlainText()));
}

void UnitCellDialog::updateFractionalMatrix()
{
  m_tempCell.setFractionalMatrix(
    stringToMatrix(m_ui->fractionalMatrix->toPlainText()));
}

bool UnitCellDialog::validateCellMatrix()
{
  return validateMatrixEditor(m_ui->cellMatrix);
}

bool UnitCellDialog::validateFractionalMatrix()
{
  return validateMatrixEditor(m_ui->fractionalMatrix);
}

void UnitCellDialog::initializeMatrixEditor(QPlainTextEdit* edit)
{
#if defined(Q_OS_WIN) || defined(Q_OS_OSX)
  QFont font("Courier");
#else
  QFont font("Monospace");
#endif
  edit->setFont(font);

  QFontMetrics metrics(font);
  int minWidth = 3 * metrics.width('0') * (MATRIX_WIDTH + 1);
  int minHeight = metrics.lineSpacing() * 3;

  edit->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Minimum);
  edit->setMinimumSize(minWidth, minHeight);
}

bool UnitCellDialog::validateMatrixEditor(QPlainTextEdit* edit)
{
  bool valid = stringToMatrix(edit->toPlainText()) != Matrix3::Zero();
  QPalette pal = edit->palette();
  pal.setColor(QPalette::Text, valid ? Qt::black : Qt::red);
  edit->setPalette(pal);
  return valid;
}

QString UnitCellDialog::matrixToString(const Matrix3& mat)
{
  // Transpose into the more intuitive row-vector format.
  return QString("%1 %2 %3\n%4 %5 %6\n%7 %8 %9")
    .arg(static_cast<double>(mat(0, 0)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(1, 0)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(2, 0)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(0, 1)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(1, 1)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(2, 1)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(0, 2)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(1, 2)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC)
    .arg(static_cast<double>(mat(2, 2)), MATRIX_WIDTH, MATRIX_FMT, MATRIX_PREC);
}

Matrix3 UnitCellDialog::stringToMatrix(const QString& str)
{
  Matrix3 result;
  QStringList lines = str.split('\n');
  if (lines.size() != 3)
    return Matrix3::Zero();

  bool ok;
  int row = 0;
  int col = 0;
  foreach (const QString& line, lines) {
    QStringList values = line.split(MATRIX_SEP, QString::SkipEmptyParts);
    if (values.size() != 3)
      return Matrix3::Zero();

    foreach (const QString& value, values) {
      Real val = static_cast<Real>(value.toDouble(&ok));
      if (!ok)
        return Matrix3::Zero();

      // Transpose from the more intuitive row-vector format.
      result(col++, row) = val;
    }
    row++;
    col = 0;
  }

  return result;
}

} // namespace QtPlugins
} // namespace Avogadro
