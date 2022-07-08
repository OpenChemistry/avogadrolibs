/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obforcefielddialog.h"
#include "ui_obforcefielddialog.h"

#include <QtCore/QDebug>
#include <QtCore/QSettings>
#include <QtCore/QString>
#include <QtCore/QStringList>

#include <cmath> // for log10

namespace Avogadro::QtPlugins {

enum OptimizationAlgorithm
{
  SteepestDescent = 0,
  ConjugateGradient
};

enum LineSearchMethod
{
  Simple = 0,
  Newton
};

OBForceFieldDialog::OBForceFieldDialog(const QStringList& forceFields,
                                       QWidget* parent_)
  : QDialog(parent_), ui(new Ui::OBForceFieldDialog)
{
  ui->setupUi(this);
  ui->forceField->addItems(forceFields);
  updateRecommendedForceField();

  connect(ui->useRecommended, SIGNAL(toggled(bool)),
          SLOT(useRecommendedForceFieldToggled(bool)));

  QSettings settings;
  bool autoDetect =
    settings.value("openbabel/optimizeGeometry/autoDetect", true).toBool();
  ui->useRecommended->setChecked(autoDetect);
}

OBForceFieldDialog::~OBForceFieldDialog()
{
  delete ui;
}

QStringList OBForceFieldDialog::prompt(QWidget* parent_,
                                       const QStringList& forceFields,
                                       const QStringList& startingOptions,
                                       const QString& recommendedForceField_)
{
  OBForceFieldDialog dlg(forceFields, parent_);
  dlg.setOptions(startingOptions);
  dlg.setRecommendedForceField(recommendedForceField_);

  QStringList options;
  if (static_cast<DialogCode>(dlg.exec()) == Accepted)
    options = dlg.options();

  return options;
}

QStringList OBForceFieldDialog::options() const
{
  QStringList opts;

  opts << "--crit"
       << QString::number(std::pow(10.0f, ui->energyConv->value()), 'e', 0)
       << "--ff" << ui->forceField->currentText() << "--steps"
       << QString::number(ui->stepLimit->value()) << "--rvdw"
       << QString::number(ui->vdwCutoff->value()) << "--rele"
       << QString::number(ui->eleCutoff->value()) << "--freq"
       << QString::number(ui->pairFreq->value());

  switch (static_cast<OptimizationAlgorithm>(ui->algorithm->currentIndex())) {
    case SteepestDescent:
      opts << "--sd";
      break;
    default:
    case ConjugateGradient:
      break;
  }

  switch (static_cast<LineSearchMethod>(ui->lineSearch->currentIndex())) {
    case Newton:
      opts << "--newton";
      break;
    default:
    case Simple:
      break;
  }

  if (ui->enableCutoffs->isChecked())
    opts << "--cut";

  return opts;
}

void OBForceFieldDialog::setOptions(const QStringList& opts)
{
  // Set some defaults. These match the defaults in obabel -L minimize
  ui->energyConv->setValue(-6);
  ui->algorithm->setCurrentIndex(static_cast<int>(ConjugateGradient));
  ui->lineSearch->setCurrentIndex(static_cast<int>(Simple));
  ui->stepLimit->setValue(2500);
  ui->enableCutoffs->setChecked(false);
  ui->vdwCutoff->setValue(10.0);
  ui->eleCutoff->setValue(10.0);
  ui->pairFreq->setValue(10);

  for (QStringList::const_iterator it = opts.constBegin(),
                                   itEnd = opts.constEnd();
       it < itEnd; ++it) {

    // We'll always use log:
    if (*it == "--log") {
      continue;
    }

    // Energy convergence:
    else if (*it == "--crit") {
      ++it;
      if (it == itEnd) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--crit missing argument.";
        continue;
      }

      bool ok;
      float econv = it->toFloat(&ok);
      if (!ok) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--crit is not numeric: "
                   << *it;
        continue;
      }

      // We just show the econv as 10^(x), so calculate the nearest x
      int exponent = static_cast<int>(std::floor(std::log10(econv) + 0.5));
      ui->energyConv->setValue(exponent);
      continue;
    }

    // Use steepest descent?
    else if (*it == "--sd") {
      ui->algorithm->setCurrentIndex(SteepestDescent);
      continue;
    }

    // Use newton linesearch?
    else if (*it == "--newton") {
      ui->lineSearch->setCurrentIndex(Newton);
      continue;
    }

    // Force field?
    else if (*it == "--ff") {
      ++it;
      if (it == itEnd) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--ff missing argument.";
        continue;
      }

      int index = ui->forceField->findText(*it);
      if (index < 0) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--ff unknown: "
                   << *it;
        continue;
      }

      ui->forceField->setCurrentIndex(index);
      continue;
    }

    // Step limit?
    else if (*it == "--steps") {
      ++it;
      if (it == itEnd) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--steps missing argument.";
        continue;
      }

      bool ok;
      int numSteps = it->toInt(&ok);
      if (!ok) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--steps is not numeric: "
                   << *it;
        continue;
      }

      ui->stepLimit->setValue(numSteps);
      continue;
    }

    // Use cutoff?
    else if (*it == "--cut") {
      ui->enableCutoffs->setChecked(true);
      continue;
    }

    // Van der Waals cutoff
    else if (*it == "--rvdw") {
      ++it;
      if (it == itEnd) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--rvdw missing argument.";
        continue;
      }

      bool ok;
      double cutoff = it->toDouble(&ok);
      if (!ok) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--rvdw is not numeric: "
                   << *it;
        continue;
      }

      ui->vdwCutoff->setValue(cutoff);
      continue;
    }

    // electrostatic cutoff
    else if (*it == "--rele") {
      ++it;
      if (it == itEnd) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--rele missing argument.";
        continue;
      }

      bool ok;
      double cutoff = it->toDouble(&ok);
      if (!ok) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--rele is not numeric: "
                   << *it;
        continue;
      }

      ui->eleCutoff->setValue(cutoff);
      continue;
    }

    // Pair update frequency:
    else if (*it == "--freq") {
      ++it;
      if (it == itEnd) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--freq missing argument.";
        continue;
      }

      bool ok;
      int numSteps = it->toInt(&ok);
      if (!ok) {
        qWarning() << "OBForceFieldDialog::setOptions: "
                      "--freq is not numeric: "
                   << *it;
        continue;
      }

      ui->pairFreq->setValue(numSteps);
      continue;
    }

    // ?????
    else {
      qWarning() << "OBForceFieldDialog::setOptions: "
                    "Unrecognized option: "
                 << *it;
    }
  }
}

void OBForceFieldDialog::setRecommendedForceField(const QString& rff)
{
  if (rff == m_recommendedForceField)
    return;

  if (ui->forceField->findText(rff) == -1)
    return;

  m_recommendedForceField = rff;
  updateRecommendedForceField();
}

void OBForceFieldDialog::useRecommendedForceFieldToggled(bool state)
{
  if (!m_recommendedForceField.isEmpty()) {
    if (state) {
      int index = ui->forceField->findText(m_recommendedForceField);
      if (index >= 0) {
        ui->forceField->setCurrentIndex(index);
      }
    }
  }
  ui->forceField->setEnabled(!state);

  QSettings().setValue("openbabel/optimizeGeometry/autoDetect", state);
}

void OBForceFieldDialog::updateRecommendedForceField()
{
  if (m_recommendedForceField.isEmpty()) {
    ui->useRecommended->hide();
    ui->forceField->setEnabled(true);
  } else {
    ui->useRecommended->setText(
      tr("Autodetect (%1)").arg(m_recommendedForceField));
    // Force the combo box to update if needed:
    useRecommendedForceFieldToggled(ui->useRecommended->isChecked());
    ui->useRecommended->show();
  }
}

} // namespace Avogadro
