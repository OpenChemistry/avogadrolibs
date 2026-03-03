/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "forcefielddialog.h"
#include "ui_forcefielddialog.h"

#include <avogadro/qtgui/jsonwidget.h>

#include <QtCore/QDebug>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonParseError>
#include <QtCore/QSettings>
#include <QtCore/QString>
#include <QtCore/QStringList>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

#include <cmath> // for log10

namespace Avogadro {
namespace QtPlugins {

namespace {
// Minimal JsonWidget subclass that renders a fixed options schema with no
// backing script. The schema must be the flat "userOptions" object (not
// wrapped in an outer object).
class SchemaWidget : public QtGui::JsonWidget
{
public:
  explicit SchemaWidget(const QJsonObject& schema, QWidget* parent = nullptr)
    : QtGui::JsonWidget(parent)
  {
    m_options.insert(QStringLiteral("userOptions"), schema);
    updateOptions();
  }
};
} // namespace

ForceFieldDialog::ForceFieldDialog(const QStringList& forceFields,
                                   QWidget* parent_)
  : QDialog(parent_), ui(new Ui::ForceFieldDialog)
{
  ui->setupUi(this);
  ui->forceField->addItems(forceFields);
  updateRecommendedForceField();

  m_optionsButton = new QPushButton(tr("Options…"), this);
  ui->formLayout->setWidget(2, QFormLayout::FieldRole, m_optionsButton);

  connect(ui->useRecommended, &QCheckBox::toggled, this,
          &ForceFieldDialog::useRecommendedForceFieldToggled);
  connect(ui->forceField, &QComboBox::currentTextChanged, this,
          &ForceFieldDialog::updateOptionsButton);
  connect(m_optionsButton, &QPushButton::clicked, this,
          &ForceFieldDialog::modelOptionsClicked);

  QSettings settings;
  bool autoDetect =
    settings.value("openbabel/optimizeGeometry/autoDetect", true).toBool();
  ui->useRecommended->setChecked(autoDetect);
  updateOptionsButton();
}

ForceFieldDialog::~ForceFieldDialog()
{
  delete ui;
}

QVariantMap ForceFieldDialog::prompt(QWidget* parent_,
                                     const QStringList& forceFields,
                                     const QVariantMap& startingOptions,
                                     const QString& recommendedForceField_)
{
  ForceFieldDialog dlg(forceFields, parent_);
  dlg.setOptions(startingOptions);
  dlg.setRecommendedForceField(recommendedForceField_);

  QVariantMap options;
  if (dlg.exec() == QDialog::Accepted)
    options = dlg.options();

  return options;
}

QVariantMap ForceFieldDialog::options() const
{
  QVariantMap opts;

  opts["forcefield"] = ui->forceField->currentText();
  opts["maxSteps"] = ui->stepLimit->value();
  opts["tolerance"] = pow(10, ui->energyConv->value());
  opts["gradientTolerance"] = pow(10, ui->gradConv->value());
  opts["autodetect"] = ui->useRecommended->isChecked();
  opts["modelUserOptions"] = m_modelUserOptions;

  return opts;
}

void ForceFieldDialog::setOptions(const QVariantMap& opts)
{
  if (opts.contains("modelUserOptionsSchemas") &&
      opts["modelUserOptionsSchemas"].canConvert<QVariantMap>()) {
    m_modelUserOptionSchemas = opts["modelUserOptionsSchemas"].toMap();
  }
  if (opts.contains("modelUserOptions") &&
      opts["modelUserOptions"].canConvert<QVariantMap>()) {
    m_modelUserOptions = opts["modelUserOptions"].toMap();
  }

  if (opts.contains("forcefield") && opts["forcefield"].canConvert<QString>())
    ui->forceField->setCurrentText(opts["forcefield"].toString());
  if (opts.contains("maxSteps") && opts["maxSteps"].canConvert<int>())
    ui->stepLimit->setValue(opts["maxSteps"].toInt());
  if (opts.contains("tolerance") && opts["tolerance"].canConvert<double>())
    ui->energyConv->setValue(log10(opts["tolerance"].toDouble()));
  if (opts.contains("gradientTolerance") &&
      opts["gradientTolerance"].canConvert<double>())
    ui->gradConv->setValue(log10(opts["gradientTolerance"].toDouble()));
  if (opts.contains("autodetect") && opts["autodetect"].canConvert<bool>())
    ui->useRecommended->setChecked(opts["autodetect"].toBool());

  updateOptionsButton();
}

void ForceFieldDialog::setRecommendedForceField(const QString& rff)
{
  if (rff == m_recommendedForceField)
    return;

  if (ui->forceField->findText(rff) == -1)
    return;

  m_recommendedForceField = rff;
  updateRecommendedForceField();
}

void ForceFieldDialog::useRecommendedForceFieldToggled(bool state)
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
  updateOptionsButton();

  QSettings().setValue("forcefield/autoDetect", state);
}

void ForceFieldDialog::modelOptionsClicked()
{
  const QString forceField = ui->forceField->currentText();
  const QString schemaJson =
    m_modelUserOptionSchemas.value(forceField).toString().trimmed();
  if (schemaJson.isEmpty())
    return;

  QJsonParseError parseError;
  const QJsonDocument schemaDoc =
    QJsonDocument::fromJson(schemaJson.toUtf8(), &parseError);
  if (parseError.error != QJsonParseError::NoError || !schemaDoc.isObject()) {
    QMessageBox::warning(
      this, tr("Invalid Model Options"),
      tr("Could not parse user options for model '%1'.").arg(forceField));
    return;
  }

  QDialog dlg(this);
  dlg.setWindowTitle(tr("%1 Options").arg(forceField));
  auto* layout = new QVBoxLayout(&dlg);
  auto* widget = new SchemaWidget(schemaDoc.object(), &dlg);

  const QString valuesJson = m_modelUserOptions.value(forceField).toString();
  if (!valuesJson.trimmed().isEmpty()) {
    QJsonParseError valueParseError;
    const QJsonDocument valueDoc =
      QJsonDocument::fromJson(valuesJson.toUtf8(), &valueParseError);
    if (valueParseError.error == QJsonParseError::NoError &&
        valueDoc.isObject()) {
      widget->applyOptions(valueDoc.object());
    }
  }

  layout->addWidget(widget);
  auto* buttonBox = new QDialogButtonBox(
    QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, &dlg);
  connect(buttonBox, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  connect(buttonBox, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
  layout->addWidget(buttonBox);

  if (dlg.exec() != QDialog::Accepted)
    return;

  const QJsonObject collected = widget->collectOptions();
  if (collected.isEmpty()) {
    m_modelUserOptions.remove(forceField);
  } else {
    m_modelUserOptions[forceField] = QString::fromUtf8(
      QJsonDocument(collected).toJson(QJsonDocument::Compact));
  }
}

void ForceFieldDialog::updateRecommendedForceField()
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

void ForceFieldDialog::updateOptionsButton()
{
  if (m_optionsButton == nullptr)
    return;

  const QString forceField = ui->forceField->currentText();
  const QString schemaJson =
    m_modelUserOptionSchemas.value(forceField).toString().trimmed();
  m_optionsButton->setEnabled(!schemaJson.isEmpty());
}

} // namespace QtPlugins
} // namespace Avogadro
