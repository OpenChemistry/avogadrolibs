/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "jsonwidget.h"

#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTextEdit>

#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QPointer>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

namespace Avogadro {
namespace QtGui {

JsonWidget::JsonWidget(QWidget* parent_)
  : QWidget(parent_), m_molecule(nullptr), m_currentLayout(nullptr),
    m_centralWidget(nullptr)
{}

JsonWidget::~JsonWidget() {}

void JsonWidget::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;
}

QString JsonWidget::lookupOptionType(const QString& name) const
{
  if (!m_options.contains("userOptions")) {
    qWarning() << tr("'userOptions' missing.");
    return QString();
  }

  QJsonObject userOptions;

  // if we have tabs, then userOptions is an array of objects
  // need to loop through to find the right one
  unsigned int size;
  bool isArray = m_options["userOptions"].isArray();
  QJsonArray options;
  if (isArray) {
    size = m_options["userOptions"].toArray().size();
    options = m_options["userOptions"].toArray();
  } else
    size = 1;

  for (unsigned int i = 0; i < size; ++i) {
    if (isArray) {
      userOptions = options.at(i).toObject();
    } else if (m_options["userOptions"].isObject()) {
      userOptions = m_options["userOptions"].toObject();
    } else {
      break;
    }

    if (!userOptions.contains(name)) {
      continue; // look in next tab
    }

    if (!userOptions.value(name).isObject()) {
      qWarning() << tr("Option '%1' does not refer to an object.").arg(name);
      return QString();
    }

    QJsonObject obj = userOptions[name].toObject();

    if (!obj.contains("type") || !obj.value("type").isString()) {
      qWarning() << tr("'type' is not a string for option '%1'.").arg(name);
      return QString();
    }

    return obj["type"].toString();
  }

  qWarning() << tr("Could not find option '%1'.").arg(name);
  return QString();
}

void JsonWidget::updateOptions()
{
  // Create the widgets, etc for the gui
  if (!m_centralWidget) {
    m_centralWidget = this;
  }
  buildOptionGui();
  setOptionDefaults();
}

void JsonWidget::buildOptionGui()
{
  if (m_centralWidget == nullptr)
    return;

  m_widgets.clear();
  delete m_centralWidget->layout();

  if (!m_options.contains("userOptions")) {
    return;
  }

  // if we have an array, we'll create tabs for each
  QTabWidget* tabs = nullptr;
  QWidget* currentPage = nullptr;

  // Create new widgets
  QJsonObject userOptions;
  unsigned int size;
  bool isArray = m_options["userOptions"].isArray();
  QJsonArray options;
  if (isArray) {
    size = m_options["userOptions"].toArray().size();
    options = m_options["userOptions"].toArray();

    // create a layout for inserting the tabs
    tabs = new QTabWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->addWidget(tabs);
    m_centralWidget->setLayout(layout);
  } else {
    size = 1;

    // create the form layout for the widget
    QFormLayout* layout = new QFormLayout();
    m_currentLayout = layout;
    m_centralWidget->setLayout(layout);
  }

  for (unsigned int i = 0; i < size; ++i) {
    QString tabName = tr("Tab %1").arg(i + 1); // default
    if (isArray) {
      userOptions = options.at(i).toObject();

      // add a new tab
      if (userOptions.contains("tabName") &&
          userOptions.value("tabName").isString()) {
        tabName = userOptions.value("tabName").toString();
        userOptions.take("tabName");
      }
      currentPage = new QWidget(this);
      QFormLayout* layout = new QFormLayout(currentPage);
      currentPage->setLayout(layout);
      m_currentLayout = layout;
    } else if (m_options["userOptions"].isObject()) {
      userOptions = m_options["userOptions"].toObject();
      // don't need to set layout, we aready did that
    } else {
      break;
    }

    // Title first
    if (userOptions.contains("Title"))
      addOptionRow(tr("Title"), userOptions.take("Title"));

    // File basename next:
    if (userOptions.contains("Filename Base"))
      addOptionRow(tr("Filename Base"), userOptions.take("Filename Base"));

    // Number of cores next:
    if (userOptions.contains("Processor Cores"))
      addOptionRow(tr("Processor Cores"), userOptions.take("Processor Cores"));

    // Calculation Type next:
    if (userOptions.contains("Calculation Type"))
      addOptionRow(tr("Calculation Type"),
                   userOptions.take("Calculation Type"));

    // Theory/basis next. Combine into one row if both present.
    combinedOptionRow("Theory", "Basis", tr("Theory"), tr("Basis"),
                      userOptions);

    // Other special cases: Charge / Multiplicity
    if (userOptions.contains("Charge"))
      addOptionRow(tr("Charge"), userOptions.take("Charge"));

    if (userOptions.contains("Multiplicity"))
      addOptionRow(tr("Multiplicity"), userOptions.take("Multiplicity"));

    // Add remaining keys at bottom.
    for (QJsonObject::const_iterator it = userOptions.constBegin(),
                                     itEnd = userOptions.constEnd();
         it != itEnd; ++it) {
      addOptionRow(it.key(), it.value());
    }

    // Make connections for standard options:
    if (QComboBox* combo = qobject_cast<QComboBox*>(
          m_widgets.value("Calculation Type", nullptr))) {
      connect(combo, SIGNAL(currentIndexChanged(int)),
              SLOT(updateTitlePlaceholder()));
    }
    if (QComboBox* combo =
          qobject_cast<QComboBox*>(m_widgets.value("Theory", nullptr))) {
      connect(combo, SIGNAL(currentIndexChanged(int)),
              SLOT(updateTitlePlaceholder()));
    }
    if (QComboBox* combo =
          qobject_cast<QComboBox*>(m_widgets.value("Basis", nullptr))) {
      connect(combo, SIGNAL(currentIndexChanged(int)),
              SLOT(updateTitlePlaceholder()));
    }

    // if we're adding tabs, add it now
    if (isArray) {
      tabs->addTab(currentPage, tabName);
    }
  } // end loop over tabs

  m_empty = m_widgets.isEmpty();
}

void JsonWidget::combinedOptionRow(const QString& label1, const QString& label2,
                                   const QString& tr1, const QString& tr2,
                                   QJsonObject& options)
{
  if (m_currentLayout == nullptr)
    return;

  bool option1 = options.contains(label1);
  bool option2 = options.contains(label2);
  if (option1 && option2) {
    QWidget* widget1 = createOptionWidget(options.take(label1));
    QWidget* widget2 = createOptionWidget(options.take(label2));
    QHBoxLayout* hbox = new QHBoxLayout;
    if (option1) {
      widget1->setObjectName(label1);
      hbox->addWidget(widget1);
      m_widgets.insert(tr1, widget1);
    }
    if (option2) {
      widget2->setObjectName(label1);
      hbox->addWidget(widget2);
      m_widgets.insert(tr2, widget2);
    }
    hbox->addStretch();

    m_currentLayout->addRow(tr1, hbox);
  } else {
    if (option1)
      addOptionRow(tr1, options.take(label1));
    if (option2)
      addOptionRow(tr2, options.take(label2));
  }
}

void JsonWidget::addOptionRow(const QString& name, const QJsonValue& option)
{
  QWidget* widget = createOptionWidget(option);
  if (!widget)
    return;

  QFormLayout* form = m_currentLayout;
  if (!form) {
    qWarning() << "Cannot add option" << name
               << "to GUI -- layout is not a form.";
    widget->deleteLater();
    return;
  }

  // For lookups during unit testing:
  widget->setObjectName(name);
  QString label(name);

  QJsonObject obj = option.toObject();

  if (obj.contains(QStringLiteral("label")) &&
      obj.value(QStringLiteral("label")).isString()) {
    label = obj[QStringLiteral("label")].toString();
  }

  form->addRow(label + ":", widget);
  m_widgets.insert(name, widget);

  // optionally hide rows .. can be shown by the script later
  bool hide = false;
  if (obj.contains(QStringLiteral("hide")) &&
      obj.value(QStringLiteral("hide")).isBool()) {
    hide = obj[QStringLiteral("hide")].toBool();
  }
  if (hide) {
    widget->hide();
    // find the label and hide that too
    auto label = form->labelForField(widget);
    if (label)
      label->hide();
  }
}

QWidget* JsonWidget::createOptionWidget(const QJsonValue& option)
{
  if (!option.isObject())
    return nullptr;

  QJsonObject obj = option.toObject();

  if (!obj.contains(QStringLiteral("type")) ||
      !obj.value(QStringLiteral("type")).isString())
    return nullptr;

  QString type = obj[QStringLiteral("type")].toString();

  if (type == QLatin1String("stringList"))
    return createStringListWidget(obj);
  else if (type == QLatin1String("string"))
    return createStringWidget(obj);
  else if (type == QLatin1String("filePath"))
    return createFilePathWidget(obj);
  else if (type == QLatin1String("integer"))
    return createIntegerWidget(obj);
  else if (type == QLatin1String("float"))
    return createFloatWidget(obj);
  else if (type == QLatin1String("boolean"))
    return createBooleanWidget(obj);

  qDebug() << "Unrecognized option type:" << type;
  return nullptr;
}

QWidget* JsonWidget::createStringListWidget(const QJsonObject& obj)
{
  if (!obj.contains(QStringLiteral("values")) ||
      !obj[QStringLiteral("values")].isArray()) {
    qDebug() << "JsonWidget::createStringListWidget()"
                "values missing, or not array!";
    return nullptr;
  }

  QJsonArray valueArray = obj[QStringLiteral("values")].toArray();

  QComboBox* combo = new QComboBox(this);
  for (QJsonArray::const_iterator vit = valueArray.constBegin(),
                                  vitEnd = valueArray.constEnd();
       vit != vitEnd; ++vit) {
    if ((*vit).isString()) {
      QString value = (*vit).toString();
      if (value == '-')
        combo->insertSeparator(combo->count());
      else
        combo->addItem((*vit).toString());
    } else
      qDebug() << "Cannot convert value to string for stringList:" << *vit;
  }
  connect(combo, SIGNAL(currentIndexChanged(int)), SLOT(updatePreviewText()));

  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    combo->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }

  return combo;
}

QWidget* JsonWidget::createStringWidget(const QJsonObject& obj)
{
  QLineEdit* edit = new QLineEdit(this);
  connect(edit, SIGNAL(textChanged(QString)), SLOT(updatePreviewText()));
  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    edit->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }

  return edit;
}

QWidget* JsonWidget::createFilePathWidget(const QJsonObject& obj)
{
  QtGui::FileBrowseWidget* fileBrowse = new QtGui::FileBrowseWidget(this);
  connect(fileBrowse, SIGNAL(fileNameChanged(QString)),
          SLOT(updatePreviewText()));

  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    fileBrowse->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }
  return fileBrowse;
}

QWidget* JsonWidget::createIntegerWidget(const QJsonObject& obj)
{
  QSpinBox* spin = new QSpinBox(this);
  if (obj.contains(QStringLiteral("minimum")) &&
      obj.value(QStringLiteral("minimum")).isDouble()) {
    spin->setMinimum(
      static_cast<int>(obj[QStringLiteral("minimum")].toDouble() + 0.5));
  }
  if (obj.contains(QStringLiteral("maximum")) &&
      obj.value(QStringLiteral("maximum")).isDouble()) {
    spin->setMaximum(
      static_cast<int>(obj[QStringLiteral("maximum")].toDouble() + 0.5));
  }
  if (obj.contains(QStringLiteral("prefix")) &&
      obj.value(QStringLiteral("prefix")).isString()) {
    spin->setPrefix(obj[QStringLiteral("prefix")].toString());
  }
  if (obj.contains(QStringLiteral("suffix")) &&
      obj.value(QStringLiteral("suffix")).isString()) {
    spin->setSuffix(obj[QStringLiteral("suffix")].toString());
  }
  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    spin->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }
  connect(spin, SIGNAL(valueChanged(int)), SLOT(updatePreviewText()));
  return spin;
}

QWidget* JsonWidget::createFloatWidget(const QJsonObject& obj)
{
  QDoubleSpinBox* spin = new QDoubleSpinBox(this);
  if (obj.contains(QStringLiteral("minimum")) &&
      obj.value(QStringLiteral("minimum")).isDouble()) {
    spin->setMinimum(obj[QStringLiteral("minimum")].toDouble());
  }
  if (obj.contains(QStringLiteral("maximum")) &&
      obj.value(QStringLiteral("maximum")).isDouble()) {
    spin->setMaximum(obj[QStringLiteral("maximum")].toDouble());
  }
  if (obj.contains(QStringLiteral("precision")) &&
      obj.value(QStringLiteral("precision")).isDouble()) {
    spin->setDecimals(
      static_cast<int>(obj[QStringLiteral("precision")].toDouble()));
  }
  if (obj.contains(QStringLiteral("prefix")) &&
      obj.value(QStringLiteral("prefix")).isString()) {
    spin->setPrefix(obj[QStringLiteral("prefix")].toString());
  }
  if (obj.contains(QStringLiteral("suffix")) &&
      obj.value(QStringLiteral("suffix")).isString()) {
    spin->setSuffix(obj[QStringLiteral("suffix")].toString());
  }
  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    spin->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }
  connect(spin, SIGNAL(valueChanged(double)), SLOT(updatePreviewText()));
  return spin;
}

QWidget* JsonWidget::createBooleanWidget(const QJsonObject& obj)
{
  QCheckBox* checkBox = new QCheckBox(this);
  connect(checkBox, SIGNAL(toggled(bool)), SLOT(updatePreviewText()));

  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    checkBox->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }
  return checkBox;
}

void JsonWidget::setOptionDefaults()
{
  if (!m_options.contains(QStringLiteral("userOptions"))) {
    return;
  }

  // if we have tabs, then userOptions is an array of objects
  // need to loop through to find the right one
  unsigned int size;
  bool isArray = m_options["userOptions"].isArray();
  QJsonArray options;
  QJsonObject userOptions;
  if (isArray) {
    size = m_options["userOptions"].toArray().size();
    options = m_options["userOptions"].toArray();
  } else
    size = 1;

  for (unsigned int i = 0; i < size; ++i) {
    // loop over tabs

    if (isArray) {
      userOptions = options.at(i).toObject();
    } else if (m_options["userOptions"].isObject()) {
      userOptions = m_options["userOptions"].toObject();
    } else {
      break;
    }

    // loop over widgets in the tab
    for (QJsonObject::ConstIterator it = userOptions.constBegin(),
                                    itEnd = userOptions.constEnd();
         it != itEnd; ++it) {
      QString label = it.key();
      QJsonValue val = it.value();

      if (!val.isObject()) {
        qWarning()
          << tr("Error: value must be object for key '%1'.").arg(label);
        continue;
      }

      QJsonObject obj = val.toObject();
      if (obj.contains("default")) {
        // TODO - check QSettings for a value too
        setOption(label, obj[QStringLiteral("default")]);
      }
    }
  }
}

void JsonWidget::setOption(const QString& name, const QJsonValue& defaultValue)
{
  QString type = lookupOptionType(name);

  if (type == QLatin1String("stringList"))
    return setStringListOption(name, defaultValue);
  else if (type == QLatin1String("string"))
    return setStringOption(name, defaultValue);
  else if (type == QLatin1String("filePath"))
    return setFilePathOption(name, defaultValue);
  else if (type == QLatin1String("integer"))
    return setIntegerOption(name, defaultValue);
  else if (type == QLatin1String("float"))
    return setFloatOption(name, defaultValue);
  else if (type == QLatin1String("boolean"))
    return setBooleanOption(name, defaultValue);

  qWarning()
    << tr("Unrecognized option type '%1' for option '%2'.").arg(type).arg(name);
  return;
}

void JsonWidget::setStringListOption(const QString& name,
                                     const QJsonValue& value)
{
  QComboBox* combo = qobject_cast<QComboBox*>(m_widgets.value(name, nullptr));
  if (!combo) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                    .arg(name);
    return;
  }

  if (!value.isDouble() && !value.isString()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                    .arg(name)
               << value;
    return;
  }

  int index = -1;
  if (value.isDouble())
    index = static_cast<int>(value.toDouble() + 0.5);
  else if (value.isString())
    index = combo->findText(value.toString());

  if (index < 0 || index > combo->count()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Could not find valid combo entry index from value:")
                    .arg(name)
               << value;
    return;
  }

  combo->setCurrentIndex(index);
}

void JsonWidget::setStringOption(const QString& name, const QJsonValue& value)
{
  QLineEdit* lineEdit =
    qobject_cast<QLineEdit*>(m_widgets.value(name, nullptr));
  if (!lineEdit) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                    .arg(name);
    return;
  }

  if (!value.isString()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                    .arg(name)
               << value;
    return;
  }

  lineEdit->setText(value.toString());
}

void JsonWidget::setFilePathOption(const QString& name, const QJsonValue& value)
{
  QtGui::FileBrowseWidget* fileBrowse =
    qobject_cast<QtGui::FileBrowseWidget*>(m_widgets.value(name, nullptr));
  if (!fileBrowse) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                    .arg(name);
    return;
  }

  if (!value.isString()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                    .arg(name)
               << value;
    return;
  }

  fileBrowse->setFileName(value.toString());
}

void JsonWidget::setIntegerOption(const QString& name, const QJsonValue& value)
{
  QSpinBox* spin = qobject_cast<QSpinBox*>(m_widgets.value(name, nullptr));
  if (!spin) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                    .arg(name);
    return;
  }

  if (!value.isDouble()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                    .arg(name)
               << value;
    return;
  }

  int intVal = static_cast<int>(value.toDouble() + 0.5);
  spin->setValue(intVal);
}

void JsonWidget::setFloatOption(const QString& name, const QJsonValue& value)
{
  QDoubleSpinBox* spin =
    qobject_cast<QDoubleSpinBox*>(m_widgets.value(name, nullptr));
  if (!spin) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                    .arg(name);
    return;
  }

  if (!value.isDouble()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                    .arg(name)
               << value;
    return;
  }

  spin->setValue(value.toDouble());
}

void JsonWidget::setBooleanOption(const QString& name, const QJsonValue& value)
{
  QCheckBox* checkBox =
    qobject_cast<QCheckBox*>(m_widgets.value(name, nullptr));
  if (!checkBox) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad widget type.")
                    .arg(name);
    return;
  }

  if (!value.isBool()) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Bad default value:")
                    .arg(name)
               << value;
    return;
  }

  checkBox->setChecked(value.toBool());
}

bool JsonWidget::optionString(const QString& option, QString& value) const
{
  QWidget* widget = m_widgets.value(option, nullptr);
  bool retval = false;
  value.clear();

  if (QLineEdit* edit = qobject_cast<QLineEdit*>(widget)) {
    retval = true;
    value = edit->text();
  } else if (QComboBox* combo = qobject_cast<QComboBox*>(widget)) {
    retval = true;
    value = combo->currentText();
  } else if (QSpinBox* spinbox = qobject_cast<QSpinBox*>(widget)) {
    retval = true;
    value = QString::number(spinbox->value());
  } else if (QDoubleSpinBox* dspinbox = qobject_cast<QDoubleSpinBox*>(widget)) {
    retval = true;
    value = QString::number(dspinbox->value());
  } else if (QtGui::FileBrowseWidget* fileBrowse =
               qobject_cast<QtGui::FileBrowseWidget*>(widget)) {
    retval = true;
    value = fileBrowse->fileName();
  }

  return retval;
}

QJsonObject JsonWidget::collectOptions() const
{
  QJsonObject ret;

  foreach (QString label, m_widgets.keys()) {
    QWidget* widget = m_widgets.value(label, nullptr);
    if (QComboBox* combo = qobject_cast<QComboBox*>(widget)) {
      ret.insert(label, combo->currentText());
    } else if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(widget)) {
      QString value(lineEdit->text());
      if (value.isEmpty() && label == QLatin1String("Title"))
        value = generateJobTitle();
      ret.insert(label, value);
    } else if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(widget)) {
      ret.insert(label, spinBox->value());
    } else if (QDoubleSpinBox* spinBox =
                 qobject_cast<QDoubleSpinBox*>(widget)) {
      ret.insert(label, spinBox->value());
    } else if (QCheckBox* checkBox = qobject_cast<QCheckBox*>(widget)) {
      ret.insert(label, checkBox->isChecked());
    } else if (QtGui::FileBrowseWidget* fileBrowse =
                 qobject_cast<QtGui::FileBrowseWidget*>(widget)) {
      ret.insert(label, fileBrowse->fileName());
    } else {
      qWarning()
        << tr("Unhandled widget in collectOptions for option '%1'.").arg(label);
    }
  }

  return ret;
}

void JsonWidget::applyOptions(const QJsonObject& opts)
{
  foreach (const QString& label, opts.keys())
    setOption(label, opts[label]);
}

QString JsonWidget::generateJobTitle() const
{
  QString calculation;
  bool haveCalculation(optionString("Calculation Type", calculation));

  QString theory;
  bool haveTheory(optionString("Theory", theory));

  QString basis;
  bool haveBasis(optionString("Basis", basis));

  // Merge theory/basis into theory
  if (haveBasis) {
    if (haveTheory)
      theory += "/";
    theory += basis;
    theory.replace(QRegExp("\\s+"), "");
    haveTheory = true;
  }

  if (m_batchMode) {
    QString result;
    result = haveCalculation ? calculation : QString();
    result += haveTheory ? (result.size() != 0 ? " | " : QString()) + theory
                         : QString();
    return result;
  }

  QString formula(m_molecule ? QString::fromStdString(m_molecule->formula())
                             : tr("[no molecule]"));

  return QString("%1%2%3")
    .arg(formula)
    .arg(haveCalculation ? " | " + calculation : QString())
    .arg(haveTheory ? " | " + theory : QString());
}

} // namespace QtGui
} // namespace Avogadro
