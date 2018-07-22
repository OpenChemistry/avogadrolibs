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

#include "interfacewidget.h"

#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QFormLayout>
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

InterfaceWidget::InterfaceWidget(const QString& scriptFilePath,
                                 QWidget* parent_)
  : QWidget(parent_)
  , m_molecule(nullptr)
  , m_interfaceScript(QString())
{
  this->setInterfaceScript(scriptFilePath);
}

InterfaceWidget::~InterfaceWidget() {}

void InterfaceWidget::setInterfaceScript(const QString& scriptFile)
{
  m_interfaceScript.setScriptFilePath(scriptFile);
  m_options = m_interfaceScript.options();
  updateOptions();
}

void InterfaceWidget::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;
}

void InterfaceWidget::defaultsClicked()
{
  setOptionDefaults();
}

void InterfaceWidget::setWarningText(const QString& warn)
{
  qWarning() << tr("Script returns warnings:\n") << warn;
}

QString InterfaceWidget::warningText() const
{
  return QString();
}

void InterfaceWidget::showError(const QString& err)
{
  qWarning() << err;

  QWidget* theParent =
    this->isVisible() ? this : qobject_cast<QWidget*>(parent());
  QDialog dlg(theParent);
  QVBoxLayout* vbox = new QVBoxLayout();
  QLabel* label = new QLabel(tr("An error has occurred:"));
  vbox->addWidget(label);
  QTextBrowser* textBrowser = new QTextBrowser();

  // adjust the size of the text browser to ~80 char wide, ~20 lines high
  QSize theSize = textBrowser->sizeHint();
  QFontMetrics metrics(textBrowser->currentFont());
  int charWidth = metrics.width(QStringLiteral("i7OPlmWn9/")) / 10;
  int charHeight = metrics.lineSpacing();
  theSize.setWidth(80 * charWidth);
  theSize.setHeight(20 * charHeight);
  textBrowser->setMinimumSize(theSize);
  textBrowser->setText(err);
  vbox->addWidget(textBrowser);
  dlg.setLayout(vbox);

  dlg.exec();
}

QString InterfaceWidget::settingsKey(const QString& identifier) const
{
  return QStringLiteral("scriptPlugin/%1/%2")
    .arg(m_interfaceScript.displayName(), identifier);
}

QString InterfaceWidget::lookupOptionType(const QString& name) const
{
  if (!m_options.contains(QStringLiteral("userOptions")) ||
      !m_options[QStringLiteral("userOptions")].isObject()) {
    qWarning() << tr("'userOptions' missing, or not an object.");
    return QString();
  }

  QJsonObject userOptions = m_options[QStringLiteral("userOptions")].toObject();

  if (!userOptions.contains(name)) {
    qWarning() << tr("Option '%1' not found in userOptions.").arg(name);
    return QString();
  }

  if (!userOptions.value(name).isObject()) {
    qWarning() << tr("Option '%1' does not refer to an object.");
    return QString();
  }

  QJsonObject obj = userOptions[name].toObject();

  if (!obj.contains(QStringLiteral("type")) ||
      !obj.value(QStringLiteral("type")).isString()) {
    qWarning() << tr("'type' is not a string for option '%1'.").arg(name);
    return QString();
  }

  return obj[QStringLiteral("type")].toString();
}

void InterfaceWidget::updateOptions()
{
  // Create the widgets, etc for the gui
  buildOptionGui();
  setOptionDefaults();
}

void InterfaceWidget::buildOptionGui()
{
  // Clear old widgets from the layout
  m_widgets.clear();
  delete layout(); // kill my layout
  QFormLayout* form = new QFormLayout;
  setLayout(form);

  if (!m_options.contains(QStringLiteral("userOptions")) ||
      !m_options[QStringLiteral("userOptions")].isObject()) {
    showError(tr("'userOptions' missing, or not an object:\n%1")
                .arg(QString(QJsonDocument(m_options).toJson())));
    return;
  }

  QJsonObject userOptions =
    m_options.value(QStringLiteral("userOptions")).toObject();

  // Title first
  if (userOptions.contains(QStringLiteral("Title")))
    addOptionRow(tr("Title"), userOptions.take(QStringLiteral("Title")));

  // File basename next:
  if (userOptions.contains(QStringLiteral("Filename Base")))
    addOptionRow(tr("Filename Base"),
                 userOptions.take(QStringLiteral("Filename Base")));

  // Number of cores next:
  if (userOptions.contains(QStringLiteral("Processor Cores")))
    addOptionRow(tr("Processor Cores"),
                 userOptions.take(QStringLiteral("Processor Cores")));

  // Calculation Type next:
  if (userOptions.contains(QStringLiteral("Calculation Type")))
    addOptionRow(tr("Calculation Type"),
                 userOptions.take(QStringLiteral("Calculation Type")));

  // Theory/basis next. Combine into one row if both present.
  bool hasTheory = userOptions.contains(QStringLiteral("Theory"));
  bool hasBasis = userOptions.contains(QStringLiteral("Basis"));
  if (hasTheory && hasBasis) {
    QWidget* theoryWidget =
      createOptionWidget(userOptions.take(QStringLiteral("Theory")));
    QWidget* basisWidget =
      createOptionWidget(userOptions.take(QStringLiteral("Basis")));
    QHBoxLayout* hbox = new QHBoxLayout;
    if (theoryWidget) {
      theoryWidget->setObjectName(QStringLiteral("Theory"));
      hbox->addWidget(theoryWidget);
      m_widgets.insert(QStringLiteral("Theory"), theoryWidget);
    }
    if (basisWidget) {
      basisWidget->setObjectName(QStringLiteral("Basis"));
      hbox->addWidget(basisWidget);
      m_widgets.insert(QStringLiteral("Basis"), basisWidget);
    }
    hbox->addStretch();

    form->addRow(tr("Theory:"), hbox);
  } else {
    if (hasTheory)
      addOptionRow(tr("Theory"), userOptions.take(QStringLiteral("Theory")));
    if (hasBasis)
      addOptionRow(tr("Basis"), userOptions.take(QStringLiteral("Basis")));
  }

  // Other special cases:
  if (userOptions.contains(QStringLiteral("Charge")))
    addOptionRow(tr("Charge"), userOptions.take(QStringLiteral("Charge")));
  if (userOptions.contains(QStringLiteral("Multiplicity")))
    addOptionRow(tr("Multiplicity"),
                 userOptions.take(QStringLiteral("Multiplicity")));

  // Add remaining keys at bottom.
  for (QJsonObject::const_iterator it = userOptions.constBegin(),
                                   itEnd = userOptions.constEnd();
       it != itEnd; ++it) {
    addOptionRow(it.key(), it.value());
  }

  // Make connections for standard options:
  if (QComboBox* combo = qobject_cast<QComboBox*>(
        m_widgets.value(QStringLiteral("Calculation Type"), nullptr))) {
    connect(combo, SIGNAL(currentIndexChanged(int)),
            SLOT(updateTitlePlaceholder()));
  }
  if (QComboBox* combo = qobject_cast<QComboBox*>(
        m_widgets.value(QStringLiteral("Theory"), nullptr))) {
    connect(combo, SIGNAL(currentIndexChanged(int)),
            SLOT(updateTitlePlaceholder()));
  }
  if (QComboBox* combo = qobject_cast<QComboBox*>(
        m_widgets.value(QStringLiteral("Basis"), nullptr))) {
    connect(combo, SIGNAL(currentIndexChanged(int)),
            SLOT(updateTitlePlaceholder()));
  }
}

void InterfaceWidget::addOptionRow(const QString& label,
                                   const QJsonValue& option)
{
  QWidget* widget = createOptionWidget(option);
  if (!widget)
    return;

  QFormLayout* form = qobject_cast<QFormLayout*>(this->layout());
  if (!form) {
    qWarning() << "Cannot add option" << label
               << "to GUI -- layout is not a form.";
    widget->deleteLater();
    return;
  }

  // For lookups during unit testing:
  widget->setObjectName(label);

  form->addRow(label + ":", widget);
  m_widgets.insert(label, widget);
}

QWidget* InterfaceWidget::createOptionWidget(const QJsonValue& option)
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

QWidget* InterfaceWidget::createStringListWidget(const QJsonObject& obj)
{
  if (!obj.contains(QStringLiteral("values")) ||
      !obj[QStringLiteral("values")].isArray()) {
    qDebug() << "QuantumInputDialog::createStringListWidget()"
                "values missing, or not array!";
    return nullptr;
  }

  QJsonArray valueArray = obj[QStringLiteral("values")].toArray();

  QComboBox* combo = new QComboBox(this);
  for (QJsonArray::const_iterator vit = valueArray.constBegin(),
                                  vitEnd = valueArray.constEnd();
       vit != vitEnd; ++vit) {
    if ((*vit).isString())
      combo->addItem((*vit).toString());
    else
      qDebug() << "Cannot convert value to string for stringList:" << *vit;
  }
  connect(combo, SIGNAL(currentIndexChanged(int)), SLOT(updatePreviewText()));

  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    combo->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }

  return combo;
}

QWidget* InterfaceWidget::createStringWidget(const QJsonObject& obj)
{
  QLineEdit* edit = new QLineEdit(this);
  //  connect(edit, SIGNAL(textChanged(QString)), SLOT(updatePreviewText()));
  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    edit->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }

  return edit;
}

QWidget* InterfaceWidget::createFilePathWidget(const QJsonObject& obj)
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

QWidget* InterfaceWidget::createIntegerWidget(const QJsonObject& obj)
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

QWidget* InterfaceWidget::createFloatWidget(const QJsonObject& obj)
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

QWidget* InterfaceWidget::createBooleanWidget(const QJsonObject& obj)
{
  QCheckBox* checkBox = new QCheckBox(this);
  connect(checkBox, SIGNAL(toggled(bool)), SLOT(updatePreviewText()));

  if (obj.contains(QStringLiteral("toolTip")) &&
      obj.value(QStringLiteral("toolTip")).isString()) {
    checkBox->setToolTip(obj[QStringLiteral("toolTip")].toString());
  }
  return checkBox;
}

void InterfaceWidget::setOptionDefaults()
{
  if (!m_options.contains(QStringLiteral("userOptions")) ||
      !m_options[QStringLiteral("userOptions")].isObject()) {
    showError(tr("'userOptions' missing, or not an object:\n%1")
                .arg(QString(QJsonDocument(m_options).toJson())));
    return;
  }

  QJsonObject userOptions = m_options[QStringLiteral("userOptions")].toObject();

  for (QJsonObject::ConstIterator it = userOptions.constBegin(),
                                  itEnd = userOptions.constEnd();
       it != itEnd; ++it) {
    QString label = it.key();
    QJsonValue val = it.value();

    if (!val.isObject()) {
      qWarning() << tr("Error: value must be object for key '%1'.").arg(label);
      continue;
    }

    QJsonObject obj = val.toObject();
    if (obj.contains(QStringLiteral("default")))
      setOption(label, obj[QStringLiteral("default")]);
    else if (m_interfaceScript.debug())
      qWarning() << tr("Default value missing for option '%1'.").arg(label);
  }
}

void InterfaceWidget::setOption(const QString& name,
                                const QJsonValue& defaultValue)
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

void InterfaceWidget::setStringListOption(const QString& name,
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

  if (index < 0) {
    qWarning() << tr("Error setting default for option '%1'. "
                     "Could not find valid combo entry index from value:")
                    .arg(name)
               << value;
    return;
  }

  combo->setCurrentIndex(index);
}

void InterfaceWidget::setStringOption(const QString& name,
                                      const QJsonValue& value)
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

void InterfaceWidget::setFilePathOption(const QString& name,
                                        const QJsonValue& value)
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

void InterfaceWidget::setIntegerOption(const QString& name,
                                       const QJsonValue& value)
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

void InterfaceWidget::setFloatOption(const QString& name,
                                     const QJsonValue& value)
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

void InterfaceWidget::setBooleanOption(const QString& name,
                                       const QJsonValue& value)
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

bool InterfaceWidget::optionString(const QString& option, QString& value) const
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

QJsonObject InterfaceWidget::collectOptions() const
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

void InterfaceWidget::applyOptions(const QJsonObject& opts)
{
  foreach (const QString& label, opts.keys())
    setOption(label, opts[label]);
}

QString InterfaceWidget::generateJobTitle() const
{
  QString calculation;
  bool haveCalculation(
    optionString(QStringLiteral("Calculation Type"), calculation));

  QString theory;
  bool haveTheory(optionString(QStringLiteral("Theory"), theory));

  QString basis;
  bool haveBasis(optionString(QStringLiteral("Basis"), basis));

  // Merge theory/basis into theory
  if (haveBasis) {
    if (haveTheory)
      theory += QLatin1String("/");
    theory += basis;
    theory.replace(QRegExp("\\s+"), QLatin1String(""));
    haveTheory = true;
  }

  QString formula(m_molecule ? QString::fromStdString(m_molecule->formula())
                             : tr("[no molecule]"));

  return QStringLiteral("%1%2%3")
    .arg(formula)
    .arg(haveCalculation ? " | " + calculation : QString())
    .arg(haveTheory ? " | " + theory : QString());
}

} // namespace QtGui
} // namespace Avogadro
