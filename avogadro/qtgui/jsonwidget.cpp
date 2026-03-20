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
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTextEdit>

#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QPointer>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

#include <QRegularExpression>

using namespace Qt::StringLiterals;

namespace Avogadro::QtGui {

JsonWidget::JsonWidget(QWidget* parent_)
  : QWidget(parent_), m_molecule(nullptr), m_empty(true), m_batchMode(false),
    m_currentLayout(nullptr), m_centralWidget(nullptr)
{
}

JsonWidget::~JsonWidget() {}

void JsonWidget::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule != nullptr) {
    // update charge and multiplicity only if those options exist
    // (command scripts don't have them, unlike input generators)
    auto hasUserOption = [&](const QString& key) -> bool {
      if (!m_options.contains(u"userOptions"_s))
        return false;
      return m_options[u"userOptions"_s].toObject().contains(key);
    };

    int charge = static_cast<int>(m_molecule->totalCharge());
    int multiplicity = static_cast<int>(m_molecule->totalSpinMultiplicity());

    if (hasUserOption(u"Charge"_s))
      setOption(u"Charge"_s, charge);
    if (hasUserOption(u"Multiplicity"_s))
      setOption(u"Multiplicity"_s, multiplicity);

    // check the molecule for "inputParameters" from CJSON
    // e.g.
    // https://github.com/OpenChemistry/chemicaljson/blob/main/chemicaljson.py#L130
    if (m_molecule->hasData("inputParameters")) {
      QByteArray inputData(
        m_molecule->data("inputParameters").toString().c_str());
      QJsonDocument doc = QJsonDocument::fromJson(inputData);
      if (!doc.isNull() && doc.isObject()) {
        QJsonObject inputParameters = doc.object();
        // check for a few known keys
        if (inputParameters.contains(u"processors"_s))
          setOption(u"Processor Cores"_s,
                    inputParameters[u"processors"_s].toInt());
        else if (inputParameters.contains(u"memory"_s))
          setOption(u"Memory"_s, inputParameters[u"memory"_s].toInt());
        else if (inputParameters.contains(u"basis"_s))
          setOption(u"Basis"_s, inputParameters[u"basis"_s].toString());
        else if (inputParameters.contains(u"functional"_s))
          setOption(u"Theory"_s, inputParameters[u"functional"_s].toString());
        else if (inputParameters.contains(u"task"_s))
          setOption(u"Calculation Type"_s,
                    inputParameters[u"task"_s].toString());
      }
    }
  }

  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;
}

QString JsonWidget::lookupOptionType(const QString& name) const
{
  if (!m_options.contains(u"userOptions"_s)) {
    qWarning() << tr("'userOptions' missing.");
    return QString();
  }

  QJsonObject userOptions = m_options[u"userOptions"_s].toObject();

  if (!userOptions.contains(name)) {
    qWarning() << tr("Could not find option '%1'.").arg(name);
    return QString();
  }

  QJsonObject obj = userOptions[name].toObject();

  if (!obj.contains(u"type"_s) || !obj[u"type"_s].isString()) {
    qWarning() << tr("'type' is not a string for option '%1'.").arg(name);
    return QString();
  }

  return obj[u"type"_s].toString();
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

  if (!m_options.contains(u"userOptions"_s)) {
    return;
  }

  // Always expect an object now, should never be an array
  if (m_options[u"userOptions"_s].isArray()) {
    return;
  }
  QJsonObject userOptions = m_options[u"userOptions"_s].toObject();

  // If a tabbed interface is specified, we'll create tabs for it
  QTabWidget* tabsWidget = nullptr;
  QWidget* currentPage = nullptr;

  // First work out whether a tabbed interface is specified
  bool isTabbed;
  if (userOptions.contains(u"tabs"_s)) {
    isTabbed = true;
  } else {
    // Interface doesn't have tabs at all
    isTabbed = false;
  }
  m_isTabbed = isTabbed;

  QJsonArray tabs;
  QMap<QString, QJsonObject> sortedOptions;
  // We need to store the tab names in order of position
  if (isTabbed) {
    tabs = userOptions.take(u"tabs"_s).toArray();

    // Sort the options by tab
    for (auto it = tabs.constBegin(); it != tabs.constEnd(); ++it) {
      QString tabName = it->toString();
      sortedOptions.insert(tabName, QJsonObject());
    }
    // Iterate over all options
    for (auto it = userOptions.constBegin(); it != userOptions.constEnd();
         ++it) {
      if (!it.value().isObject())
        continue;
      QJsonObject obj = it.value().toObject();
      QString tab = obj[u"tab"_s].toString();
      if (sortedOptions.contains(tab)) {
        QJsonObject& tabObj = sortedOptions[tab];
        tabObj.insert(it.key(), it.value());
      }
    }
  }

  // Lambda to add a set of options to the current layout
  auto addOptions = [this](QJsonObject options) {
    // Title first
    if (options.contains(u"Title"_s))
      addOptionRow(u"Title"_s, tr("Title"), options.take(u"Title"_s));

    // File basename next:
    if (options.contains(u"Filename Base"_s))
      addOptionRow(u"Filename Base"_s, tr("Filename Base"),
                   options.take(u"Filename Base"_s));

    // Number of cores and memory next:
    if (options.contains(u"Processor Cores"_s) &&
        options.contains(u"Memory"_s)) {
      combinedOptionRow(u"Processor Cores"_s, u"Memory"_s,
                        tr("Processor Cores"), tr("Memory"), options,
                        true); // both labels
    } else {
      // do them separately
      if (options.contains(u"Processor Cores"_s))
        addOptionRow(u"Processor Cores"_s, tr("Processor Cores"),
                     options.take(u"Processor Cores"_s));
      if (options.contains(u"Memory"_s))
        addOptionRow(u"Memory"_s, tr("Memory"), options.take(u"Memory"_s));
    }

    // Calculation Type next:
    if (options.contains(u"Calculation Type"_s))
      addOptionRow(u"Calculation Type"_s, tr("Calculation Type"),
                   options.take(u"Calculation Type"_s));

    // Theory/basis next. Combine into one row if both present.
    combinedOptionRow(u"Theory"_s, u"Basis"_s, tr("Theory"), tr("Basis"),
                      options);

    // Other special cases: Charge / Multiplicity
    if (options.contains(u"Charge"_s) && options.contains(u"Multiplicity"_s))
      combinedOptionRow(u"Charge"_s, u"Multiplicity"_s, tr("Charge"),
                        tr("Multiplicity"), options, true); // both labels
    else {
      if (options.contains(u"Charge"_s))
        addOptionRow(u"Charge"_s, tr("Charge"), options.take(u"Charge"_s));
      if (options.contains(u"Multiplicity"_s))
        addOptionRow(u"Multiplicity"_s, tr("Multiplicity"),
                     options.take(u"Multiplicity"_s));
    }

    // Solvation / model
    if (options.contains(u"Solvent"_s) &&
        options.contains(u"Solvation Model"_s)) {
      combinedOptionRow(u"Solvent"_s, u"Solvation Model"_s, tr("Solvent"),
                        tr("Model", "solvation method / model"), options,
                        true); // both labels
    }

    // Add remaining keys at bottom.
    // Look for "order" key to determine order
    QMap<int, QString> keys;
    int order = 0;
    for (QJsonObject::const_iterator it = options.constBegin(),
                                     itEnd = options.constEnd();
         it != itEnd; ++it) {
      if (it.value().isObject()) {
        QJsonObject obj = it.value().toObject();
        if (obj.contains(u"order"_s) && obj[u"order"_s].isDouble()) {
          order = obj[u"order"_s].toInt();
          keys.insert(order, it.key());
        } else { // object doesn't contain "order"
          keys.insert(order, it.key());
          order++;
        }
      } else {
        keys.insert(order++, it.key());
      }
    }

    // Now loop over keys and add them
    for (QString key : std::as_const(keys))
      addOptionRow(key, key, options.take(key));

    // Make connections for standard options:
    if (auto* combo = qobject_cast<QComboBox*>(
          m_widgets.value(u"Calculation Type"_s, nullptr))) {
      connect(combo, SIGNAL(currentIndexChanged(int)),
              SLOT(updateTitlePlaceholder()));
    }
    if (auto* combo =
          qobject_cast<QComboBox*>(m_widgets.value(u"Theory"_s, nullptr))) {
      connect(combo, SIGNAL(currentIndexChanged(int)),
              SLOT(updateTitlePlaceholder()));
    }
    if (auto* combo =
          qobject_cast<QComboBox*>(m_widgets.value(u"Basis"_s, nullptr))) {
      connect(combo, SIGNAL(currentIndexChanged(int)),
              SLOT(updateTitlePlaceholder()));
    }
  };

  // Create new widgets using the lambda
  if (isTabbed) {
    // Create a layout for inserting the tabs
    tabsWidget = new QTabWidget(this);
    auto* layout = new QVBoxLayout;
    layout->addWidget(tabsWidget);
    m_centralWidget->setLayout(layout);
    // Loop over the tabs, which are the top-level key/value pairs
    for (auto it = tabs.constBegin(); it != tabs.constEnd(); ++it) {
      QString tabName = it->toString();
      QJsonObject tabOptions = sortedOptions.value(tabName);
      // Add the new tab
      currentPage = new QWidget(this);
      auto* tabLayout = new QFormLayout(currentPage);
      currentPage->setLayout(tabLayout);
      // Make the created tab the current layout so that the lambda adds the
      // tab's options to it
      m_currentLayout = tabLayout;
      addOptions(tabOptions);
      tabsWidget->addTab(currentPage, tabName);
    } // End loop over tabs
  } else {
    // Create the form layout for the widgets
    auto* layout = new QFormLayout;
    m_currentLayout = layout;
    m_centralWidget->setLayout(layout);
    // Options are just the top level
    addOptions(userOptions);
  }

  m_empty = m_widgets.isEmpty();
}

void JsonWidget::combinedOptionRow(const QString& label1, const QString& label2,
                                   const QString& tr1, const QString& tr2,
                                   QJsonObject& options, bool bothLabels)
{
  if (m_currentLayout == nullptr)
    return;

  bool option1 = options.contains(label1);
  bool option2 = options.contains(label2);
  if (option1 && option2) {
    QWidget* widget1 = createOptionWidget(options.take(label1));
    QWidget* widget2 = createOptionWidget(options.take(label2));
    auto* hbox = new QHBoxLayout;
    if (option1) {
      widget1->setObjectName(label1);
      hbox->addWidget(widget1);
      m_widgets.insert(label1, widget1);
    }
    if (bothLabels) {
      QLabel* label = new QLabel(tr2 + ":");
      hbox->addWidget(label);
    }
    if (option2) {
      widget2->setObjectName(label2);
      hbox->addWidget(widget2);
      m_widgets.insert(label2, widget2);
    }
    hbox->addStretch();

    m_currentLayout->addRow(tr1, hbox);
  } else {
    if (option1)
      addOptionRow(label1, tr1, options.take(label1));
    if (option2)
      addOptionRow(label2, tr2, options.take(label2));
  }
}

void JsonWidget::addOptionRow(const QString& key, const QString& name,
                              const QJsonValue& option)
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
  widget->setObjectName(key);
  QString label(name);

  QJsonObject obj = option.toObject();

  if (obj.contains(u"label"_s) && obj[u"label"_s].isString()) {
    label = obj[u"label"_s].toString();
  }

  // also check for "User Name" or "Password" for translation
  // with case-insensitive comparison
  if (label.toLower() == u"user name"_s || label.toLower() == u"username"_s)
    label = tr("User Name");
  else if (label.toLower() == u"password"_s) {
    label = tr("Password");
    // make sure the widget has the right echo
    if (auto* lineEdit = qobject_cast<QLineEdit*>(widget)) {
      lineEdit->setEchoMode(QLineEdit::PasswordEchoOnEdit);
    }
  }

  form->addRow(label + ":", widget);
  m_widgets.insert(key, widget);

  // optionally hide rows .. can be shown by the script later
  bool hide = false;
  if (obj.contains(u"hide"_s) && obj[u"hide"_s].isBool()) {
    hide = obj[u"hide"_s].toBool();
  }
  if (hide) {
    widget->hide();
    // find the label and hide that too
    auto fLabel = form->labelForField(widget);
    if (fLabel)
      fLabel->hide();
  }
}

QWidget* JsonWidget::createOptionWidget(const QJsonValue& option)
{
  if (!option.isObject())
    return nullptr;

  QJsonObject obj = option.toObject();

  if (!obj.contains(u"type"_s) || !obj[u"type"_s].isString())
    return nullptr;

  QString type = obj[u"type"_s].toString();

  if (type == u"stringList"_s)
    return createStringListWidget(obj);
  else if (type == u"string"_s)
    return createStringWidget(obj);
  else if (type == u"filePath"_s)
    return createFilePathWidget(obj);
  else if (type == u"integer"_s)
    return createIntegerWidget(obj);
  else if (type == u"float"_s)
    return createFloatWidget(obj);
  else if (type == u"boolean"_s)
    return createBooleanWidget(obj);
  else if (type == u"text"_s)
    return createTextWidget(obj);
  else if (type == u"table"_s)
    return createTableWidget(obj);

  qDebug() << "Unrecognized option type:" << type;
  return nullptr;
}

QWidget* JsonWidget::createStringListWidget(const QJsonObject& obj)
{
  if (!obj.contains(u"values"_s) || !obj[u"values"_s].isArray()) {
    qDebug() << "JsonWidget::createStringListWidget()"
                "values missing, or not array!";
    return nullptr;
  }

  QJsonArray valueArray = obj[u"values"_s].toArray();

  auto* combo = new QComboBox(this);
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

  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    combo->setToolTip(obj[u"toolTip"_s].toString());
  }

  return combo;
}

QWidget* JsonWidget::createStringWidget(const QJsonObject& obj)
{
  auto* edit = new QLineEdit(this);
  connect(edit, SIGNAL(textChanged(QString)), SLOT(updatePreviewText()));
  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    edit->setToolTip(obj[u"toolTip"_s].toString());
  }
  if (obj.contains(u"placeholderText"_s) &&
      obj[u"placeholderText"_s].isString()) {
    edit->setPlaceholderText(obj[u"placeholderText"_s].toString());
  }
  // don't echo password fields
  if (obj.contains(u"password"_s) && obj[u"password"_s].isBool() &&
      obj[u"password"_s].toBool()) {
    edit->setEchoMode(QLineEdit::PasswordEchoOnEdit);
  }

  return edit;
}

QWidget* JsonWidget::createTextWidget(const QJsonObject& obj)
{
  auto* text = new QLabel(this);
  text->setWordWrap(true);

  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    text->setToolTip(obj[u"toolTip"_s].toString());
  }

  return text;
}

QWidget* JsonWidget::createFilePathWidget(const QJsonObject& obj)
{
  auto* fileBrowse = new QtGui::FileBrowseWidget(this);
  connect(fileBrowse, SIGNAL(fileNameChanged(QString)),
          SLOT(updatePreviewText()));

  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    fileBrowse->setToolTip(obj[u"toolTip"_s].toString());
  }
  return fileBrowse;
}

QWidget* JsonWidget::createIntegerWidget(const QJsonObject& obj)
{
  auto* spin = new QSpinBox(this);
  if (obj.contains(u"minimum"_s) && obj[u"minimum"_s].isDouble()) {
    spin->setMinimum(static_cast<int>(obj[u"minimum"_s].toDouble()));
  }
  if (obj.contains(u"maximum"_s) && obj[u"maximum"_s].isDouble()) {
    spin->setMaximum(static_cast<int>(obj[u"maximum"_s].toDouble()));
  }
  if (obj.contains(u"prefix"_s) && obj[u"prefix"_s].isString()) {
    spin->setPrefix(obj[u"prefix"_s].toString());
  }
  if (obj.contains(u"suffix"_s) && obj[u"suffix"_s].isString()) {
    spin->setSuffix(obj[u"suffix"_s].toString());
  }
  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    spin->setToolTip(obj[u"toolTip"_s].toString());
  }
  connect(spin, SIGNAL(valueChanged(int)), SLOT(updatePreviewText()));
  return spin;
}

QWidget* JsonWidget::createFloatWidget(const QJsonObject& obj)
{
  auto* spin = new QDoubleSpinBox(this);
  if (obj.contains(u"minimum"_s) && obj[u"minimum"_s].isDouble()) {
    spin->setMinimum(obj[u"minimum"_s].toDouble());
  }
  if (obj.contains(u"maximum"_s) && obj[u"maximum"_s].isDouble()) {
    spin->setMaximum(obj[u"maximum"_s].toDouble());
  }
  if (obj.contains(u"precision"_s) && obj[u"precision"_s].isDouble()) {
    spin->setDecimals(static_cast<int>(obj[u"precision"_s].toDouble()));
  }
  if (obj.contains(u"prefix"_s) && obj[u"prefix"_s].isString()) {
    spin->setPrefix(obj[u"prefix"_s].toString());
  }
  if (obj.contains(u"suffix"_s) && obj[u"suffix"_s].isString()) {
    spin->setSuffix(obj[u"suffix"_s].toString());
  }
  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    spin->setToolTip(obj[u"toolTip"_s].toString());
  }
  connect(spin, SIGNAL(valueChanged(double)), SLOT(updatePreviewText()));
  return spin;
}

QWidget* JsonWidget::createBooleanWidget(const QJsonObject& obj)
{
  auto* checkBox = new QCheckBox(this);
  connect(checkBox, SIGNAL(toggled(bool)), SLOT(updatePreviewText()));

  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    checkBox->setToolTip(obj[u"toolTip"_s].toString());
  }
  return checkBox;
}

QWidget* JsonWidget::createTableWidget(const QJsonObject& obj)
{
  auto* tableWidget = new QTableWidget(this);
  connect(tableWidget, SIGNAL(cellChanged(int, int)),
          SLOT(updatePreviewText()));

  if (obj.contains(u"toolTip"_s) && obj[u"toolTip"_s].isString()) {
    tableWidget->setToolTip(obj[u"toolTip"_s].toString());
  }
  if (obj.contains(u"headers"_s) && obj[u"headers"_s].isArray()) {
    QJsonArray headers = obj[u"headers"_s].toArray();
    tableWidget->setColumnCount(headers.size());
    for (int i = 0; i < headers.size(); ++i) {
      tableWidget->setHorizontalHeaderItem(
        i, new QTableWidgetItem(headers[i].toString()));
    }
  }
  if (obj.contains(u"delimiter"_s) && obj[u"delimiter"_s].isString()) {
    tableWidget->setProperty("delimiter", obj[u"delimiter"_s].toString());
  }

  // data might be supplied as columns or rows
  if (obj.contains(u"columns"_s) && obj[u"columns"_s].isArray()) {
    QJsonArray columns = obj[u"columns"_s].toArray();
    // get the row count from the first column
    tableWidget->setRowCount(columns[0].toArray().size());
    for (int i = 0; i < columns.size(); ++i) {
      int j = 0;
      for (QJsonArray::const_iterator it = columns[i].toArray().constBegin(),
                                      itEnd = columns[i].toArray().constEnd();
           it != itEnd; ++it) {
        tableWidget->setItem(i, j++, new QTableWidgetItem(it->toString()));
      }
    }
  }
  if (obj.contains(u"rows"_s) && obj[u"rows"_s].isArray()) {
    QJsonArray rows = obj[u"rows"_s].toArray();
    // get the column count from the first row
    tableWidget->setColumnCount(rows[0].toArray().size());
    for (int j = 0; j < rows.size(); ++j) {
      int i = 0;
      for (QJsonArray::const_iterator it = rows[i].toArray().constBegin(),
                                      itEnd = rows[i].toArray().constEnd();
           it != itEnd; ++it) {
        tableWidget->setItem(i++, j, new QTableWidgetItem(it->toString()));
      }
    }
  }

  return tableWidget;
}

void JsonWidget::setOptionDefaults()
{
  if (!m_options.contains(u"userOptions"_s)) {
    return;
  }
  QJsonObject userOptions = m_options[u"userOptions"_s].toObject();
  // Remove those keys that aren't for options
  userOptions.take(u"tabs"_s);

  // Loop over all options
  for (auto it = userOptions.constBegin(); it != userOptions.constEnd(); ++it) {
    QString label = it.key();
    QJsonObject obj = it.value().toObject();

    if (obj.contains(u"default"_s)) {
      // TODO - check QSettings for a value too
      setOption(label, obj[u"default"_s]);
    }
  }
}

void JsonWidget::setOption(const QString& name, const QJsonValue& defaultValue)
{
  QString type = lookupOptionType(name);

  if (type == u"stringList"_s)
    return setStringListOption(name, defaultValue);
  else if (type == u"string"_s)
    return setStringOption(name, defaultValue);
  else if (type == u"filePath"_s)
    return setFilePathOption(name, defaultValue);
  else if (type == u"integer"_s)
    return setIntegerOption(name, defaultValue);
  else if (type == u"float"_s)
    return setFloatOption(name, defaultValue);
  else if (type == u"boolean"_s)
    return setBooleanOption(name, defaultValue);
  else if (type == u"text"_s)
    return setTextOption(name, defaultValue);
  else if (type == u"table"_s)
    return setTableOption(name, defaultValue);

  qWarning()
    << tr("Unrecognized option type '%1' for option '%2'.").arg(type).arg(name);
  return;
}

void JsonWidget::setStringListOption(const QString& name,
                                     const QJsonValue& value)
{
  auto* combo = qobject_cast<QComboBox*>(m_widgets.value(name, nullptr));
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
  auto* lineEdit = qobject_cast<QLineEdit*>(m_widgets.value(name, nullptr));
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

void JsonWidget::setTextOption(const QString& name, const QJsonValue& value)
{
  auto* text = qobject_cast<QLabel*>(m_widgets.value(name, nullptr));
  if (text == nullptr) {
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

  text->setText(value.toString());
}

void JsonWidget::setTableOption(const QString& name, const QJsonValue& value)
{
  auto* table = qobject_cast<QTableWidget*>(m_widgets.value(name, nullptr));
  if (table == nullptr) {
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

  // parse the table (default delimiter is tab)
  QString delimiter;
  if (table->property("delimiter").isValid())
    delimiter = table->property("delimiter").toString();
  else
    delimiter = "\t";

  // parse the table
  table->clearContents();
  QStringList tableLines = value.toString().split("\n");
  table->setRowCount(tableLines.size());
  for (int i = 0; i < tableLines.size(); ++i) {
    QStringList entry = tableLines[i].split(delimiter);
    for (int j = 0; j < entry.size(); ++j) {
      table->setItem(i, j, new QTableWidgetItem(entry[j]));
    }
  }
}

void JsonWidget::setFilePathOption(const QString& name, const QJsonValue& value)
{
  auto* fileBrowse =
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
  auto* spin = qobject_cast<QSpinBox*>(m_widgets.value(name, nullptr));
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

  int intVal = static_cast<int>(value.toDouble());
  spin->setValue(intVal);
}

void JsonWidget::setFloatOption(const QString& name, const QJsonValue& value)
{
  auto* spin = qobject_cast<QDoubleSpinBox*>(m_widgets.value(name, nullptr));
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
  auto* checkBox = qobject_cast<QCheckBox*>(m_widgets.value(name, nullptr));
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

  if (auto* edit = qobject_cast<QLineEdit*>(widget)) {
    retval = true;
    value = edit->text();
  } else if (auto* combo = qobject_cast<QComboBox*>(widget)) {
    retval = true;
    value = combo->currentText();
  } else if (auto* spinbox = qobject_cast<QSpinBox*>(widget)) {
    retval = true;
    value = QString::number(spinbox->value());
  } else if (auto* dspinbox = qobject_cast<QDoubleSpinBox*>(widget)) {
    retval = true;
    value = QString::number(dspinbox->value());
  } else if (auto* fileBrowse =
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
    if (auto* combo = qobject_cast<QComboBox*>(widget)) {
      ret.insert(label, combo->currentText());
    } else if (auto* lineEdit = qobject_cast<QLineEdit*>(widget)) {
      QString value(lineEdit->text());
      if (value.isEmpty() && label == u"Title"_s)
        value = generateJobTitle();
      ret.insert(label, value);
    } else if (auto* spinBox = qobject_cast<QSpinBox*>(widget)) {
      ret.insert(label, spinBox->value());
    } else if (auto* doubleSpinBox = qobject_cast<QDoubleSpinBox*>(widget)) {
      ret.insert(label, doubleSpinBox->value());
    } else if (auto* checkBox = qobject_cast<QCheckBox*>(widget)) {
      ret.insert(label, checkBox->isChecked());
    } else if (auto* fileBrowse =
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
  foreach (const QString& label, opts.keys()) {
    setOption(label, opts[label]);

    qDebug() << "Setting option" << label << "to" << opts[label];
  }
}

QString JsonWidget::generateJobTitle() const
{
  QString calculation;
  bool haveCalculation(optionString(u"Calculation Type"_s, calculation));

  QString theory;
  bool haveTheory(optionString(u"Theory"_s, theory));

  QString basis;
  bool haveBasis(optionString(u"Basis"_s, basis));

  // Merge theory/basis into theory
  if (haveBasis) {
    if (haveTheory)
      theory += "/";
    theory += basis;
    theory.replace(QRegularExpression("\\s+"), "");
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

} // namespace Avogadro::QtGui
