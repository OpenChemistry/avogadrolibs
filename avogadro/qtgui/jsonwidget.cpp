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
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTextEdit>

#include <QtCore/QDebug>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QPointer>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

#include <QRegularExpression>

#include <utility>

using namespace Qt::StringLiterals;

namespace Avogadro::QtGui {

namespace {

/// QSettings group holding every command's remembered option values.
const auto settingsGroup = u"commandOptions"_s;

/**
 * Whether a widget's value may be written to disk.
 *
 * Any line edit not echoing normally is a password, however it got that way:
 * createStringWidget() honours "password", and addOptionRow() also switches
 * on a field labelled "Password". Asking the widget rather than re-reading
 * the JSON means the two can never drift apart.
 *
 * Tables are excluded too. A picker's chosen row may not exist next time, and
 * restoring one would overwrite the rows the script had just supplied.
 */
bool isSaveableWidget(const QWidget* widget)
{
  if (widget == nullptr)
    return false;
  if (const auto* edit = qobject_cast<const QLineEdit*>(widget))
    return edit->echoMode() == QLineEdit::Normal;
  return qobject_cast<const QTableWidget*>(widget) == nullptr;
}

/// The cell separator a table option was built with; a tab unless it said so.
QString tableDelimiter(const QTableWidget* table)
{
  const QVariant delimiter = table->property("delimiter");
  return delimiter.isValid() ? delimiter.toString() : u"\t"_s;
}

/**
 * Serialize a table the way setTableOption() parses one: cells joined by the
 * widget's delimiter, rows joined by newlines, so an editable table round
 * trips through its own default value.
 *
 * A table created with "selectable" is a picker rather than a grid, so only
 * the row the user chose is returned.  An empty string means nothing is
 * selected, which the script must handle.
 */
QString tableToString(const QTableWidget* table)
{
  const QString delimiter = tableDelimiter(table);

  auto rowText = [table, &delimiter](int row) {
    QStringList cells;
    cells.reserve(table->columnCount());
    for (int column = 0; column < table->columnCount(); ++column) {
      const QTableWidgetItem* cell = table->item(row, column);
      cells << (cell != nullptr ? cell->text() : QString());
    }
    return cells.join(delimiter);
  };

  if (table->property("selectable").toBool()) {
    const QItemSelectionModel* selection = table->selectionModel();
    if (selection == nullptr)
      return QString();
    const QModelIndexList rows = selection->selectedRows();
    if (rows.isEmpty())
      return QString();
    return rowText(rows.first().row());
  }

  QStringList lines;
  lines.reserve(table->rowCount());
  for (int row = 0; row < table->rowCount(); ++row)
    lines << rowText(row);
  return lines.join(u"\n"_s);
}

} // namespace

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
  m_currentLayout = nullptr;

  // Deleting a layout does not delete the widgets it managed: they stay on as
  // children of m_centralWidget, no longer positioned by anything, and paint
  // over the form built below. Everything under m_centralWidget was put there
  // by a previous run of this function, so it all goes. Unparent first, so the
  // stale form leaves the screen right away, then defer the delete in case
  // this rebuild was triggered from one of those widgets' own signals.
  const QList<QWidget*> stale = m_centralWidget->findChildren<QWidget*>(
    QString(), Qt::FindDirectChildrenOnly);
  for (QWidget* staleWidget : stale) {
    staleWidget->setParent(nullptr);
    staleWidget->deleteLater();
  }

  // Nothing below builds a widget, so the form is empty either way. Say so, or
  // isEmpty() would keep reporting whatever the previous option set produced.
  if (!m_options.contains(u"userOptions"_s)) {
    m_empty = true;
    return;
  }

  // Always expect an object now, should never be an array
  if (m_options[u"userOptions"_s].isArray()) {
    m_empty = true;
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

  // A "selectable" table is a picker rather than an editable grid: the user
  // chooses one row and collectOptions() hands that row to the script.
  if (obj[u"selectable"_s].toBool()) {
    tableWidget->setProperty("selectable", true);
    tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    tableWidget->verticalHeader()->setVisible(false);
    connect(tableWidget, SIGNAL(itemSelectionChanged()),
            SLOT(updatePreviewText()));
  }

  // Data may be supplied either as columns or as rows: both are arrays of
  // arrays of cell strings, and only the nesting order differs.  Fill the
  // table from one of them, mapping the outer index to whichever axis it
  // names.  Note that setItem() takes (row, column) in that order.
  auto populate = [tableWidget](const QJsonArray& outer, bool outerIsRows) {
    // The longest inner array sets the size of the other axis. Ragged input
    // is allowed: missing cells are simply left empty.
    int innerCount = 0;
    for (const QJsonValue& inner : outer)
      innerCount = qMax(innerCount, static_cast<int>(inner.toArray().size()));

    const auto outerCount = static_cast<int>(outer.size());
    tableWidget->setRowCount(outerIsRows ? outerCount : innerCount);
    // Headers, if any, have already set the column count; only grow it.
    const int columnCount = outerIsRows ? innerCount : outerCount;
    if (columnCount > tableWidget->columnCount())
      tableWidget->setColumnCount(columnCount);

    for (int i = 0; i < outerCount; ++i) {
      const QJsonArray cells = outer[i].toArray();
      for (int j = 0; j < cells.size(); ++j)
        tableWidget->setItem(outerIsRows ? i : j, outerIsRows ? j : i,
                             new QTableWidgetItem(cells[j].toString()));
    }
    tableWidget->resizeColumnsToContents();
  };

  if (obj[u"columns"_s].isArray())
    populate(obj[u"columns"_s].toArray(), false);
  if (obj[u"rows"_s].isArray())
    populate(obj[u"rows"_s].toArray(), true);

  // Sorting has to be switched on after the data is in place, or the rows are
  // re-ordered underneath setItem() as they are inserted.
  if (obj[u"sortable"_s].toBool())
    tableWidget->setSortingEnabled(true);

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
      setOption(label, obj[u"default"_s]);
    }
  }

  // Anything the user chose last time wins over the script's default. Applied
  // second, so a saved value that has gone stale - an entry dropped from a
  // stringList, say - leaves the default in place rather than nothing.
  restoreOptionValues();
}

bool JsonWidget::optionIsSaveable(const QString& name) const
{
  if (!isSaveableWidget(m_widgets.value(name, nullptr)))
    return false;

  // A script can opt out an option that would only confuse when it came back,
  // such as a one-shot value or a deliberate per-run choice.
  const QJsonValue option = m_options[u"userOptions"_s].toObject().value(name);
  if (option.isObject()) {
    const QJsonValue save = option.toObject().value(u"save"_s);
    if (save.isBool())
      return save.toBool();
  }
  return true;
}

void JsonWidget::saveOptionValues() const
{
  if (m_settingsKey.isEmpty())
    return;

  const QJsonObject collected = collectOptions();
  QJsonObject saved;
  for (auto it = collected.constBegin(); it != collected.constEnd(); ++it) {
    if (optionIsSaveable(it.key()))
      saved.insert(it.key(), it.value());
  }

  QSettings settings;
  settings.setValue(
    settingsGroup + '/' + m_settingsKey,
    QString::fromUtf8(QJsonDocument(saved).toJson(QJsonDocument::Compact)));
}

void JsonWidget::restoreOptionValues()
{
  if (m_settingsKey.isEmpty())
    return;

  QSettings settings;
  const QString stored =
    settings.value(settingsGroup + '/' + m_settingsKey).toString();
  if (stored.isEmpty())
    return;

  const QJsonObject saved = QJsonDocument::fromJson(stored.toUtf8()).object();
  for (auto it = saved.constBegin(); it != saved.constEnd(); ++it) {
    // The option may be gone, may have become a password, or may have been
    // opted out since it was written; in every case the saved value is not
    // ours to apply any more.
    if (optionIsSaveable(it.key()))
      setOption(it.key(), it.value());
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

  // Parse the table up front: the rows are needed twice, to size it and to
  // fill it, and splitting each line again for the second pass allocates a
  // fresh QString per cell.
  const QString delimiter = tableDelimiter(table);
  const QStringList lines = value.toString().split(u"\n"_s);
  QList<QStringList> rows;
  rows.reserve(lines.size());
  // Without headers the column count is still zero, and setItem() would drop
  // every cell, so widen the table to the longest line first.
  int columnCount = table->columnCount();
  for (const QString& line : lines) {
    rows.append(line.split(delimiter));
    columnCount = qMax(columnCount, static_cast<int>(rows.last().size()));
  }

  // A sortable table re-sorts on every setItem() into the column the sort
  // indicator is on, moving rows out from under the insertion and scattering
  // each row's cells across the others. Fill it with sorting off, then put the
  // setting back and let the view sort the finished rows as a whole.
  const bool sortingEnabled = table->isSortingEnabled();
  table->setSortingEnabled(false);

  table->clearContents();
  table->setRowCount(static_cast<int>(rows.size()));
  table->setColumnCount(columnCount);
  for (int i = 0; i < rows.size(); ++i) {
    const QStringList& entry = rows.at(i);
    for (int j = 0; j < entry.size(); ++j) {
      table->setItem(i, j, new QTableWidgetItem(entry.at(j)));
    }
  }
  // createTableWidget() only sizes the columns when the JSON carried the data;
  // a table filled from its default gets its turn here.
  table->resizeColumnsToContents();
  table->setSortingEnabled(sortingEnabled);
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
    } else if (auto* table = qobject_cast<QTableWidget*>(widget)) {
      ret.insert(label, tableToString(table));
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
