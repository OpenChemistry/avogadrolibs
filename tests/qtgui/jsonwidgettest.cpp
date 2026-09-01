/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/jsonwidget.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QPointer>
#include <QtWidgets/QApplication>
#include <QtWidgets/QTableWidget>

using Avogadro::QtGui::JsonWidget;

namespace {

/**
 * JsonWidget is a QWidget, so a plain QCoreApplication is not enough. Other
 * tests in this binary may have created one already; if that instance is not
 * a QApplication there is no way to upgrade it, and the caller skips.
 */
QApplication* ensureApp()
{
  if (QCoreApplication::instance() != nullptr)
    return qobject_cast<QApplication*>(QCoreApplication::instance());

  static int argc = 1;
  static char arg0[] = "jsonwidgettest";
  static char* argv[] = { arg0, nullptr };
  // Run without a display so this works in CI.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
  static QApplication app(argc, argv);
  return &app;
}

/// Thin subclass so the test can push option JSON in and reach the widgets.
class TestableJsonWidget : public JsonWidget
{
public:
  explicit TestableJsonWidget(QWidget* parent = nullptr) : JsonWidget(parent) {}

  void setOptions(const QJsonObject& userOptions)
  {
    QJsonObject options;
    options.insert(QStringLiteral("userOptions"), userOptions);
    m_options = options;
    updateOptions();
  }

  /// Replace the options wholesale, without the "userOptions" wrapper.
  void setRawOptions(const QJsonObject& options)
  {
    m_options = options;
    updateOptions();
  }

  QWidget* widgetFor(const QString& name) const
  {
    return m_widgets.value(name, nullptr);
  }

  QTableWidget* table(const QString& name) const
  {
    return qobject_cast<QTableWidget*>(m_widgets.value(name, nullptr));
  }
};

/// A trivial single-line option, for tests that only care about the form.
QJsonObject stringOption()
{
  QJsonObject option;
  option.insert(QStringLiteral("type"), QStringLiteral("string"));
  return option;
}

QJsonArray toArray(const QStringList& values)
{
  QJsonArray array;
  for (const QString& value : values)
    array.append(value);
  return array;
}

/// One option named "Job" holding the given table definition.
QJsonObject jobTable(QJsonObject table)
{
  table.insert(QStringLiteral("type"), QStringLiteral("table"));
  QJsonObject userOptions;
  userOptions.insert(QStringLiteral("Job"), table);
  return userOptions;
}

const QStringList headers = { "Job", "Name", "Calculation" };
const QStringList row0 = { "1963207", "H2N", "Molecular Energy" };
const QStringList row1 = { "1963205", "CH3F", "NMR" };

} // namespace

// Rows are arrays of cells; setItem() takes (row, column) in that order, so a
// table given by rows must come back with row 0 holding row0.
TEST(JsonWidgetTest, RowsPopulateInOrder)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  QJsonObject table;
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  rows.append(toArray(row1));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  widget.setOptions(jobTable(table));

  QTableWidget* view = widget.table(QStringLiteral("Job"));
  ASSERT_NE(view, nullptr);
  EXPECT_EQ(view->rowCount(), 2);
  EXPECT_EQ(view->columnCount(), 3);

  ASSERT_NE(view->item(0, 0), nullptr);
  EXPECT_EQ(view->item(0, 0)->text().toStdString(), "1963207");
  ASSERT_NE(view->item(0, 2), nullptr);
  EXPECT_EQ(view->item(0, 2)->text().toStdString(), "Molecular Energy");
  ASSERT_NE(view->item(1, 1), nullptr);
  EXPECT_EQ(view->item(1, 1)->text().toStdString(), "CH3F");
}

// The same data supplied column-wise has to produce the identical grid.
TEST(JsonWidgetTest, ColumnsPopulateInOrder)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  QJsonObject table;
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray columns;
  for (int i = 0; i < headers.size(); ++i)
    columns.append(toArray({ row0[i], row1[i] }));
  table.insert(QStringLiteral("columns"), columns);

  TestableJsonWidget widget;
  widget.setOptions(jobTable(table));

  QTableWidget* view = widget.table(QStringLiteral("Job"));
  ASSERT_NE(view, nullptr);
  EXPECT_EQ(view->rowCount(), 2);
  EXPECT_EQ(view->columnCount(), 3);

  ASSERT_NE(view->item(0, 0), nullptr);
  EXPECT_EQ(view->item(0, 0)->text().toStdString(), "1963207");
  ASSERT_NE(view->item(1, 2), nullptr);
  EXPECT_EQ(view->item(1, 2)->text().toStdString(), "NMR");
}

// A short row leaves the trailing cells empty rather than shifting them, and
// the header still fixes the column count.
TEST(JsonWidgetTest, RaggedRowsLeaveMissingCellsEmpty)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  QJsonObject table;
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  rows.append(toArray({ "1963205" }));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  widget.setOptions(jobTable(table));

  QTableWidget* view = widget.table(QStringLiteral("Job"));
  ASSERT_NE(view, nullptr);
  EXPECT_EQ(view->columnCount(), 3);
  ASSERT_NE(view->item(1, 0), nullptr);
  EXPECT_EQ(view->item(1, 0)->text().toStdString(), "1963205");
  EXPECT_EQ(view->item(1, 1), nullptr);
}

// A "selectable" table is a picker: the script gets the chosen row, and an
// empty string while nothing is chosen.
TEST(JsonWidgetTest, SelectableTableCollectsSelectedRow)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  QJsonObject table;
  table.insert(QStringLiteral("selectable"), true);
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  rows.append(toArray(row1));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  widget.setOptions(jobTable(table));

  QTableWidget* view = widget.table(QStringLiteral("Job"));
  ASSERT_NE(view, nullptr);

  QJsonObject collected = widget.collectOptions();
  ASSERT_TRUE(collected.contains(QStringLiteral("Job")));
  EXPECT_EQ(collected.value(QStringLiteral("Job")).toString().toStdString(), "")
    << "an unselected picker must not claim a row";

  view->selectRow(1);
  collected = widget.collectOptions();
  EXPECT_EQ(collected.value(QStringLiteral("Job")).toString().toStdString(),
            "1963205\tCH3F\tNMR");
}

// A selectable table honours a custom delimiter, so a script can pick one that
// cannot occur in its own data.
TEST(JsonWidgetTest, SelectableTableHonoursDelimiter)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  QJsonObject table;
  table.insert(QStringLiteral("selectable"), true);
  table.insert(QStringLiteral("delimiter"), QStringLiteral("|"));
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  widget.setOptions(jobTable(table));

  QTableWidget* view = widget.table(QStringLiteral("Job"));
  ASSERT_NE(view, nullptr);
  view->selectRow(0);

  EXPECT_EQ(widget.collectOptions()
              .value(QStringLiteral("Job"))
              .toString()
              .toStdString(),
            "1963207|H2N|Molecular Energy");
}

// An ordinary (non-selectable) table is an editable grid: its "default" string
// is parsed by setTableOption() and collectOptions() must give it back
// unchanged, with no headers to establish the column count.
TEST(JsonWidgetTest, EditableTableRoundTripsItsDefault)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  const QString contents = QStringLiteral("1.0\t2.0\t3.0\n4.0\t5.0\t6.0");

  QJsonObject table;
  table.insert(QStringLiteral("default"), contents);

  TestableJsonWidget widget;
  widget.setOptions(jobTable(table));

  QTableWidget* view = widget.table(QStringLiteral("Job"));
  ASSERT_NE(view, nullptr);
  EXPECT_EQ(view->rowCount(), 2);
  EXPECT_EQ(view->columnCount(), 3);

  EXPECT_EQ(widget.collectOptions()
              .value(QStringLiteral("Job"))
              .toString()
              .toStdString(),
            contents.toStdString());
}

// Sorting is applied after the rows are inserted, so the data must survive it,
// and a selection made afterwards must report the row the user actually sees.
TEST(JsonWidgetTest, SortableTableCollectsTheVisibleRow)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  QJsonObject table;
  table.insert(QStringLiteral("selectable"), true);
  table.insert(QStringLiteral("sortable"), true);
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0)); // 1963207
  rows.append(toArray(row1)); // 1963205
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  widget.setOptions(jobTable(table));

  QTableWidget* view = widget.table(QStringLiteral("Job"));
  ASSERT_NE(view, nullptr);
  EXPECT_TRUE(view->isSortingEnabled());
  EXPECT_EQ(view->rowCount(), 2);

  view->sortItems(0, Qt::AscendingOrder);
  view->selectRow(0);
  EXPECT_EQ(widget.collectOptions()
              .value(QStringLiteral("Job"))
              .toString()
              .toStdString(),
            "1963205\tCH3F\tNMR");
}

// Rebuilding the form has to take the old widgets with it. Deleting the layout
// leaves them behind as children, where they keep painting over the new form.
TEST(JsonWidgetTest, RebuildDiscardsTheOldForm)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  TestableJsonWidget widget;

  QJsonObject first;
  first.insert(QStringLiteral("Alpha"), stringOption());
  first.insert(QStringLiteral("Beta"), stringOption());
  widget.setOptions(first);

  QPointer<QWidget> alpha = widget.widgetFor(QStringLiteral("Alpha"));
  QPointer<QWidget> beta = widget.widgetFor(QStringLiteral("Beta"));
  ASSERT_FALSE(alpha.isNull());
  ASSERT_FALSE(beta.isNull());

  QJsonObject second;
  second.insert(QStringLiteral("Gamma"), stringOption());
  widget.setOptions(second);

  // Off the form immediately: an orphan that is merely scheduled for deletion
  // would still be drawn until the event loop next runs.
  const QList<QWidget*> children =
    widget.findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
  EXPECT_FALSE(children.contains(alpha.data()));
  EXPECT_FALSE(children.contains(beta.data()));
  EXPECT_NE(widget.widgetFor(QStringLiteral("Gamma")), nullptr);
  EXPECT_EQ(children.size(), 2) << "one field plus the label QFormLayout makes";

  // ...and genuinely freed, not just orphaned.
  QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
  EXPECT_TRUE(alpha.isNull());
  EXPECT_TRUE(beta.isNull());
}

// An option set with nothing in it must report itself empty, so that Command
// runs the script straight away instead of showing a blank dialog.
TEST(JsonWidgetTest, RebuildWithoutOptionsReportsEmpty)
{
  if (ensureApp() == nullptr)
    GTEST_SKIP() << "a non-GUI QCoreApplication already exists";

  TestableJsonWidget widget;

  QJsonObject first;
  first.insert(QStringLiteral("Alpha"), stringOption());
  widget.setOptions(first);
  EXPECT_FALSE(widget.isEmpty());

  widget.setRawOptions(QJsonObject());
  EXPECT_TRUE(widget.isEmpty());
}
