/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/interfacewidget.h>
#include <avogadro/qtgui/jsonwidget.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QPointer>
#include <QtWidgets/QApplication>
#include <QtWidgets/QTableWidget>

using Avogadro::QtGui::InterfaceWidget;
using Avogadro::QtGui::JsonWidget;

namespace {

/// The full options object an InterfaceScript hands to the widget.
QJsonObject wrapOptions(const QJsonObject& userOptions)
{
  QJsonObject options;
  options.insert(QStringLiteral("userOptions"), userOptions);
  return options;
}

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

  /// Replace the options wholesale, without the "userOptions" wrapper.
  void setRawOptions(const QJsonObject& options)
  {
    m_options = options;
    updateOptions();
  }

  void setOptions(const QJsonObject& userOptions)
  {
    setRawOptions(wrapOptions(userOptions));
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

/// Build the form for a lone "table" option named "Job" and hand back its view.
QTableWidget* buildTable(TestableJsonWidget& widget, const QJsonObject& table)
{
  widget.setOptions(jobTable(table));
  return widget.table(QStringLiteral("Job"));
}

const QStringList headers = { "Job", "Name", "Calculation" };
const QStringList row0 = { "1963207", "H2N", "Molecular Energy" };
const QStringList row1 = { "1963205", "CH3F", "NMR" };

} // namespace

/**
 * Every case needs a QApplication before it can build a widget, and skips
 * rather than fails if another test in this binary got in first with a plain
 * QCoreApplication.
 */
class JsonWidgetTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    if (ensureApp() == nullptr)
      GTEST_SKIP() << "a non-GUI QCoreApplication already exists";
  }
};

// Rows are arrays of cells; setItem() takes (row, column) in that order, so a
// table given by rows must come back with row 0 holding row0.
TEST_F(JsonWidgetTest, RowsPopulateInOrder)
{
  QJsonObject table;
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  rows.append(toArray(row1));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
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
TEST_F(JsonWidgetTest, ColumnsPopulateInOrder)
{
  QJsonObject table;
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray columns;
  for (int i = 0; i < headers.size(); ++i)
    columns.append(toArray({ row0[i], row1[i] }));
  table.insert(QStringLiteral("columns"), columns);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
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
TEST_F(JsonWidgetTest, RaggedRowsLeaveMissingCellsEmpty)
{
  QJsonObject table;
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  rows.append(toArray({ "1963205" }));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
  ASSERT_NE(view, nullptr);
  EXPECT_EQ(view->columnCount(), 3);
  ASSERT_NE(view->item(1, 0), nullptr);
  EXPECT_EQ(view->item(1, 0)->text().toStdString(), "1963205");
  EXPECT_EQ(view->item(1, 1), nullptr);
}

// A "selectable" table is a picker: the script gets the chosen row, and an
// empty string while nothing is chosen.
TEST_F(JsonWidgetTest, SelectableTableCollectsSelectedRow)
{
  QJsonObject table;
  table.insert(QStringLiteral("selectable"), true);
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  rows.append(toArray(row1));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
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
TEST_F(JsonWidgetTest, SelectableTableHonoursDelimiter)
{
  QJsonObject table;
  table.insert(QStringLiteral("selectable"), true);
  table.insert(QStringLiteral("delimiter"), QStringLiteral("|"));
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0));
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
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
TEST_F(JsonWidgetTest, EditableTableRoundTripsItsDefault)
{
  const QString contents = QStringLiteral("1.0\t2.0\t3.0\n4.0\t5.0\t6.0");

  QJsonObject table;
  table.insert(QStringLiteral("default"), contents);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
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
TEST_F(JsonWidgetTest, SortableTableCollectsTheVisibleRow)
{
  QJsonObject table;
  table.insert(QStringLiteral("selectable"), true);
  table.insert(QStringLiteral("sortable"), true);
  table.insert(QStringLiteral("headers"), toArray(headers));
  QJsonArray rows;
  rows.append(toArray(row0)); // 1963207
  rows.append(toArray(row1)); // 1963205
  table.insert(QStringLiteral("rows"), rows);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
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
TEST_F(JsonWidgetTest, RebuildDiscardsTheOldForm)
{
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
TEST_F(JsonWidgetTest, RebuildWithoutOptionsReportsEmpty)
{
  TestableJsonWidget widget;

  QJsonObject first;
  first.insert(QStringLiteral("Alpha"), stringOption());
  widget.setOptions(first);
  EXPECT_FALSE(widget.isEmpty());

  widget.setRawOptions(QJsonObject());
  EXPECT_TRUE(widget.isEmpty());
}

// Command::menuActivated() refreshes a cached dialog for a "dynamic" feature by
// pushing a freshly generated option set through the same InterfaceWidget. The
// new set has to replace the old one outright rather than accumulate on it.
TEST_F(JsonWidgetTest, InterfaceWidgetReloadsOptionsInPlace)
{
  InterfaceWidget widget{ QString() };

  QJsonObject alpha;
  alpha.insert(QStringLiteral("Alpha"), stringOption());
  widget.interfaceScript().setOptionsJson(wrapOptions(alpha));
  widget.reloadOptions();

  EXPECT_FALSE(widget.isEmpty());
  EXPECT_TRUE(widget.collectOptions().contains(QStringLiteral("Alpha")));

  QJsonObject gamma;
  gamma.insert(QStringLiteral("Gamma"), stringOption());
  widget.interfaceScript().setOptionsJson(wrapOptions(gamma));
  widget.reloadOptions();

  const QJsonObject collected = widget.collectOptions();
  EXPECT_TRUE(collected.contains(QStringLiteral("Gamma")));
  EXPECT_FALSE(collected.contains(QStringLiteral("Alpha")))
    << "the previous option set must not survive the refresh";
  EXPECT_EQ(collected.size(), 1);
}

// A table that is both "sortable" and filled from a "default" has its cells
// inserted while sorting is live, and QTableWidget re-sorts on every setItem(),
// moving rows out from under the insertion. The default must survive intact.
TEST_F(JsonWidgetTest, SortableTableKeepsItsDefaultIntact)
{
  const QString contents = QStringLiteral("3\tgamma\n1\talpha\n2\tbeta");

  QJsonObject table;
  table.insert(QStringLiteral("sortable"), true);
  table.insert(QStringLiteral("default"), contents);

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
  ASSERT_NE(view, nullptr);
  EXPECT_EQ(view->rowCount(), 3);
  EXPECT_EQ(view->columnCount(), 2);

  EXPECT_EQ(widget.collectOptions()
              .value(QStringLiteral("Job"))
              .toString()
              .toStdString(),
            contents.toStdString());
}

// Once the user clicks a header the sort indicator sits on a live column, and
// a later applyOptions() (forcefielddialog, or InputGeneratorWidget reverting
// to its cached options) refills the table. Sorting has to be suspended for
// that, or QTableWidget shuffles rows between setItem() calls and each row
// ends up holding cells that belong to its neighbours.
TEST_F(JsonWidgetTest, SortedTableSurvivesANewDefault)
{
  QJsonObject table;
  table.insert(QStringLiteral("sortable"), true);
  table.insert(QStringLiteral("headers"), toArray({ "Num", "Word" }));
  table.insert(QStringLiteral("default"), QStringLiteral("3\tgamma"));

  TestableJsonWidget widget;
  QTableWidget* view = buildTable(widget, table);
  ASSERT_NE(view, nullptr);
  view->sortByColumn(0, Qt::AscendingOrder);

  QJsonObject opts;
  opts.insert(QStringLiteral("Job"),
              QStringLiteral("3\tgamma\n1\talpha\n2\tbeta"));
  widget.applyOptions(opts);

  ASSERT_EQ(view->rowCount(), 3);
  ASSERT_EQ(view->columnCount(), 2);

  // Every number must still be beside its own word. The view is sorted on
  // column 0, so the rows read in numeric order.
  const QStringList expected = { "1\talpha", "2\tbeta", "3\tgamma" };
  for (int row = 0; row < 3; ++row) {
    ASSERT_NE(view->item(row, 0), nullptr) << "row " << row << " column 0";
    ASSERT_NE(view->item(row, 1), nullptr) << "row " << row << " column 1";
    const QString actual =
      view->item(row, 0)->text() + '\t' + view->item(row, 1)->text();
    EXPECT_EQ(actual.toStdString(), expected.at(row).toStdString());
  }
}
