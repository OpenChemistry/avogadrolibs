/** \example dateaxes.cpp
 * Shows how to use date/time axes with JKQTPlotter
 *
 * \ref JKQTPlotterDateTimeAxes
 */

#include <QApplication>
#include <QDateTime>
#include <QTime>
#include <QFile>
#include <QTextStream>
#include "jkqtplotter/jkqtplotter.h"
#include "jkqtplotter/graphs/jkqtpscatter.h"
#include "jkqtplotter/graphs/jkqtpgeometric.h"
#include "jkqtplotter/jkqtptools.h"
#include "jkqtplotter/graphs/jkqtpfilledcurve.h"

void drawWithDateAxis(JKQTPlotter& plot)
{

  // 1. create a plotter window and get a pointer to the internal datastore (for
  // convenience)
  JKQTPDatastore* ds = plot.getDatastore();

  // 2. now we create data vectors with data parsed from a CSV-file
  QVector<double> date;
  QVector<double> temperature, temperature_min, temperature_max;
  // parse a textfile with comments on the first line and the
  // semicolon separated data. The first column is a date and time
  // the second to fourth columns contain a floating-point number
  // with temperature average, min and max
  QFile file(":/weatherdata_gelsenkirchen.csv");
  file.open(QFile::ReadOnly | QFile::Text);
  file.readLine(); // eat comment
  while (!file.atEnd()) {
    QString line = file.readLine();
    QTextStream in(&line);
    QStringList items = line.split(";");
    // date/time values are stored as doubles representing the corresponding
    // number of milliseconds sind epoch
    date << QDateTime::fromString(items[0], Qt::ISODate)
              .toUTC()
              .toMSecsSinceEpoch();
    // store Heidelbergs daily temperature
    temperature << items[1].toDouble();
    temperature_min << items[2].toDouble();
    temperature_max << items[3].toDouble();
  }

  // 3. add a plot for the data mean line (graphTemperature) and range
  // (graphTemperatureRange)
  JKQTPFilledVerticalRangeGraph* graphTemperatureRange =
    new JKQTPFilledVerticalRangeGraph(&plot);
  JKQTPXYLineErrorGraph* graphTemperature = new JKQTPXYLineErrorGraph(&plot);

  // 4. copy data into datastore and immediately set the yColumn
  size_t colDate = ds->addCopiedColumn(date, "date");
  graphTemperature->setXColumn(colDate);
  graphTemperature->setYColumn(ds->addCopiedColumn(temperature, "temperature"));
  graphTemperatureRange->setXColumn(colDate);
  graphTemperatureRange->setYColumn(
    ds->addCopiedColumn(temperature_min, "temperature_min"));
  graphTemperatureRange->setYColumn2(
    ds->addCopiedColumn(temperature_max, "temperature_max"));

  // 5. min/max range data
  // graph fill color is a lighter shade of the average graph
  graphTemperatureRange->setFillColor(
    graphTemperature->getLineColor().lighter());
  // don't draw lines of the data
  graphTemperatureRange->setDrawLine(false);
  // plot label in key
  graphTemperatureRange->setTitle("Min/Max Temperature");
  // add the graph to the plot, so it is actually displayed
  plot.addGraph(graphTemperatureRange);

  // 6. average data
  // don't use symbols
  graphTemperature->setSymbolType(JKQTPNoSymbol);
  // set the line width
  graphTemperature->setLineWidth(1);
  // draw small symbols
  graphTemperature->setSymbolSize(6);
  // graph title
  graphTemperature->setTitle("Average Temperature");
  // add the graph to the plot, so it is actually displayed
  plot.addGraph(graphTemperature);

  // 7. format the plot
  // set the title above the plot, use LaTeX instructions to make text bold
  plot.getPlotter()->setPlotLabel(
    "\\textbf{Weather in Gelsenkirchen, 2017-2018}");
  // set x-axis date-time-axis
  plot.getXAxis()->setLabelType(JKQTPCALTdatetime);
  plot.getXAxis()->setAxisLabel("Date");
  // set format string for date axis (e.g. Jan '18), see Documentation of
  // QDateTime::toString()
  plot.getXAxis()->setTickDateTimeFormat("MMM ''yy");
  // set y-axis temperature axis
  plot.getYAxis()->setAxisLabel("Average Daily Temperature [{\\degree}C]");

  // 8. autoscale the plot so the graph is contained
  plot.zoomToFit();

  // 9. show plotter and make it a decent size
  plot.show();
  plot.resize(600, 400);
  plot.setWindowTitle("Date Axis");
}

void drawWithTimeAxis(JKQTPlotter& plot)
{
  // 1. create a plotter window and get a pointer to the internal datastore (for
  // convenience)
  JKQTPDatastore* ds = plot.getDatastore();

  // 2. now we create data vectors with data parsed from a CSV-file
  QVector<double> time;
  QVector<double> temperature;
  // parse a textfile with comments on the first line and the
  // semicolon separated data. The first column is a time
  // the second contain a floating-point number with temperatures
  QFile file(":/weatherdata_heidelberg_2018-10-14.csv");
  file.open(QFile::ReadOnly | QFile::Text);
  file.readLine(); // eat comment
  while (!file.atEnd()) {
    QString line = file.readLine();
    QTextStream in(&line);
    QStringList items = line.split(";");
    // date/time values are stored as doubles representing the corresponding
    // number of milliseconds sind epoch. Since the data is time only, we have
    // to use an arbitrary date as basis
    time << QDateTime::fromString("1970-01-01T" + items[0], Qt::ISODate)
              .toMSecsSinceEpoch();
    // store Heidelbergs daily temperature
    temperature << items[1].toDouble();
  }

  // 3. add a plot for the data mean line (graphTemperature) and range
  // (graphTemperatureRange)
  JKQTPXYLineErrorGraph* graphTemperature = new JKQTPXYLineErrorGraph(&plot);

  // 4. copy data into datastore and immediately set the yColumn
  size_t colDate = ds->addCopiedColumn(time, "time");
  graphTemperature->setXColumn(colDate);
  graphTemperature->setYColumn(ds->addCopiedColumn(temperature, "temperature"));

  // 6. average data
  // don't use symbols
  graphTemperature->setSymbolType(JKQTPCross);
  // set the line width
  graphTemperature->setLineWidth(1);
  // draw small symbols
  graphTemperature->setSymbolSize(6);
  // graph title
  graphTemperature->setTitle("Average Temperature");
  // add the graph to the plot, so it is actually displayed
  plot.addGraph(graphTemperature);

  // 7. format the plot
  // set the title above the plot, use LaTeX instructions to make text bold
  plot.getPlotter()->setPlotLabel(
    "\\textbf{Weather in Heidelberg, 14^{th} Oct 2018}");
  // set x-axis date-time-axis
  plot.getXAxis()->setLabelType(JKQTPCALTtime);
  plot.getXAxis()->setAxisLabel("Time of Day");
  // set format string for time axis with 24-hour and minute only,
  // see QDateTime::toString() documentation for details on format strings
  plot.getXAxis()->setTickTimeFormat("HH:mm");
  // set y-axis temperature axis
  plot.getYAxis()->setAxisLabel("Temperature [{\\degree}C]");

  // 8. autoscale the plot so the graph is contained
  plot.zoomToFit();

  // 9. show plotter and make it a decent size
  plot.show();
  plot.resize(600, 400);
  plot.setWindowTitle("Time Axis");
}

int main(int argc, char* argv[])
{

#if QT_VERSION >= QT_VERSION_CHECK(5, 6, 0) &&                                 \
  QT_VERSION < QT_VERSION_CHECK(6, 0, 0)

  QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);  // DPI support
  QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps); // HiDPI pixmaps
#endif
  QApplication app(argc, argv);

  JKQTPlotter plotDate;
  drawWithDateAxis(plotDate);
  plotDate.move(100, 100);
  JKQTPlotter plotTime;
  drawWithTimeAxis(plotTime);
  plotTime.move(100, 550);

  return app.exec();
}
