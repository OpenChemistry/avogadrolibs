/** \example datastore_iterators.cpp
 * Iterator-base data Management in JKQTPDatastore.
 *
 * \ref JKQTPlotterBasicJKQTPDatastoreIterators
 */

#include <QApplication>
#include "jkqtplotter/jkqtplotter.h"
#include "jkqtplotter/graphs/jkqtpscatter.h"
#include "jkqtplotter/graphs/jkqtpimage.h"
#include <algorithm>

int main(int argc, char* argv[])
{

#if QT_VERSION >= QT_VERSION_CHECK(5, 6, 0) &&                                 \
  QT_VERSION < QT_VERSION_CHECK(6, 0, 0)

  QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);  // DPI support
  QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps); // HiDPI pixmaps
#endif
  QApplication app(argc, argv);

  // 1. create a plotter window and get a pointer to the internal datastore (for
  // convenience)
  JKQTPlotter plot;
  JKQTPDatastore* datastore = plot.getDatastore();

  JKQTPXYLineGraph* linegraph;

  // 2. now we create a cos-curve plot with the standard means of
  // JKQTPDatastore::addColumn(NRows, "name")
  //    and JKQTPDatastore::set() to actually set the values:
  // size_t XCol=datastore->addLinearColumn(50, 0, 4.0*JKQTPSTATISTICS_PI, "cos
  // curve: x-data"); size_t YCol=datastore->addColumn(datastore->getRows(XCol),
  // "cos curve: y-data"); for (size_t i=0; i<datastore->getRows(XCol); i++) {
  //    datastore->set(YCol, i, cos(datastore->get(XCol, i)));
  //}
  // 2.1. the for-loop above can also be expressed in terms of (random-access)
  // iterators:
  // auto itY=datastore->begin(YCol);
  // for (auto itX=datastore->begin(XCol); itX!=datastore->end(XCol); ++itX,
  // ++itY) {
  //    *itY=cos(*itX);
  //}
  // 2.2 with backInserter() you can generate an object liek a
  // std::back_inserter, which
  //     removes the requirement to pre-allocate the columns:
  size_t XCol = datastore->addColumn("cos curve: x-data");
  size_t YCol = datastore->addColumn("cos curve: y-data");
  auto biXCol = datastore->backInserter(XCol);
  auto biYCol = datastore->backInserter(YCol);
  for (double x = 0; x < 4.0 * JKQTPSTATISTICS_PI;
       x += 4.0 * JKQTPSTATISTICS_PI / 50.0) {
    *biXCol = x;
    *biYCol = cos(x);
    ++biXCol;
    ++biYCol;
  }
  // 2.3 combining with addLinearColumn() you can also use C++ STL algorithms:
  // size_t XCol=datastore->addLinearColumn(50, 0, 4.0*JKQTPSTATISTICS_PI, "cos
  // curve: x-data"); size_t YCol=datastore->addColumn("cos curve: y-data");
  // std::transform(datastore->begin(XCol), datastore->end(XCol),
  // datastore->backInserter(YCol), cos);
  // 2.4. Just for fun we can now sort the data:
  // std::sort(datastore->begin(YCol), datastore->end(YCol));
  //      or replace any value <-0.5 with 1:
  // std::replace_if(datastore->begin(YCol), datastore->end(YCol), [](double v)
  // { return v<-0.5; }, 1.0);
  // 2.5. Also the erase-remove idiom is supported:
  // datastore->eraseFromColumn(std::remove_if(datastore->begin(YCol),
  // datastore->end(YCol), [](double v) { return v<0; }), datastore->end(YCol));

  plot.addGraph(linegraph = new JKQTPXYLineGraph(&plot));
  linegraph->setXColumn(XCol);
  linegraph->setYColumn(YCol);
  linegraph->setTitle(QObject::tr("cosine graph"));

  // 6. autoscale the plot so the graph is contained
  plot.zoomToFit();

  // show plotter and make it a decent size
  plot.show();
  plot.resize(600, 400);

  return app.exec();
}
