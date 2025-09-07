#include "TestWidgetEmptyPlot.h"
#include <QDebug>
#include <QDate>
#include <QDateTime>
#include <QApplication>
#include "jkqtplotter/graphs/jkqtpscatter.h"

TestWidgetEmptyPlot::TestWidgetEmptyPlot(QWidget* parent) : QWidget(parent)
{

#define NEMPTY 500

  JKQTPlotter* plotEmpty = new JKQTPlotter(true, this);
  JKQTPXYLineGraph* efunc = new JKQTPXYLineGraph(plotEmpty->getPlotter());
  double xef[NEMPTY], efy[NEMPTY];
  for (int i = 0; i < NEMPTY; i++) {
    xef[i] = i;
    efy[i] = double(i % 5) * 1e-308;
  }
  efunc->setXColumn(
    plotEmpty->getDatastore()->addCopiedColumn(xef, NEMPTY, "x"));
  efunc->setYColumn(
    plotEmpty->getDatastore()->addCopiedColumn(efy, NEMPTY, "y"));
  plotEmpty->addGraph(efunc);
  plotEmpty->getYAxis()->setLogAxis(true);
  plotEmpty->zoomToFit();
  plotEmpty->setY(0, 0);
}
