/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chartwidget.h"

#include <jkqtplotter/jkqtplotter.h>
#include <jkqtplotter/graphs/jkqtplines.h>

#include <QDebug>
#include <QHBoxLayout>

namespace Avogadro::QtGui {

class ChartWidget::ChartWidgetImpl
{
public:
  ChartWidgetImpl()
  {
    plot = new JKQTPlotter;
    // set the default text color for dark and light mode
    const QPalette defaultPalette;
    // is the text lighter than the window color?
    bool darkMode = (defaultPalette.color(QPalette::WindowText).lightness() >
                     defaultPalette.color(QPalette::Window).lightness());

    if (darkMode) {
      plot->getXAxis()->setTickLabelColor(Qt::white);
      plot->getYAxis()->setTickLabelColor(Qt::white);
      plot->getXAxis()->setLabelColor(Qt::white);
      plot->getYAxis()->setLabelColor(Qt::white);
    } else {
      plot->getXAxis()->setTickLabelColor(Qt::black);
      plot->getYAxis()->setTickLabelColor(Qt::black);
      plot->getXAxis()->setLabelColor(Qt::black);
      plot->getYAxis()->setLabelColor(Qt::black);
    }
  }
  ~ChartWidgetImpl() { delete plot; }

  // copy constructor
  ChartWidgetImpl(const ChartWidgetImpl& other) { plot = other.plot; }

  // copy assignment
  ChartWidgetImpl& operator=(const ChartWidgetImpl& other)
  {
    plot = other.plot;
    return *this;
  }
  // move constructor
  ChartWidgetImpl(ChartWidgetImpl&& other) { plot = other.plot; }

  // move assignment
  ChartWidgetImpl& operator=(ChartWidgetImpl&& other)
  {
    plot = other.plot;
    return *this;
  }

  JKQTPlotter* plot; // widget
};

ChartWidget::ChartWidget(QWidget* p) : QWidget(p), m_impl(new ChartWidgetImpl)
{
  auto hLayout = new QHBoxLayout(this);
  auto* plot = m_impl->plot;

  // connect the single-click and double-click signals
  connect(plot, &JKQTPlotter::plotMouseClicked, this,
          &ChartWidget::plotClicked);
  connect(plot, &JKQTPlotter::plotMouseDoubleClicked, this,
          &ChartWidget::resetZoom);

  hLayout->setContentsMargins(0, 0, 0, 0);
  hLayout->addWidget(plot);
  setLayout(hLayout);
  setMinimumWidth(100);
  setMinimumHeight(100);
}

ChartWidget::~ChartWidget() = default;

bool ChartWidget::addPlot(const std::vector<float>& x,
                          const std::vector<float>& y,
                          const std::array<unsigned char, 4>& color,
                          const QString& xName, const QString& yName)
{
  // The x and y arrays must be of the same length, otherwise it is not x, y...
  if (x.size() != y.size())
    return false;

  auto* plot = m_impl->plot;
  if (plot == nullptr)
    return false;

  auto* ds = plot->getDatastore();
  size_t columnX = ds->addCopiedColumn(x, xName);
  size_t columnY = ds->addCopiedColumn(y, yName);

  JKQTPXYLineGraph* graph = new JKQTPXYLineGraph(plot);
  graph->setXColumn(columnX);
  graph->setYColumn(columnY);
  graph->setSymbolType(JKQTPNoSymbol);
  graph->setLineWidth(m_lineWidth);

  QColor c(color[0], color[1], color[2], color[3]);
  graph->setLineColor(c, color[3] / 255.0);
  graph->setTitle(yName);

  plot->addGraph(graph);
  return true;
}

bool ChartWidget::addSeries(const std::vector<float>& newSeries,
                            const std::array<unsigned char, 4>& color,
                            const QString& name)
{
  if (newSeries.empty())
    return false;

  auto* plot = m_impl->plot;
  if (plot == nullptr)
    return false;

  auto* ds = plot->getDatastore();
  // get the x column
  size_t maxRows = ds->getMaxRows();
  if (newSeries.size() != maxRows)
    return false;

  size_t columnY = ds->addCopiedColumn(newSeries, name);

  JKQTPXYLineGraph* graph = new JKQTPXYLineGraph(plot);
  graph->setXColumn(0);
  graph->setYColumn(columnY);
  graph->setSymbolType(JKQTPNoSymbol);
  graph->setLineWidth(m_lineWidth);

  QColor c(color[0], color[1], color[2], color[3]);
  graph->setLineColor(c, color[3] / 255.0);
  graph->setTitle(name);

  plot->addGraph(graph);
  return true;
}

bool ChartWidget::addPlots(const std::vector<std::vector<float>>& plotData,
                           const std::array<unsigned char, 4>& color,
                           const QStringList& names)
{
  // Need at least an x and a y.
  if (plotData.size() < 2)
    return false;

  // All arrays must be the same size to go in the same table.
  auto xSize = plotData[0].size();
  for (const auto& d : plotData)
    if (xSize != d.size())
      return false;

  // check to make sure names is the same size as plotData
  if (names.size() != plotData.size())
    return false;

  auto* plot = m_impl->plot;
  if (plot == nullptr)
    return false;

  auto* ds = plot->getDatastore();
  const QString xName = names[0];
  size_t columnX = ds->addCopiedColumn(plotData[0], xName);
  QColor c(color[0], color[1], color[2], color[3]);

  // loop through the columns
  for (size_t i = 1; i < plotData.size(); i++) {
    const QString yName = names[i];
    size_t columnY = ds->addCopiedColumn(plotData[i], yName);

    JKQTPXYLineGraph* graph = new JKQTPXYLineGraph(plot);
    graph->setXColumn(columnX);
    graph->setYColumn(columnY);
    graph->setSymbolType(JKQTPNoSymbol);
    graph->setLineWidth(m_lineWidth);
    graph->setLineColor(c, color[3] / 255.0);
    graph->setTitle(yName);

    plot->addGraph(graph);
  }

  return true;
}

void ChartWidget::resetZoom()
{
  m_impl->plot->zoomToFit();
}

void ChartWidget::plotClicked(double x, double y,
                              Qt::KeyboardModifiers modifiers,
                              Qt::MouseButton button)
{
  emit clicked(x, y, modifiers);
}

void ChartWidget::clearPlots()
{
  m_impl->plot->clearGraphs();
  m_impl->plot->getDatastore()->clear();
}

void ChartWidget::setXAxisTitle(const QString& title)
{
  QString label = QString("{\\bf %1 }").arg(title);
  m_impl->plot->getXAxis()->setAxisLabel(label);
}

void ChartWidget::setYAxisTitle(const QString& title)
{
  QString label = QString("{\\bf %1 }").arg(title);
  m_impl->plot->getYAxis()->setAxisLabel(label);
}

void ChartWidget::setFontSize(int size)
{
  auto* plot = m_impl->plot;
  plot->getXAxis()->setTickLabelFontSize(size);
  plot->getYAxis()->setTickLabelFontSize(size);

  int titleSize = round(size * 1.25);
  plot->getXAxis()->setLabelFontSize(titleSize);
  plot->getYAxis()->setLabelFontSize(titleSize);
}

void ChartWidget::setLineWidth(float width)
{
  m_lineWidth = width;
  for (auto* g : m_impl->plot->getGraphs()) {
    auto* lineGraph = dynamic_cast<JKQTPXYLineGraph*>(g);
    if (lineGraph != nullptr)
      lineGraph->setLineWidth(m_lineWidth);
  }
  // redraw
  m_impl->plot->update();
}

void ChartWidget::setAxisColor(Axis a, const color4ub& color)
{
  QColor c(color[0], color[1], color[2], color[3]);
  if (a == Axis::x) {
    m_impl->plot->getXAxis()->setAxisColor(c);
  } else {
    m_impl->plot->getYAxis()->setAxisColor(c);
  }
}

void ChartWidget::setBackgroundColor(const color4ub& color)
{
  QColor c(color[0], color[1], color[2], color[3]);
  m_impl->plot->getPlotter()->setPlotBackgroundColor(c);
}

void ChartWidget::setLegendLocation(LegendLocation location)
{

  m_impl->plot->getPlotter()->setShowKey(true);
  switch (location) {
    case LegendLocation::TopLeft:
      m_impl->plot->getPlotter()->setKeyPosition(JKQTPKeyInsideTopLeft);
      break;
    case LegendLocation::TopRight:
      m_impl->plot->getPlotter()->setKeyPosition(JKQTPKeyInsideTopRight);
      break;
    case LegendLocation::BottomLeft:
      m_impl->plot->getPlotter()->setKeyPosition(JKQTPKeyInsideBottomLeft);
      break;
    case LegendLocation::BottomRight:
      m_impl->plot->getPlotter()->setKeyPosition(JKQTPKeyInsideBottomRight);
      break;
    default:
      m_impl->plot->getPlotter()->setShowKey(false);
      break;
  }
}

void ChartWidget::setTickLabels(Axis a, const std::vector<float>& tickPositions,
                                const QStringList& tickLabels)
{
  // check to see if they're the same size
  if (tickPositions.size() != tickLabels.size())
    return;

  if (tickPositions.size() == 0)
    return;

  JKQTPCoordinateAxis* axis;
  if (a == Axis::x) {
    axis = m_impl->plot->getXAxis();
  } else {
    axis = m_impl->plot->getYAxis();
  }

  for (int i = 0; i < tickPositions.size(); i++) {
    axis->addAxisTickLabel(tickPositions[i], tickLabels[i]);
  }
}

void ChartWidget::setAxisLimits(Axis a, float min, float max)
{
  bool inverted = (min > max);

  if (inverted)
    std::swap(min, max);

  if (a == Axis::x) {
    m_impl->plot->getXAxis()->setRange(min, max);
    m_impl->plot->getXAxis()->setInverted(inverted);
  } else {
    m_impl->plot->getYAxis()->setRange(min, max);
    m_impl->plot->getYAxis()->setInverted(inverted);
  }
}

void ChartWidget::setXAxisLimits(float min, float max)
{
  setAxisLimits(Axis::x, min, max);
}

void ChartWidget::setYAxisLimits(float min, float max)
{
  setAxisLimits(Axis::y, min, max);
}

void ChartWidget::setAxisLogScale(Axis a, bool logScale)
{
  if (a == Axis::x)
    m_impl->plot->getXAxis()->setLogAxis(logScale);
  else
    m_impl->plot->getYAxis()->setLogAxis(logScale);
}

void ChartWidget::setAxisDigits(Axis a, int digits)
{
  if (a == Axis::x)
    m_impl->plot->getXAxis()->setLabelDigits(digits);
  else
    m_impl->plot->getYAxis()->setLabelDigits(digits);
}

void ChartWidget::labelPeaks(int yColumn, float threshold, int window)
{
  std::vector<std::pair<float, float>> peaks;

  /*  auto& x = m_impl->plot->getDatastore()->getColumn(0);
    auto& y = m_impl->plot->getDatastore()->getColumn(yColumn);

    const int n = static_cast<int>(y.size());
    if (n == 0)
      return peaks;

    int i = 0;
    while (i < n) {
      if (y[i] <= threshold) {
        ++i;
        continue;
      }

      // --- We’re inside a peak region ---
      int regionStart = std::max(0, i - window);
      int regionEnd = std::min(n - 1, i + window);

      // Expand region forward while we're above threshold
      while (regionEnd + 1 < n && y[regionEnd + 1] > threshold)
        ++regionEnd;

      // Find max within this region
      int maxIdx = regionStart;
      for (int j = regionStart + 1; j <= regionEnd; ++j) {
        if (y[j] > y[maxIdx])
          maxIdx = j;
      }

      peaks.emplace_back(x[maxIdx], y[maxIdx]);

      // Skip past this region to avoid duplicates
      i = regionEnd + 1;
    }
  */

  // add them to the plot
}

} // namespace Avogadro::QtGui
