/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_CHARTWIDGET_H
#define AVOGADRO_QTGUI_CHARTWIDGET_H

#include "avogadroqtguiexport.h"

#include <QWidget>

#include <array>
#include <string>

namespace Avogadro::QtGui {

typedef std::array<unsigned char, 4> color4ub;

class AVOGADROQTGUI_EXPORT ChartWidget : public QWidget
{
  Q_OBJECT

public:
  explicit ChartWidget(QWidget* p = nullptr);
  ~ChartWidget() override;

  enum class Axis
  {
    x,
    y
  };

  bool addPlot(const std::vector<float>& x, const std::vector<float>& y,
               const color4ub& color = color4ub{ 0, 0, 0, 255 },
               const QString& xName = "x", const QString& yName = "y");

  bool addSeries(const std::vector<float>& y,
                 const color4ub& color = color4ub{ 0, 0, 0, 255 },
                 const QString& name = "");

  bool addPlots(const std::vector<std::vector<float>>& plotData,
                const color4ub& color = color4ub{ 0, 0, 0, 255 },
                const QStringList& names = {});

  void clearPlots();

  void setXAxisTitle(const QString& title);
  void setYAxisTitle(const QString& title);

  void setTickLabels(Axis a, const std::vector<float>& tickPositions,
                     const QStringList& tickLabels);

  void setAxisLimits(Axis a, float min, float max);
  void setXAxisLimits(float min, float max);
  void setYAxisLimits(float min, float max);

  void setFontSize(int size = 14);
  void setLineWidth(float width = 1.0);

  void setAxisLogScale(Axis a, bool logScale);

  void setAxisDigits(Axis a, int digits = 2);

  void labelPeaks(int yColumn = 1, float threshold = 1.0, int windowSize = 5);

  void resetZoom();

private:
  void renderViews();
  float m_lineWidth = 1.0;

  // private members
  class ChartWidgetImpl;
  ChartWidgetImpl* m_impl;
};

} // namespace Avogadro::QtGui

#endif // AVOGADRO_QTGUI_CHARTWIDGET_H
