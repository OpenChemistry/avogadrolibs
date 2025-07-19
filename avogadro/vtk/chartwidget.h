/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#pragma once

#include "avogadrovtkexport.h"

#include <QWidget>

#include <array>
#include <string>

#include <vtkNew.h>

class vtkAxis;
class vtkChartXY;
class vtkContextView;
class vtkTable;

namespace Avogadro::VTK {

typedef std::array<unsigned char, 4> color4ub;

class QVTKWidget;

class AVOGADROVTK_EXPORT ChartWidget : public QWidget
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
               const color4ub& color = color4ub{ 0, 0, 0, 255 });

  bool addSeries(const std::vector<float>& y,
                 const color4ub& color = color4ub{ 0, 0, 0, 255 });

  bool addPlots(const std::vector<std::vector<float>>& plotData,
                const color4ub& color = color4ub{ 0, 0, 0, 255 });

  void clearPlots();

  void setXAxisTitle(const std::string& title);

  void setYAxisTitle(const std::string& title);

  void setTickLabels(Axis a, const std::vector<float>& tickPositions,
                     const std::vector<std::string>& tickLabels);

  void setAxisLimits(Axis a, float min, float max);
  void setXAxisLimits(float min, float max);
  void setYAxisLimits(float min, float max);

  void setFontSize(int size = 14);
  void setLineWidth(float width = 1.0);

  void setAxisLogScale(Axis a, bool logScale);

private:
  void renderViews();
  float m_lineWidth = 1.0;
  vtkAxis* axis(Axis a);

  vtkNew<vtkContextView> m_view;
  vtkNew<vtkChartXY> m_chart;
  vtkNew<vtkTable> m_table;

  QVTKWidget* m_qvtk;
};

} // namespace Avogadro::VTK
