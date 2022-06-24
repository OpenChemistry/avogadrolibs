/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_VTK_VTKPLOT_H
#define AVOGADRO_VTK_VTKPLOT_H

#include "avogadrovtkexport.h"

#include <vtkNew.h>

#include <array>
#include <memory>
#include <string>
#include <vector>

class QVTKOpenGLStereoWidget;
class vtkAxis;
class vtkChartXY;
class vtkContextView;
class vtkGenericOpenGLRenderWindow;
class vtkTable;

namespace Avogadro {
namespace VTK {

/**
 * @brief Generate a plot using VTK
 */
class AVOGADROVTK_EXPORT VtkPlot
{
public:
  explicit VtkPlot();
  ~VtkPlot();

  // Enum for the different axes
  enum class Axis
  {
    xAxis,
    yAxis
  };

  // Enum for the different line styles
  enum class LineStyle
  {
    noLine,
    solidLine,
    dashLine,
    dotLine,
    dashDotLine,
    dashDotDotLine
  };

  // data[0] is the x data, and data[i] for i != 0 is the y data for the
  // line i != 0.
  void setData(const std::vector<std::vector<double>>& data);
  void setWindowName(const char* windowName);
  void setXTitle(const char* xTitle);
  void setYTitle(const char* yTitle);

  // 'lineLabels' and 'lineColors' should be equal to the number of lines
  // (data.size() - 1) and ordered in the same way as they are in 'data'.
  void setLineLabels(const std::vector<std::string>& labels)
  {
    m_lineLabels = labels;
  }
  void setLineColors(const std::vector<std::array<double, 4>>& colors)
  {
    m_lineColors = colors;
  }
  void setLineStyles(const std::vector<LineStyle>& styles)
  {
    m_lineStyles = styles;
  }

  void show();

  // customTickPositions must be equal in size to customTickLabels
  void setCustomTickLabels(Axis axis,
                           const std::vector<double>& customTickPositions,
                           const std::vector<std::string>& customTickLabels);

  // Set the limits for a particular axis
  void setAxisLimits(Axis axis, double min, double max);

private:
  // Get a pointer to a particular axis. Returns nullptr if invalid.
  vtkAxis* getAxis(Axis axis);

  std::unique_ptr<QVTKOpenGLStereoWidget> m_widget;
  vtkNew<vtkTable> m_table;
  vtkNew<vtkGenericOpenGLRenderWindow> m_renderWindow;
  vtkNew<vtkContextView> m_view;
  vtkNew<vtkChartXY> m_chart;
  std::vector<std::string> m_lineLabels;
  std::vector<std::array<double, 4>> m_lineColors;
  std::vector<LineStyle> m_lineStyles;
};

} // namespace VTK
} // namespace Avogadro

#endif // AVOGADRO_VTK_VTKPLOT_H
