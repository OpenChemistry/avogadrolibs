/*******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/

#ifndef AVOGADRO_VTK_VTKPLOT_H
#define AVOGADRO_VTK_VTKPLOT_H

#include "avogadrovtkexport.h"

#include <vtkNew.h>

#include <array>
#include <memory>
#include <string>
#include <vector>

class QVTKOpenGLWidget;
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
  void show();

private:
  std::unique_ptr<QVTKOpenGLWidget> m_widget;
  vtkNew<vtkTable> m_table;
  vtkNew<vtkGenericOpenGLRenderWindow> m_renderWindow;
  vtkNew<vtkContextView> m_view;
  vtkNew<vtkChartXY> m_chart;
  std::vector<std::string> m_lineLabels;
  std::vector<std::array<double, 4>> m_lineColors;
};

} // namespace VTK
} // namespace Avogadro

#endif // AVOGADRO_VTK_VTKPLOT_H
