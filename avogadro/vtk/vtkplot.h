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

#include <array>
#include <string>
#include <vector>

namespace Avogadro {
namespace VTK {

/**
 * @brief Generate a plot using VTK
 */
class AVOGADROVTK_EXPORT VtkPlot
{
public:
  // This function can generate multiple lines on the same chart.
  // data[0] is the x data, and data[i] for i != 0 is the y data for line
  // i - 1. 'lineLabels' and 'lineColors' should be equal to the number of
  // lines (data.size() - 1) and ordered in the same way as they are in 'data'.
  static void generatePlot(const std::vector<std::vector<double>>& data,
                           const std::vector<std::string>& lineLabels,
                           const std::vector<std::array<double, 4>>& lineColors,
                           const char* xTitle, const char* yTitle,
                           const char* windowName);
};

} // namespace VTK
} // namespace Avogadro

#endif // AVOGADRO_VTK_VTKPLOT_H
