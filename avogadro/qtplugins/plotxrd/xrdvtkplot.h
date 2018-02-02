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

#ifndef AVOGADRO_QTPLUGINS_XRDVTKPLOT_H
#define AVOGADRO_QTPLUGINS_XRDVTKPLOT_H

#include <utility>
#include <vector>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Generate and plot using VTK
 */
class XrdVtkPlot
{
 public:
  static void generatePlot(const std::vector<std::pair<double, double>>& data);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_XRDVTKPLOT_H
