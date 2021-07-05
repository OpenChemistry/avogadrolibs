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

#ifndef AVOGADRO_QTPLUGINS_YAEHMOP_SPECIALKPOINTS_H
#define AVOGADRO_QTPLUGINS_YAEHMOP_SPECIALKPOINTS_H

namespace Avogadro {
namespace Core {
class Molecule;
}
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {

#include <QString>

class SpecialKPoints
{
public:
  /* Get the special k points for a particular space group. It will
   * be returned like the following:
   *
   * GM 0 0 0
   * Y  0 0.5 0
   * etc.
   *
   * @param mol The molecule for which to get special k points. If the
   *            space group is cached, that will be used. If not, this
   *            function will attempt to determine the space group via
   *            avospglib. If that fails, an empty string is returned.
   *
   * @return A QString containing the data for the special kpoint.
   */
  static QString getSpecialKPoints(Core::Molecule& mol);

private:
  /* Process a special k point with a condition. These special k points
   * are separated in specialkpointsdata.h by a '#' symbol. This function
   * has stored in it all of the cases for different conditions. It will
   * process and change the @param specialKPoints to be the correct
   * QString for the @param molecule.
   *
   */
  static void processConditionKPoints(QString& specialKPoints,
                                      Core::Molecule& mol,
                                      unsigned short spgNum);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif
