/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "symmetryutil.h"

#define _ORIENT_HORIZONTAL                                                     \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_ORIENTATION_HORIZONTAL
#define _ORIENT_VERTICAL                                                       \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_ORIENTATION_VERTICAL
#define _ORIENT_DIHEDRAL                                                       \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_ORIENTATION_DIHEDRAL

namespace Avogadro {
namespace QtPlugins {

namespace SymmetryUtil {

QString pointGroupSymbol(const char* point_group)
{
  QString pointGroup(point_group);
  if (pointGroup.isEmpty())
    pointGroup = "C1"; // default

  // check if we need an infinity symbol
  if (pointGroup[1] == '0')
    pointGroup = pointGroup.replace(1, 1, QObject::trUtf8("\u221e"));

  // After first character, point group should subscript everything
  pointGroup.insert(1, "<sub>");
  pointGroup.append("</sub>");

  return pointGroup;
}

QString operationSymbol(const msym::msym_symmetry_operation_t* operation)
{
  // omit first power
  QString symbol;
  if (operation->type == IDENTITY) {
    symbol = QString("E");
  } else if (operation->type == INVERSION) {
    symbol = QString("i");
  } else if (operation->type == PROPER_ROTATION) {
    symbol = QString("C<sub>%1</sub>").arg(operation->order);
    if (operation->power > 1) // add the power for ^2, ^3, etc.
      symbol.append(QString("<sup>%2</sup>").arg(operation->power));
  } else if (operation->type == IMPROPER_ROTATION) {
    symbol = QString("S<sub>%1</sub>").arg(operation->order);
    if (operation->power > 1) // add the power for ^2, ^3, etc.
      symbol.append(QString("<sup>%2</sup>").arg(operation->power));
  } else if (operation->type == REFLECTION) {
    symbol = QString("&sigma;");
    if (operation->orientation == _ORIENT_HORIZONTAL)
      symbol.append("<sub>h</sub>");
    else if (operation->orientation == _ORIENT_DIHEDRAL)
      symbol.append("<sub>d</sub>");
    else if (operation->orientation == _ORIENT_VERTICAL)
      symbol.append("<sub>v</sub>");
  }

  return symbol;
}
} // namespace SymmetryUtil
} // namespace QtPlugins
} // namespace Avogadro
