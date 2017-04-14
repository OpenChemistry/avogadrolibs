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

namespace Avogadro {
namespace QtPlugins {

namespace SymmetryUtil {

QString pointGroupSymbol(char* point_group)
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
  QString symbol;
  switch (operation->type) {
    case IDENTITY:
      symbol = QString("E");
      break;
    case INVERSION:
      symbol = QString("i");
      break;
    case PROPER_ROTATION:
      symbol = QString("C<sub>%1</sub><sup>%2</sup>")
                 .arg(QString::number(operation->order),
                      QString::number(operation->power));
      break;
    case IMPROPER_ROTATION:
      symbol = QString("S<sub>%1</sub><sup>%2</sup>")
                 .arg(QString::number(operation->order),
                      QString::number(operation->power));
      break;
    case REFLECTION:
      symbol = QString("&sigma;");
      break;
    default:
      symbol = QString();
  }

  return symbol;
}
}
}
}
