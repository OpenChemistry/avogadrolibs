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

#ifndef AVOGADRO_QTPLUGINS_SYMMETRYUTIL_H
#define AVOGADRO_QTPLUGINS_SYMMETRYUTIL_H

#include <QtCore/QObject>

namespace msym {
  extern "C" {
    #include <libmsym/msym.h>
  }
}

namespace Avogadro {
namespace QtPlugins {

  namespace SymmetryUtil {
    QString pointGroupSymbol(char* point_group);
    QString operationSymbol(const msym::msym_symmetry_operation_t *operation);
  }
}
}
#endif // AVOGADRO_QTPLUGINS_SYMMETRYUTIL_H
