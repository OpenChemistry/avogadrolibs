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

#ifndef IDENTITY
#define IDENTITY                                                               \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_TYPE_IDENTITY
#endif
#ifndef REFLECTION
#define REFLECTION                                                             \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_TYPE_REFLECTION
#endif
#ifndef INVERSION
#define INVERSION                                                              \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_TYPE_INVERSION
#endif
#ifndef PROPER_ROTATION
#define PROPER_ROTATION                                                        \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_TYPE_PROPER_ROTATION
#endif
#ifndef IMPROPER_ROTATION
#define IMPROPER_ROTATION                                                      \
  msym::_msym_symmetry_operation::MSYM_SYMMETRY_OPERATION_TYPE_IMPROPER_ROTATION
#endif

namespace Avogadro {
namespace QtPlugins {

namespace SymmetryUtil {
QString pointGroupSymbol(const char* point_group);
QString operationSymbol(const msym::msym_symmetry_operation_t* operation);
}
}
}
#endif // AVOGADRO_QTPLUGINS_SYMMETRYUTIL_H
