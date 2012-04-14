/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_H
#define AVOGADRO_CORE_H

#include "avogadrocoreexport.h"
#include <cstddef>

/// This macro marks a parameter as unused. Its purpose is to
/// disable the compiler from emitting unused parameter warnings.
#define AVOGADRO_UNUSED(variable) (void) variable

/// This macro marks a class as not copyable. It should be used in
/// the private section of a class's declaration.
#define AVOGADRO_DISABLE_COPY(Class) \
  Class(const Class&); \
  Class& operator=(const Class&);

namespace Avogadro {
namespace Core {

/// Typedef for a real number.
typedef double Real;

/// Typedef for indices and sizes.
typedef size_t Index;

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_H
