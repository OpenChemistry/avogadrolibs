/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2013 Kitware, Inc.

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
#include <limits>

/** Prevent compiler error when using std::numeric_limits<T>::max() */
#if defined(_MSC_VER) && defined(max)
#undef max
#endif

/**
 * Define a macro for the new C++11 override and final identifiers when using
 * a compiler with C++11 support enabled.
 */
#if __cplusplus >= 201103L
# define AVO_OVERRIDE override
# define AVO_FINAL final
#else
# define AVO_OVERRIDE
# define AVO_FINAL
#endif

/**
 * This macro marks a parameter as unused. Its purpose is to disable the
 * compiler from emitting unused parameter warnings.
 */
#define AVO_UNUSED(variable) (void) variable

/**
 * This macro marks a class as not copyable. It should be used in the private
 * section of a class's declaration.
 */
#define AVO_DISABLE_COPY(Class) \
  Class(const Class&); \
  Class& operator=(const Class&);

namespace Avogadro {

/** Typedef for a real number. */
typedef double Real;

/** Typedef for indices and sizes. */
typedef size_t Index;
const Index MaxIndex = std::numeric_limits<Index>::max();

/** Used to represent an invalid atomic number. */
const unsigned char InvalidElement = 255;

} // end Avogadro namespace

#endif // AVOGADRO_CORE_H
