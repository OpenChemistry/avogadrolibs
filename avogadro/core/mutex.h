/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_MUTEX_H
#define AVOGADRO_CORE_MUTEX_H

#include "avogadrocore.h"

namespace Avogadro {
namespace Core {

/**
 * @class Mutex mutex.h <avogadro/core/mutex.h>
 * @brief The Mutex class provides a simple wrapper for the C++11 mutex
 * class
 * @author Marcus D. Hanwell
 *
 * A very simple, and thin wrapper around the C++11 mutex class, allowing for
 * lock, tryLock and unlock.
 */

class AVOGADROCORE_EXPORT Mutex
{
public:
  Mutex();
  ~Mutex();

  /**
   * @brief Obtain an exclusive lock.
   */
  void lock();

  /**
   * @brief Attempt to obtain an exclusive lock.
   * @return True on success, false on failure.
   */
  bool tryLock();

  /**
   * @brief Unlocks the lock.
   */
  void unlock();

private:
  class PIMPL;
  PIMPL* d;
};
}
}

#endif // AVOGADRO_CORE_MUTEX_H
