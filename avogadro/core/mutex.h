/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_MUTEX_H
#define AVOGADRO_CORE_MUTEX_H

#include "avogadrocoreexport.h"

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
