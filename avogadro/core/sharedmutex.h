/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SHAREDMUTEX_H
#define AVOGADRO_CORE_SHAREDMUTEX_H

#include "avogadrocoreexport.h"

namespace Avogadro {
namespace Core {

/**
 * @class SharedMutex sharedmutex.h <avogadro/core/sharedmutex.h>
 * @brief The SharedMutex class provides a simple wrapper for the C++17
 * shared_mutex class
 * @author Marcus D. Hanwell
 *
 * A very simple, and thin wrapper around the C++17 shared_mutex class, allowing
 * for lock, tryLock and unlock.
 */

class AVOGADROCORE_EXPORT SharedMutex
{
public:
  SharedMutex();
  ~SharedMutex();

  /**
   * @brief Obtain a shared read lock.
   */
  void lockForRead();

  /**
   * @brief Attempt to obtain a shared read lock.
   * @return True on success, false on failure.
   */
  bool tryLockForRead();

  /**
   * @brief Unlocks the exclusive write lock.
   */
  void unlockForRead();

  /**
   * @brief Obtain an exclusive write lock.
   */
  void lockForWrite();

  /**
   * @brief Attempt to obtain an exclusive write  lock.
   * @return True on success, false on failure.
   */
  bool tryLockForWrite();

  /**
   * @brief Unlocks the exclusive write lock.
   */
  void unlockForWrite();

private:
  class PIMPL;
  PIMPL* d;
};
} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_SHAREDMUTEX_H
