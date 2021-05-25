/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "sharedmutex.h"

#include <shared_mutex>

namespace Avogadro {
namespace Core {

using std::shared_mutex;

class SharedMutex::PIMPL
{
public:
  PIMPL() {}

  shared_mutex lock;
};

SharedMutex::SharedMutex() : d(new PIMPL) {}

SharedMutex::~SharedMutex()
{
  delete d;
}

void SharedMutex::lockForRead()
{
  d->lock.lock_shared();
}

bool SharedMutex::tryLockForRead()
{
  return d->lock.try_lock_shared();
}

void SharedMutex::unlockForRead()
{
  d->lock.unlock_shared();
}

void SharedMutex::lockForWrite()
{
  d->lock.lock();
}

bool SharedMutex::tryLockForWrite()
{
  return d->lock.try_lock();
}

void SharedMutex::unlockForWrite()
{
  d->lock.unlock();
}

} // namespace Core
} // namespace Avogadro
