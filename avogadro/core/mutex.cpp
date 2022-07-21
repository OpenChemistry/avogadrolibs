/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mutex.h"

#include <mutex>

namespace Avogadro::Core {

using std::mutex;

class Mutex::PIMPL
{
public:
  PIMPL() {}

  mutex lock;
};

Mutex::Mutex() : d(new PIMPL)
{
}

Mutex::~Mutex()
{
  delete d;
}

void Mutex::lock()
{
  d->lock.lock();
}

bool Mutex::tryLock()
{
  return d->lock.try_lock();
}

void Mutex::unlock()
{
  d->lock.unlock();
}
}
