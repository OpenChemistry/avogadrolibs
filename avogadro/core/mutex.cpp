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

#include "mutex.h"

#include <mutex>

namespace Avogadro {
namespace Core {

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
}
