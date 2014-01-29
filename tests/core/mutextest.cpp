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

#include <gtest/gtest.h>

#include <avogadro/core/mutex.h>

using Avogadro::Core::Mutex;

TEST(MutexTest, lock)
{
  Mutex mutex;

  mutex.lock();
  int array[15];
  array[4] = 1;
  mutex.unlock();

  EXPECT_EQ(array[4], 1);
}

TEST(MutexText, tryLock)
{
  Mutex mutex;

  mutex.lock();
  EXPECT_FALSE(mutex.tryLock());
  int array[15];
  array[4] = 2;
  mutex.unlock();

  EXPECT_TRUE(mutex.tryLock());
  mutex.unlock();

  EXPECT_EQ(array[4], 2);
}
