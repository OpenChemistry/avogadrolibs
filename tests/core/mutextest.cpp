/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
