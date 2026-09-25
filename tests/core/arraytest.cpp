/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>

#include <atomic>
#include <thread>
#include <vector>

using Avogadro::Core::Array;

TEST(ArrayTest, setSize)
{
  Array<int> array;

  EXPECT_EQ(array.size(), static_cast<size_t>(0));

  array.resize(2);
  EXPECT_EQ(array.size(), static_cast<size_t>(2));
}

TEST(ArrayTest, isEmpty)
{
  Array<int> array;
  EXPECT_TRUE(array.empty());
}

TEST(ArrayTest, push_back)
{
  Array<int> array;
  array.push_back(6);
  EXPECT_EQ(array.size(), static_cast<size_t>(1));
  array.push_back(9);
  EXPECT_EQ(array.size(), static_cast<size_t>(2));
}

TEST(ArrayTest, clear)
{
  Array<int> array;
  array.push_back(6);
  EXPECT_EQ(array.size(), static_cast<size_t>(1));
  array.push_back(9);
  EXPECT_EQ(array.size(), static_cast<size_t>(2));
  array.clear();
  EXPECT_EQ(array.size(), static_cast<size_t>(0));
}

TEST(ArrayTest, detach)
{
  // Verify the data pointers match for the two arrays.
  Array<int> array(5);
  Array<int> array2 = array;
  EXPECT_EQ(array.constData(), array2.constData());
  // After detaching the data pointers should differ.
  array2.detach();
  EXPECT_NE(array.constData(), array2.constData());
}

TEST(ArrayTest, implicitDetach)
{
  Array<int> array(5, 3);
  array[2] = 666;
  Array<int> array2 = array;
  EXPECT_EQ(array.constData(), array2.constData());
  EXPECT_EQ(array.at(0), 3);
  EXPECT_EQ(array2.at(0), 3);
  EXPECT_EQ(array.at(2), 666);
  EXPECT_EQ(array2.at(2), 666);

  // Now change some values, these should not be visible to the other instance.
  array[0] = 1;
  array2[2] = 42;

  EXPECT_NE(array.constData(), array2.constData());
  EXPECT_EQ(array.at(0), 1);
  EXPECT_EQ(array2.at(0), 3);
  EXPECT_EQ(array.at(2), 666);
  EXPECT_EQ(array2.at(2), 42);
}

TEST(ArrayTest, operators)
{
  Array<int> a1;
  Array<int> a2;
  for (int i = 0; i < 10; ++i) {
    a1.push_back(i);
    a2.push_back(i * 10);
  }

  Array<int> a1c(a1);
  EXPECT_TRUE(a1 == a1c);
  EXPECT_TRUE(a1 != a2);
  EXPECT_TRUE(a1 < a2);
  EXPECT_TRUE(a1 <= a1c);
  EXPECT_TRUE(a2 > a1);
  EXPECT_TRUE(a1 >= a1c);

  using std::swap;
  swap(a1, a2);
  EXPECT_TRUE(a2 == a1c);
}

TEST(ArrayTest, swapAndPopDetaches)
{
  Array<int> a1;
  a1.push_back(1);
  a1.push_back(2);
  a1.push_back(3);

  Array<int> a2 = a1;
  EXPECT_EQ(a1.constData(), a2.constData());

  a1.swapAndPop(0);

  EXPECT_NE(a1.constData(), a2.constData());
  EXPECT_EQ(a1.size(), static_cast<size_t>(2));
  EXPECT_EQ(a2.size(), static_cast<size_t>(3));
  EXPECT_EQ(a2.at(0), 1);
  EXPECT_EQ(a2.at(1), 2);
  EXPECT_EQ(a2.at(2), 3);
}

TEST(ArrayTest, detachLeavesOtherHolderIntact)
{
  Array<int> a1(4, 7);
  {
    Array<int> a2 = a1;
    Array<int> a3 = a1;
    EXPECT_EQ(a1.constData(), a3.constData());

    // Detach two of the three holders; the remaining one keeps the data.
    a2[0] = 1;
    a3.detach();
    EXPECT_NE(a1.constData(), a2.constData());
    EXPECT_NE(a1.constData(), a3.constData());
    EXPECT_EQ(a2.at(0), 1);
    EXPECT_EQ(a2.at(1), 7);
  }
  // The copies are gone, a1 is now the sole owner and must still be valid.
  ASSERT_EQ(a1.size(), static_cast<size_t>(4));
  for (size_t i = 0; i < a1.size(); ++i)
    EXPECT_EQ(a1.at(i), 7);
  const int* before = a1.constData();
  a1[0] = 3; // sole owner: no copy
  EXPECT_EQ(a1.constData(), before);
}

namespace {

// Spin until every thread has arrived, so the work starts at the same time.
void waitForAll(std::atomic<int>& arrived, int count)
{
  arrived.fetch_add(1);
  while (arrived.load() < count)
    std::this_thread::yield();
}

} // namespace

TEST(ArrayTest, threadedCopyDetachDestroy)
{
  // Each thread copies a shared source (sharing its container), sometimes
  // writes to the copy (forcing a detach with copy) and destroys it, while the
  // other threads do the same with the same container.
  const int threadCount = 4;
  const int iterations = 5000;
  const Array<int> source(64, 42);
  const int* sourceData = source.constData();

  std::atomic<int> arrived(0);
  std::vector<std::thread> threads;
  for (int t = 0; t < threadCount; ++t) {
    threads.emplace_back([&, t]() {
      waitForAll(arrived, threadCount);
      for (int i = 0; i < iterations; ++i) {
        Array<int> copy(source);
        if ((i + t) % 3 == 0) {
          copy[0] = i; // detachWithCopy
        } else if ((i + t) % 3 == 1) {
          Array<int> second(copy);
          second.detach();
        }
      }
    });
  }
  for (auto& thread : threads)
    thread.join();

  EXPECT_EQ(source.constData(), sourceData);
  ASSERT_EQ(source.size(), static_cast<size_t>(64));
  for (size_t i = 0; i < source.size(); ++i)
    EXPECT_EQ(source.at(i), 42);
}

TEST(ArrayTest, threadedSimultaneousDetach)
{
  // Every thread holds its own copy of the same data, then all of them detach
  // at once. Whichever release is last must free the shared container.
  const int threadCount = 4;
  const int rounds = 500;
  for (int round = 0; round < rounds; ++round) {
    Array<int>* shared = new Array<int>(16, round);
    std::vector<Array<int>> copies(threadCount, *shared);
    // Drop the original so only the thread-owned copies remain.
    delete shared;

    std::atomic<int> arrived(0);
    std::vector<std::thread> threads;
    for (int t = 0; t < threadCount; ++t) {
      threads.emplace_back([&, t]() {
        waitForAll(arrived, threadCount);
        if (t % 2 == 0)
          copies[t][0] = -t; // detachWithCopy
        else
          copies[t].detach();
      });
    }
    for (auto& thread : threads)
      thread.join();

    for (int t = 0; t < threadCount; ++t) {
      if (t % 2 == 0) {
        ASSERT_EQ(copies[t].size(), static_cast<size_t>(16));
        EXPECT_EQ(copies[t].at(0), -t);
        EXPECT_EQ(copies[t].at(15), round);
      } else if (!copies[t].empty()) {
        // detach() is a no-op for whichever holder was already the last one.
        ASSERT_EQ(copies[t].size(), static_cast<size_t>(16));
        EXPECT_EQ(copies[t].at(0), round);
      }
    }
  }
}
