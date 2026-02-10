/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/array.h>

#include <algorithm>
#include <cstdint>

using Avogadro::Core::Array;

// Caps to prevent OOM/timeout during fuzzing
constexpr size_t kMaxSize = 4096;
constexpr size_t kMaxSteps = 256;

// Fuzz Array<int> with random mutation sequences, exercising copy-on-write,
// iterators, comparisons, insert/erase, and element access.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  // Start with a fuzz-chosen initial size and fill value
  size_t initSize =
    fdp.ConsumeIntegralInRange<size_t>(0, std::min(kMaxSize, size_t(128)));
  int fillVal = fdp.ConsumeIntegral<int>();
  Array<int> arr(initSize, fillVal);

  // Make a CoW copy so we exercise shared-state paths
  Array<int> cow = arr;

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, kMaxSteps);
  for (size_t s = 0; s < steps && fdp.remaining_bytes() > 0; ++s) {
    uint8_t op = fdp.ConsumeIntegral<uint8_t>() % 16;

    switch (op) {
      case 0: { // push_back
        int v = fdp.ConsumeIntegral<int>();
        if (arr.size() < kMaxSize)
          arr.push_back(v);
        break;
      }
      case 1: { // pop_back
        if (!arr.empty())
          arr.pop_back();
        break;
      }
      case 2: { // resize
        size_t newSz = fdp.ConsumeIntegralInRange<size_t>(0, kMaxSize);
        arr.resize(newSz, fdp.ConsumeIntegral<int>());
        break;
      }
      case 3: { // clear
        arr.clear();
        break;
      }
      case 4: { // reserve
        size_t cap = fdp.ConsumeIntegralInRange<size_t>(0, kMaxSize);
        arr.reserve(cap);
        break;
      }
      case 5: { // operator[] write (triggers detach)
        if (!arr.empty()) {
          size_t idx = fdp.ConsumeIntegral<uint16_t>() % arr.size();
          arr[idx] = fdp.ConsumeIntegral<int>();
        }
        break;
      }
      case 6: { // at() read
        if (!arr.empty()) {
          size_t idx = fdp.ConsumeIntegral<uint16_t>() % arr.size();
          (void)arr.at(idx);
        }
        break;
      }
      case 7: { // front / back
        if (!arr.empty()) {
          (void)arr.front();
          (void)arr.back();
        }
        break;
      }
      case 8: { // insert single element
        if (arr.size() < kMaxSize && !arr.empty()) {
          size_t pos = fdp.ConsumeIntegral<uint16_t>() % arr.size();
          arr.insert(arr.begin() + pos, fdp.ConsumeIntegral<int>());
        }
        break;
      }
      case 9: { // erase single element
        if (!arr.empty()) {
          size_t pos = fdp.ConsumeIntegral<uint16_t>() % arr.size();
          arr.erase(arr.begin() + pos);
        }
        break;
      }
      case 10: { // swapAndPop
        if (!arr.empty()) {
          size_t idx = fdp.ConsumeIntegral<uint16_t>() % arr.size();
          arr.swapAndPop(idx);
        }
        break;
      }
      case 11: { // copy and compare
        Array<int> copy = arr;
        (void)(arr == copy);
        (void)(arr != copy);
        break;
      }
      case 12: { // swap with cow copy
        using std::swap;
        swap(arr, cow);
        break;
      }
      case 13: { // assign from iterators
        if (cow.size() > 0) {
          size_t count = std::min(cow.size(), size_t(64));
          arr.assign(cow.begin(), cow.begin() + count);
        }
        break;
      }
      case 14: { // comparison operators
        (void)(arr < cow);
        (void)(arr > cow);
        (void)(arr <= cow);
        (void)(arr >= cow);
        break;
      }
      case 15: { // iterate (const)
        int sum = 0;
        for (auto it = arr.begin(); it != arr.end(); ++it)
          sum += *it;
        (void)sum;
        break;
      }
      default:
        break;
    }
  }

  // Exercise detach / detachWithCopy on the final state
  Array<int> shared = arr;
  (void)shared.constData(); // no detach
  (void)shared.data();      // triggers detachWithCopy
  shared.detach();          // explicit detach (new empty container)

  // Exercise size/empty/capacity on final state
  (void)arr.size();
  (void)arr.empty();
  (void)arr.capacity();
  (void)arr.max_size();

  return 0;
}
