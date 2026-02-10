/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/variantmap.h>

#include <cstdint>
#include <string>
#include <vector>

using Avogadro::MatrixX;
using Avogadro::Vector3;
using Avogadro::Core::Variant;
using Avogadro::Core::VariantMap;

constexpr size_t kMaxSteps = 256;
constexpr size_t kMaxKeyLen = 128;
constexpr size_t kMaxStringLen = 256;
constexpr int kMaxMatrixDim = 8;

// Build a random Variant from fuzz data
static Variant makeRandomVariant(FuzzedDataProvider& fdp)
{
  switch (fdp.ConsumeIntegral<uint8_t>() % 9) {
    case 0:
      return Variant(fdp.ConsumeBool());
    case 1:
      return Variant(fdp.ConsumeIntegral<int>());
    case 2:
      return Variant(static_cast<long>(fdp.ConsumeIntegral<int64_t>()));
    case 3:
      return Variant(fdp.ConsumeFloatingPoint<float>());
    case 4:
      return Variant(fdp.ConsumeFloatingPoint<double>());
    case 5:
      return Variant(fdp.ConsumeRandomLengthString(kMaxStringLen).c_str());
    case 6: {
      double x = fdp.ConsumeFloatingPoint<double>();
      double y = fdp.ConsumeFloatingPoint<double>();
      double z = fdp.ConsumeFloatingPoint<double>();
      return Variant(x, y, z);
    }
    case 7: {
      int rows = fdp.ConsumeIntegralInRange<int>(0, kMaxMatrixDim);
      int cols = fdp.ConsumeIntegralInRange<int>(1, kMaxMatrixDim);
      MatrixX m(rows, cols);
      for (int r = 0; r < rows; ++r)
        for (int c = 0; c < cols; ++c)
          m(r, c) = fdp.ConsumeFloatingPoint<double>();
      return Variant(m);
    }
    case 8: {
      size_t len = fdp.ConsumeIntegralInRange<size_t>(0, 32);
      std::vector<double> list(len);
      for (size_t i = 0; i < len; ++i)
        list[i] = fdp.ConsumeFloatingPoint<double>();
      return Variant(list);
    }
    default:
      return Variant();
  }
}

// Fuzz VariantMap with random insert/lookup/remove/iterate sequences.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  VariantMap map;

  // Keep a small pool of keys so lookups/overwrites actually hit
  std::vector<std::string> keyPool;

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, kMaxSteps);
  for (size_t s = 0; s < steps && fdp.remaining_bytes() > 0; ++s) {
    uint8_t op = fdp.ConsumeIntegral<uint8_t>() % 10;

    switch (op) {
      case 0: { // setValue with new key
        std::string key = fdp.ConsumeRandomLengthString(kMaxKeyLen);
        map.setValue(key, makeRandomVariant(fdp));
        if (keyPool.size() < 64)
          keyPool.push_back(key);
        break;
      }
      case 1: { // setValue overwriting existing key
        if (!keyPool.empty()) {
          size_t idx = fdp.ConsumeIntegral<uint8_t>() % keyPool.size();
          map.setValue(keyPool[idx], makeRandomVariant(fdp));
        }
        break;
      }
      case 2: { // value lookup for existing key
        if (!keyPool.empty()) {
          size_t idx = fdp.ConsumeIntegral<uint8_t>() % keyPool.size();
          Variant v = map.value(keyPool[idx]);
          (void)v.type();
        }
        break;
      }
      case 3: { // value lookup for random (possibly missing) key
        std::string key = fdp.ConsumeRandomLengthString(kMaxKeyLen);
        Variant v = map.value(key);
        (void)v.isNull();
        break;
      }
      case 4: { // hasValue for existing key
        if (!keyPool.empty()) {
          size_t idx = fdp.ConsumeIntegral<uint8_t>() % keyPool.size();
          (void)map.hasValue(keyPool[idx]);
        }
        break;
      }
      case 5: { // hasValue for random key
        std::string key = fdp.ConsumeRandomLengthString(kMaxKeyLen);
        (void)map.hasValue(key);
        break;
      }
      case 6: { // names
        std::vector<std::string> n = map.names();
        (void)n.size();
        break;
      }
      case 7: { // iterate and read values
        for (auto it = map.constBegin(); it != map.constEnd(); ++it) {
          (void)it->first.size();
          (void)it->second.type();
        }
        break;
      }
      case 8: // size + isEmpty
        (void)map.size();
        (void)map.isEmpty();
        break;
      case 9: { // clear (occasionally)
        map.clear();
        keyPool.clear();
        break;
      }
      default:
        break;
    }
  }

  // Final consistency check: iterate all entries and read back values
  (void)map.size();
  (void)map.isEmpty();
  std::vector<std::string> finalNames = map.names();
  for (const auto& name : finalNames) {
    Variant v = map.value(name);
    (void)v.type();
    (void)v.isNull();
    (void)v.toString();
  }

  return 0;
}
