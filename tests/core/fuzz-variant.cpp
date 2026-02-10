/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/variant.h>

#include <cstdint>
#include <string>
#include <vector>

using Avogadro::MatrixX;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Vector3f;
using Avogadro::Core::Variant;

constexpr size_t kMaxSteps = 256;
constexpr size_t kMaxStringLen = 512;
constexpr int kMaxMatrixDim = 16;

// Set a variant to a random type from fuzz data
static void setRandomValue(Variant& v, FuzzedDataProvider& fdp)
{
  switch (fdp.ConsumeIntegral<uint8_t>() % 12) {
    case 0: // bool
      v.setValue(fdp.ConsumeBool());
      break;
    case 1: // char
      v.setValue(fdp.ConsumeIntegral<char>());
      break;
    case 2: // short
      v.setValue(static_cast<short>(fdp.ConsumeIntegral<int16_t>()));
      break;
    case 3: // int
      v.setValue(fdp.ConsumeIntegral<int>());
      break;
    case 4: // long
      v.setValue(static_cast<long>(fdp.ConsumeIntegral<int64_t>()));
      break;
    case 5: // float
      v.setValue(fdp.ConsumeFloatingPoint<float>());
      break;
    case 6: // double
      v.setValue(fdp.ConsumeFloatingPoint<double>());
      break;
    case 7: // string
      v.setValue(fdp.ConsumeRandomLengthString(kMaxStringLen));
      break;
    case 8: // const char*
      v.setValue(fdp.ConsumeRandomLengthString(kMaxStringLen).c_str());
      break;
    case 9: { // Vector3
      double x = fdp.ConsumeFloatingPoint<double>();
      double y = fdp.ConsumeFloatingPoint<double>();
      double z = fdp.ConsumeFloatingPoint<double>();
      v.setValue(x, y, z);
      break;
    }
    case 10: { // MatrixX
      int rows = fdp.ConsumeIntegralInRange<int>(0, kMaxMatrixDim);
      int cols = fdp.ConsumeIntegralInRange<int>(1, kMaxMatrixDim);
      MatrixX m(rows, cols);
      for (int r = 0; r < rows; ++r)
        for (int c = 0; c < cols; ++c)
          m(r, c) = fdp.ConsumeFloatingPoint<double>();
      v.setValue(m);
      break;
    }
    case 11: { // vector<double> (stored as single-column matrix)
      size_t len = fdp.ConsumeIntegralInRange<size_t>(0, 64);
      std::vector<double> list(len);
      for (size_t i = 0; i < len; ++i)
        list[i] = fdp.ConsumeFloatingPoint<double>();
      v.setValue(list);
      break;
    }
    default:
      break;
  }
}

// Read the variant as a random output type
static void readRandomType(const Variant& v, FuzzedDataProvider& fdp)
{
  switch (fdp.ConsumeIntegral<uint8_t>() % 16) {
    case 0:
      (void)v.toBool();
      break;
    case 1:
      (void)v.toChar();
      break;
    case 2:
      (void)v.toUChar();
      break;
    case 3:
      (void)v.toShort();
      break;
    case 4:
      (void)v.toUShort();
      break;
    case 5:
      (void)v.toInt();
      break;
    case 6:
      (void)v.toUInt();
      break;
    case 7:
      (void)v.toLong();
      break;
    case 8:
      (void)v.toULong();
      break;
    case 9:
      (void)v.toFloat();
      break;
    case 10:
      (void)v.toDouble();
      break;
    case 11:
      (void)v.toReal();
      break;
    case 12:
      (void)v.toString();
      break;
    case 13:
      (void)v.toPointer();
      break;
    case 14:
      (void)v.toMatrix();
      break;
    case 15:
      (void)v.toVector3();
      break;
    default:
      break;
  }
}

// Fuzz Variant with random type mutations and cross-type conversions.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Variant v;

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, kMaxSteps);
  for (size_t s = 0; s < steps && fdp.remaining_bytes() > 0; ++s) {
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 8;

    switch (action) {
      case 0: // set to a random type
        setRandomValue(v, fdp);
        break;
      case 1: // read as a random type (cross-type conversion)
        readRandomType(v, fdp);
        break;
      case 2: // clear
        v.clear();
        break;
      case 3: { // copy construct
        Variant copy(v);
        (void)copy.type();
        (void)copy.isNull();
        readRandomType(copy, fdp);
        break;
      }
      case 4: { // assignment operator
        Variant other;
        setRandomValue(other, fdp);
        v = other;
        break;
      }
      case 5: // self-assignment
        v = v;
        break;
      case 6: // check type and null
        (void)v.type();
        (void)v.isNull();
        break;
      case 7: { // toMatrixRef and toList
        (void)v.toMatrixRef();
        (void)v.toList();
        break;
      }
      default:
        break;
    }
  }

  // Final read of all conversion methods on whatever state we're in
  (void)v.type();
  (void)v.isNull();
  (void)v.toBool();
  (void)v.toChar();
  (void)v.toUChar();
  (void)v.toShort();
  (void)v.toUShort();
  (void)v.toInt();
  (void)v.toUInt();
  (void)v.toLong();
  (void)v.toULong();
  (void)v.toFloat();
  (void)v.toDouble();
  (void)v.toReal();
  (void)v.toPointer();
  (void)v.toString();
  (void)v.toMatrix();
  (void)v.toMatrixRef();
  (void)v.toVector3();
  (void)v.toList();

  return 0;
}
