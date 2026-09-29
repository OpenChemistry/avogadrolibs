/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/variant.h>

#include <limits>

using Avogadro::MatrixX;
using Avogadro::Core::Variant;
using namespace std::string_literals;

TEST(VariantTest, isNull)
{
  Variant variant;
  EXPECT_EQ(variant.isNull(), true);

  variant.setValue(7);
  EXPECT_EQ(variant.isNull(), false);
}

TEST(VariantTest, clear)
{
  Variant variant(62);
  EXPECT_EQ(variant.isNull(), false);

  variant.clear();
  EXPECT_EQ(variant.isNull(), true);

  variant.setValue('f');
  EXPECT_EQ(variant.isNull(), false);

  variant.clear();
  EXPECT_EQ(variant.isNull(), true);
}

TEST(VariantTest, toBool)
{
  Variant variant(false);
  EXPECT_EQ(variant.toBool(), false);

  variant.setValue(true);
  EXPECT_EQ(variant.toBool(), true);

  variant.setValue(0);
  EXPECT_EQ(variant.toBool(), false);

  variant.setValue(1);
  EXPECT_EQ(variant.toBool(), true);

  variant.setValue(-5);
  EXPECT_EQ(variant.toBool(), true);
}

TEST(VariantTest, toChar)
{
  Variant variant('c');
  EXPECT_EQ(variant.toChar(), 'c');

  variant.setValue("hello");
  EXPECT_EQ(variant.toChar(), 'h');
}

TEST(VariantTest, toShort)
{
  Variant variant(short(4));
  EXPECT_EQ(variant.toShort(), short(4));
}

TEST(VariantTest, toInt)
{
  Variant variant(12);
  EXPECT_EQ(variant.toInt(), int(12));

  variant.setValue(-23);
  EXPECT_EQ(variant.toInt(), int(-23));

  variant.setValue("42");
  EXPECT_EQ(variant.toInt(), int(42));

  variant.setValue(true);
  EXPECT_EQ(variant.toInt(), int(1));

  variant.setValue(false);
  EXPECT_EQ(variant.toInt(), int(0));
}

TEST(VariantTest, floatToIntSaturates)
{
  const double inf = std::numeric_limits<double>::infinity();
  const double nan = std::numeric_limits<double>::quiet_NaN();
  const int imax = std::numeric_limits<int>::max();
  const int imin = std::numeric_limits<int>::lowest();

  for (double d : { 1e30, inf, 2147483648.0 })
    EXPECT_EQ(imax, Variant(d).value<int>()) << d;
  for (double d : { -1e30, -inf, -2147483649.0 })
    EXPECT_EQ(imin, Variant(d).value<int>()) << d;
  EXPECT_EQ(0, Variant(nan).value<int>());
  EXPECT_EQ(imax, Variant(2147483647.0).value<int>());
  EXPECT_EQ(imin, Variant(-2147483648.0).value<int>());

  // float source, as seen from the fuzzer
  EXPECT_EQ(imin, Variant(-3.40282e+38f).value<int>());
  EXPECT_EQ(imax, Variant(3.40282e+38f).value<int>());
  EXPECT_EQ(0, Variant(std::numeric_limits<float>::quiet_NaN()).value<int>());
  EXPECT_EQ(imax, Variant(std::numeric_limits<float>::infinity()).value<int>());

  // ordinary values truncate toward zero
  EXPECT_EQ(3, Variant(3.9).value<int>());
  EXPECT_EQ(-3, Variant(-3.9).value<int>());
  EXPECT_EQ(3, Variant(3.9f).value<int>());
  EXPECT_EQ(-3, Variant(-3.9f).value<int>());
}

TEST(VariantTest, floatToIntegerHelper)
{
  using Avogadro::Core::detail::floatToInteger;
  const double inf = std::numeric_limits<double>::infinity();
  const double nan = std::numeric_limits<double>::quiet_NaN();

  // long long: max() converts to 2^63 as a double, which must saturate
  constexpr long long llmax = std::numeric_limits<long long>::max();
  constexpr long long llmin = std::numeric_limits<long long>::lowest();
  EXPECT_EQ(llmax, floatToInteger<long long>(9223372036854775808.0));
  EXPECT_EQ(llmax, floatToInteger<long long>(1e30));
  EXPECT_EQ(llmax, floatToInteger<long long>(inf));
  EXPECT_EQ(llmin, floatToInteger<long long>(-9223372036854775808.0));
  EXPECT_EQ(llmin, floatToInteger<long long>(-1e30));
  EXPECT_EQ(llmin, floatToInteger<long long>(-inf));
  EXPECT_EQ(0, floatToInteger<long long>(nan));
  EXPECT_EQ(3, floatToInteger<long long>(3.9));
  EXPECT_EQ(-3, floatToInteger<long long>(-3.9));
  EXPECT_EQ(4000000000LL, floatToInteger<long long>(4e9));

  EXPECT_EQ(32767, floatToInteger<short>(1e30));
  EXPECT_EQ(-32768, floatToInteger<short>(-inf));
  EXPECT_EQ(0, floatToInteger<short>(nan));
  EXPECT_EQ(-3, floatToInteger<short>(-3.9));

  EXPECT_EQ(std::numeric_limits<unsigned int>::max(),
            floatToInteger<unsigned int>(1e30));
  EXPECT_EQ(0u, floatToInteger<unsigned int>(-5.0));
  EXPECT_EQ(3u, floatToInteger<unsigned int>(3.9));
  EXPECT_EQ(std::numeric_limits<char>::max(), floatToInteger<char>(1e30));
}

TEST(VariantTest, toLong)
{
  Variant variant(192L);
  EXPECT_EQ(variant.toLong(), 192L);

  variant.setValue(7);
  EXPECT_EQ(variant.toLong(), 7L);

  variant.setValue("562");
  EXPECT_EQ(variant.toLong(), 562L);
}

TEST(VariantTest, toFloat)
{
  Variant variant(12.3f);
  EXPECT_EQ(variant.toFloat(), 12.3f);
}

TEST(VariantTest, toDouble)
{
  Variant variant(3.14);
  EXPECT_EQ(variant.toDouble(), 3.14);
}

TEST(VariantTest, toPointer)
{
  int value;
  void* pointer = &value;
  Variant variant(pointer);
  EXPECT_EQ(variant.toPointer(), pointer);
}

TEST(VariantTest, toString)
{
  Variant variant("hello");
  EXPECT_EQ(variant.toString(), "hello"s);

  variant.setValue(12);
  EXPECT_EQ(variant.toString(), "12"s);

  variant.setValue("hello2"s);
  EXPECT_EQ(variant.toString(), "hello2"s);
}

TEST(VariantTest, toMatrix)
{
  MatrixX matrix(6, 7);
  for (int row = 0; row < matrix.rows(); ++row) {
    for (int col = 0; col < matrix.cols(); ++col) {
      matrix(row, col) = 2 * row + col / static_cast<double>(matrix.cols());
    }
  }

  Variant variant(matrix);
  const MatrixX& varMatrix = variant.toMatrixRef();

  ASSERT_EQ(matrix.rows(), varMatrix.rows())
    << "Number of rows don't match after variant-matrix conversion!";
  ASSERT_EQ(matrix.cols(), varMatrix.cols())
    << "Number of columns don't match after variant-matrix conversion!";
  for (int row = 0; row < matrix.rows(); ++row) {
    for (int col = 0; col < matrix.cols(); ++col) {
      EXPECT_EQ(matrix(row, col), varMatrix(row, col))
        << "Value mismatch at " << row << ", " << col << "!";
    }
  }
}
