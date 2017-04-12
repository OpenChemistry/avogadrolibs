/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/variant.h>

using Avogadro::MatrixX;
using Avogadro::Core::Variant;

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
  EXPECT_EQ(variant.toString(), std::string("hello"));

  variant.setValue(12);
  EXPECT_EQ(variant.toString(), std::string("12"));

  variant.setValue(std::string("hello2"));
  EXPECT_EQ(variant.toString(), std::string("hello2"));
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
