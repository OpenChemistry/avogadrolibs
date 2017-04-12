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

#include "matrixserialization.h"

#include <avogadro/core/vector.h>
#include <gtest/gtest.h>

TEST(MatrixSerializationTest, vector2)
{
  Avogadro::Vector2 vec2;
  vec2[0] = 1;
  vec2[1] = 2;

  size_t size = Avogadro::ProtoCall::MatrixSerialization::sizeOf(vec2);
  unsigned char* data = new unsigned char[size];

  bool success =
    Avogadro::ProtoCall::MatrixSerialization::serialize(vec2, data, size);
  EXPECT_TRUE(success);

  Avogadro::Vector2 afterRoundTrip;
  success =
    Avogadro::ProtoCall::MatrixSerialization::deserialize(afterRoundTrip, data);

  EXPECT_TRUE(success);

  delete[] data;

  for (int row = 0; row < 2; row++)
    EXPECT_EQ(vec2[row], afterRoundTrip[row]);
}

TEST(MatrixSerializationTest, vector3)
{
  Avogadro::Vector3 vec3;
  vec3[0] = 1;
  vec3[1] = 2;
  vec3[2] = 3;

  size_t size = Avogadro::ProtoCall::MatrixSerialization::sizeOf(vec3);
  unsigned char* data = new unsigned char[size];

  bool success =
    Avogadro::ProtoCall::MatrixSerialization::serialize(vec3, data, size);

  EXPECT_TRUE(success);

  Avogadro::Vector3 afterRoundTrip;
  success =
    Avogadro::ProtoCall::MatrixSerialization::deserialize(afterRoundTrip, data);

  EXPECT_TRUE(success);

  delete[] data;

  for (int row = 0; row < 3; row++)
    EXPECT_EQ(vec3[row], afterRoundTrip[row]);
}

TEST(MatrixSerializationTest, matrixX)
{
  Avogadro::MatrixX matrix(100, 100);

  for (int row = 0; row < 100; row++) {
    for (int col = 0; col < 100; col++) {
      matrix(row, col) = row * col;
    }
  }

  size_t size = Avogadro::ProtoCall::MatrixSerialization::sizeOf(matrix);

  unsigned char* data = new unsigned char[size];

  bool success =
    Avogadro::ProtoCall::MatrixSerialization::serialize(matrix, data, size);

  EXPECT_TRUE(success);

  Avogadro::MatrixX afterRoundTrip(100, 100);
  success = Avogadro::ProtoCall::MatrixSerialization::deserialize(
    afterRoundTrip, data, size);

  EXPECT_TRUE(success);

  delete[] data;

  for (int row = 0; row < 100; row++) {
    for (int col = 0; col < 100; col++)
      EXPECT_EQ(matrix(row, col), afterRoundTrip(row, col));
  }
}
