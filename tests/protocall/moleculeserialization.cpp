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

#include <avogadro/io/fileformatmanager.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <gtest/gtest.h>

#include "moleculedeserializer.h"
#include "moleculeserializer.h"
#include "protocalltests.h"

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;
using Avogadro::Core::MoleculeDeserializer;
using Avogadro::Core::MoleculeSerializer;

using google::protobuf::io::ArrayOutputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::CodedInputStream;
using google::protobuf::uint32;
using google::protobuf::uint8;

class MoleculeSerializationTest : public testing::Test
{
protected:
  virtual void SetUp()
  {
    FileFormatManager::instance().readFile(
      ethane, AVOGADRO_DATA "/data/ethane.cml", "cml");
  }

  bool equal(const Avogadro::MatrixX& mat1, const Avogadro::MatrixX& mat2)
  {
    if (mat1.rows() != mat2.rows() || mat1.cols() != mat2.cols())
      return false;
    for (int row = 0; row < mat1.rows(); row++) {
      for (int col = 0; col < mat1.cols(); col++) {
        if (mat1(row, col) != mat2(row, col))
          return false;
      }
    }

    return true;
  }

  Molecule ethane;
};

TEST_F(MoleculeSerializationTest, roundTrip)
{
  MoleculeSerializer serializer(&this->ethane);

  size_t size = serializer.size();

  uint8* data = new uint8[size];

  bool success = serializer.serialize(data, size);
  EXPECT_TRUE(success);

  Molecule after;

  MoleculeDeserializer deserializer(&after);
  success = deserializer.deserialize(data, size);
  EXPECT_TRUE(success);

  delete[] data;

  EXPECT_EQ(this->ethane.atomicNumbers(), after.atomicNumbers());

  std::vector<Avogadro::Vector2> expected2d = this->ethane.atomPositions2d();
  std::vector<Avogadro::Vector2> actual2d = after.atomPositions2d();

  EXPECT_EQ(expected2d.size(), actual2d.size());

  for (size_t i = 0; i < expected2d.size(); i++)
    EXPECT_TRUE(this->equal(expected2d[i], actual2d[i]));

  std::vector<Avogadro::Vector3> expected3d = this->ethane.atomPositions3d();
  std::vector<Avogadro::Vector3> actual3d = after.atomPositions3d();

  EXPECT_EQ(expected3d.size(), actual3d.size());

  for (size_t i = 0; i < expected3d.size(); i++)
    EXPECT_TRUE(this->equal(expected3d[i], actual3d[i]));

  const std::vector<std::pair<size_t, size_t>> expectedBondPairs =
    this->ethane.bondPairs();
  const std::vector<std::pair<size_t, size_t>> actualBondPairs =
    after.bondPairs();

  EXPECT_EQ(expectedBondPairs.size(), actualBondPairs.size());

  for (size_t i = 0; i < expectedBondPairs.size(); i++) {
    EXPECT_EQ(expectedBondPairs[i].first, actualBondPairs[i].first);
    EXPECT_EQ(expectedBondPairs[i].second, actualBondPairs[i].second);
  }

  const std::vector<unsigned char> expectedBondOrder =
    this->ethane.bondOrders();
  const std::vector<unsigned char> actualBondOrder = after.bondOrders();

  for (size_t i = 0; i < expectedBondOrder.size(); i++)
    EXPECT_EQ(expectedBondOrder[i], actualBondOrder[i]);
}
