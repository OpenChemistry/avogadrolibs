/******************************************************************************

  This source file is part of the MolCore project.

  Copyright 2011 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <array.h>

using MolCore::Array;

TEST(ArrayTest, setSize)
{
  MolCore::Array<int> array;

  EXPECT_EQ(array.size(), 0);

  array.resize(2);
  EXPECT_EQ(array.size(), 2);
}

TEST(ArrayTest, isEmpty)
{
  Array<int> array;
  EXPECT_TRUE(array.empty());
}

TEST(ArrayTest, push_back)
{
  MolCore::Array<int> array;
  array.push_back(6);
  EXPECT_EQ(array.size(), 1);
  array.push_back(9);
  EXPECT_EQ(array.size(), 2);
}

TEST(ArrayTest, clear)
{
  MolCore::Array<int> array;
  array.push_back(6);
  EXPECT_EQ(array.size(), 1);
  array.push_back(9);
  EXPECT_EQ(array.size(), 2);
  array.clear();
  EXPECT_EQ(array.size(), 0);
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
