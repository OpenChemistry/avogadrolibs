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

#include <avogadro/core/variantmap.h>

using Avogadro::Core::VariantMap;

TEST(VariantMapTest, size)
{
  VariantMap map;
  EXPECT_EQ(map.size(), static_cast<size_t>(0));
}

TEST(VariantMapTest, isEmpty)
{
  VariantMap map;
  EXPECT_EQ(map.isEmpty(), true);

  map.setValue("value1", 1);
  EXPECT_EQ(map.isEmpty(), false);
  EXPECT_EQ(map.hasValue("value1"), true);
  EXPECT_EQ(map.hasValue("value2"), false);
  EXPECT_EQ(map.value("value1").toInt(), 1);
}
