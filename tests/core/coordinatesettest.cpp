/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/coordinateset.h>
#include <avogadro/core/vector.h>

using Avogadro::Vector3;
using Avogadro::Core::ArraySet;
using Avogadro::Core::CoordinateSet;

TEST(CoordinateSetTest, StoreType)
{
  ArraySet* array = new CoordinateSet<Vector3>;

  EXPECT_TRUE(array->isType(Vector3()));

  delete array;
  array = nullptr;

  array = new CoordinateSet<float>;
  EXPECT_TRUE(array->isType(float()));
  delete array;
  array = nullptr;
}

TEST(CoordinateSetTest, Resize)
{
  CoordinateSet<Vector3> data;
  data.resize(5);
  EXPECT_EQ(data.size(), static_cast<size_t>(5));

  data.resize(3);
  EXPECT_EQ(data.size(), static_cast<size_t>(3));
}

TEST(CoordinateSetTest, Store)
{
  CoordinateSet<Vector3> data;
  data.resize(5);
  data[0] = Vector3(0.0, 1.0, 2.0);
  EXPECT_EQ(data[0].x(), 0.0);
  EXPECT_EQ(data[0].y(), 1.0);
  EXPECT_EQ(data[0].z(), 2.0);
}

TEST(CoordinateSetTest, StoreTypeRetrieve)
{
  CoordinateSet<Vector3> data;
  data.resize(5);
  data[0] = Vector3(0.0, 1.0, 2.0);

  ArraySet* array = &data;
  CoordinateSet<Vector3>& ref =
    *reinterpret_cast<CoordinateSet<Vector3>*>(array);
  EXPECT_EQ(ref[0].x(), 0.0);
  EXPECT_EQ(ref[0].y(), 1.0);
  EXPECT_EQ(ref[0].z(), 2.0);
}
