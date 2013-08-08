#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/core/color3f.h>
#include <avogadro/core/mesh.h>

void assertEqual(const Avogadro::Core::Molecule &m1,
    const Avogadro::Core::Molecule &m2)
{
  EXPECT_EQ(m1.atomCount(), m2.atomCount());
  EXPECT_TRUE(m1.atomicNumbers() == m2.atomicNumbers());
  EXPECT_TRUE(m1.atomPositions2d() == m2.atomPositions2d());
  EXPECT_TRUE(m1.atomPositions3d() == m2.atomPositions3d());
  EXPECT_EQ(m1.data("test").toString(), m2.data("test").toString());
  EXPECT_TRUE(m1.bondPairs() == m2.bondPairs());
  EXPECT_TRUE(m1.bondOrders() == m2.bondOrders());

  EXPECT_EQ(m1.meshCount(), m2.meshCount());
  for(size_t i=0; i<m1.meshCount(); i++) {
    const Avogadro::Core::Mesh *mesh1 = m1.mesh(i);
    const Avogadro::Core::Mesh *mesh2 = m2.mesh(i);

    EXPECT_TRUE(mesh1->vertices() == mesh2->vertices());
    EXPECT_TRUE(mesh1->normals() == mesh2->vertices());
    EXPECT_EQ(mesh1->name(), mesh2->name());
    EXPECT_EQ(mesh1->isoValue(), mesh2->isoValue());
  }
}
