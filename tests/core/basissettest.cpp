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

#include <avogadro/core/basisset.h>
#include <avogadro/core/slaterset.h>

using Avogadro::Core::BasisSet;
using Avogadro::Core::SlaterSet;

TEST(BasisSetTest, homo)
{
  SlaterSet basis;

  basis.setElectronCount(2, BasisSet::Paired);
  EXPECT_EQ(basis.homo(), 1);
  EXPECT_TRUE(basis.homo(basis.homo()));

  EXPECT_EQ(basis.lumo(), 2);
  EXPECT_TRUE(basis.lumo(basis.lumo()));

  basis = SlaterSet();
  basis.setElectronCount(2, BasisSet::Alpha);
  basis.setElectronCount(1, BasisSet::Beta);

  EXPECT_EQ(basis.homo(), 1);
  EXPECT_TRUE(basis.homo(basis.homo()));

  // This is broken: the lumo could be either the
  // next alpha or the next beta depending on the
  // energetics of the system

  // EXPECT_EQ(basis.lumo(), 2);
  // EXPECT_TRUE(basis.lumo(basis.lumo()));
}
