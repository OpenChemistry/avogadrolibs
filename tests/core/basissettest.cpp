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

using namespace Avogadro::Core;
using Avogadro::Core::SlaterSet;

TEST(BasisSetTest, homo)
{
  SlaterSet basis;

  basis.setElectronCount(2, Alpha);
  EXPECT_EQ(basis.homo(Alpha), 1);
  EXPECT_TRUE(basis.homo(basis.homo(Alpha), Alpha));

  EXPECT_EQ(basis.lumo(Alpha), 2);
  EXPECT_TRUE(basis.lumo(basis.lumo(Alpha), Alpha));


  basis = SlaterSet();
  basis.setElectronCount(2, Alpha);
  basis.setElectronCount(1, Beta);

  EXPECT_EQ(basis.homo(Alpha), 2);
  EXPECT_EQ(basis.homo(Beta), 1);

  EXPECT_TRUE(basis.homo(basis.homo(Alpha), Alpha));
  EXPECT_TRUE(basis.homo(basis.homo(Beta), Beta));

  EXPECT_TRUE(!basis.homo(basis.homo(Alpha), Beta));
}

