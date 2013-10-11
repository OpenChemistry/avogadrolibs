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

#include <gtest/gtest.h>

#include <avogadro/core/unitcell.h>

using namespace Avogadro;
using namespace Avogadro::Core;

namespace {
const Real DEG_TO_RAD = static_cast<Real>(M_PI / 180.0);
}

TEST(UnitCellTest, cellParameters)
{
  Real a = static_cast<Real>(2.0);
  Real b = static_cast<Real>(3.0);
  Real c = static_cast<Real>(4.0);
  Real alpha = static_cast<Real>(70 * DEG_TO_RAD);
  Real beta = static_cast<Real>(120 * DEG_TO_RAD);
  Real gamma = static_cast<Real>(85 * DEG_TO_RAD);

  UnitCell unitCell;
  unitCell.setCellParameters(a, b, c, alpha, beta, gamma);
  EXPECT_FLOAT_EQ(a, unitCell.a());
  EXPECT_FLOAT_EQ(b, unitCell.b());
  EXPECT_FLOAT_EQ(c, unitCell.c());
  EXPECT_FLOAT_EQ(alpha, unitCell.alpha());
  EXPECT_FLOAT_EQ(beta,  unitCell.beta());
  EXPECT_FLOAT_EQ(gamma, unitCell.gamma());
}
