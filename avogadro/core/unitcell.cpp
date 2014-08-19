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

#include "unitcell.h"

#include <cmath>
#include <iostream>
#include <avogadro/core/vector.h>
#include <avogadro/core/matrix.h>


using std::cout;
using std::endl;
using std::string;
using std::istringstream;
using std::locale;

namespace Avogadro {
namespace Core {

void UnitCell::setCellParameters(Real a_, Real b_, Real c_,
                                 Real al, Real be, Real ga)
{
  // Convert parameters to matrix. See "Appendix 2: Coordinate Systems and
  // Transformations" of the PDB guide (ref v2.2, 4/23/13,
  // http://www.bmsc.washington.edu/CrystaLinks/man/pdb/guide2.2_frame.html)
  const Real cosAlpha = std::cos(al);
  const Real cosBeta  = std::cos(be);
  const Real cosGamma = std::cos(ga);
  const Real sinGamma = std::sin(ga);

  m_cellMatrix(0, 0) = a_;
  m_cellMatrix(1, 0) = static_cast<Real>(0.0);
  m_cellMatrix(1, 0) = static_cast<Real>(0.0);

  m_cellMatrix(0, 1) = b_ * cosGamma;
  m_cellMatrix(1, 1) = b_ * sinGamma;
  m_cellMatrix(2, 1) = static_cast<Real>(0.0);

  m_cellMatrix(0, 2) = c_ * cosBeta;
  m_cellMatrix(1, 2) = c_ * (cosAlpha - cosBeta * cosGamma) / sinGamma;
  m_cellMatrix(2, 2) = (c_ / sinGamma) * std::sqrt(
        static_cast<Real>(1.0)
        - ((cosAlpha * cosAlpha) + (cosBeta * cosBeta) + (cosGamma * cosGamma))
        + (static_cast<Real>(2.0) * cosAlpha * cosBeta * cosGamma));
  computeFractionalMatrix();
}

Real UnitCell::signedAngleRadians(const Vector3 &v1, const Vector3 &v2,
                                  const Vector3 &axis)
{
  const Vector3 crossProduct(v1.cross(v2));
  const Real crossProductNorm(crossProduct.norm());
  const Real dotProduct(v1.dot(v2));
  const Real signDet(crossProduct.dot(axis));
  const Real angle(std::atan2(crossProductNorm, dotProduct));
  return signDet > 0.f ? angle : -angle;
}

void UnitCell::AddTransform(const std::string &s)
{
  Matrix3 m;
  Vector3 v;
  istringstream iss(s);
  locale cLocale("C");
  iss.imbue(cLocale);

  if (s.find(',') != string::npos)
  {
    string row;
    int i;
    size_t j;
    bool neg;
    double *t;
    for (i = 0; i < 3; i++)
    {
      getline(iss, row, ',');
      j = 0;
      neg = false;
      while (j < row.length())
      {
        switch (row[j])
        {
          case '0':
          case '.': // anticipating something like 0.5 or .3333
            {
              char *end;
              switch (i)
              {
                case 0:
                  t = &v.x();
                  break;
                case 1:
                  t = &v.y();
                  break;
                case 2:
                  t = &v.z();
                  break;
              }
              *t = strtod(row.c_str() + j, &end);
              j = end - row.c_str() - 1;
              if (neg)
                *t = - *t;
              break;
            }
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
            if (row[j+1] == '/')
            {
              double *t = NULL;
              switch (i)
              {
                case 0:
                  t = &v.x();
                  break;
                case 1:
                  t = &v.y();
                  break;
                case 2:
                  t = &v.z();
                  break;
              }
              *t = ((double) (row[j] - '0')) / (row[j+2] - '0');
              if (neg)
                *t = - *t;
            }
            j +=2;
            break;
          case '-':
            neg = true;
            break;
          case '+':
            neg = false;
            break;
          case 'x':
            m(i, 0) = (neg)? -1.: 1.;
            break;
          case 'y':
            m(i, 1) = (neg)? -1.: 1.;
            break;
          case 'z':
            m(i, 2) = (neg)? -1.: 1.;
            break;
        }
        j++;
      }
    }
  }
  else if (s.find(' ') != string::npos)
  {
    /* supposing the string is a list of at least 12 float values. If there are
       16, the last four are 0., 0., 0. and 1. and are not needed */
    iss >> m(0,0) >> m(0,1) >> m(0,2) >> v.x();
    iss >> m(1,0) >> m(1,1) >> m(1,2) >> v.y();
    iss >> m(2,0) >> m(2,1) >> m(2,2) >> v.z();
  }
  if (v.x() < 0)
    v.x() += 1.;
  else if (v.x() >= 1.)
    v.x() -= 1.;
  if (v.y() < 0)
    v.y() += 1.;
  else if (v.y() >= 1.)
    v.y() -= 1.;
  if (v.z() < 0)
    v.z() += 1.;
  else if (v.z() >= 1.)
    v.z() -= 1.;
  m_transformM.push_back(m);
  m_transformV.push_back(v);
}

} // end namespace Core
} // end namespace Avogadro
