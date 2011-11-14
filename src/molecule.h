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

#ifndef MOLCORE_MOLECULE_H
#define MOLCORE_MOLECULE_H

#include "molcore.h"

#include <vector>

#include "atom.h"
#include "bond.h"
#include "graph.h"
#include "variantmap.h"

namespace MolCore {

class MOLCORE_EXPORT Molecule
{
public:
  // construction and destruction
  Molecule();
  ~Molecule();

  // properties
  size_t size() const;
  bool isEmpty() const;
  void setData(const std::string &name, const Variant &value);
  Variant data(const std::string &name) const;
  std::vector<unsigned char>& atomicNumbers();
  const std::vector<unsigned char>& atomicNumbers() const;
  std::vector<std::pair<size_t, size_t> >& bondPairs();
  const std::vector<std::pair<size_t, size_t> >& bondPairs() const;
  std::vector<unsigned char>& bondOrders();
  const std::vector<unsigned char>& bondOrders() const;
  Graph& graph();
  const Graph& graph() const;

  // structure
  Atom addAtom(unsigned char atomicNumber);
  Atom atom(size_t index) const;
  size_t atomCount() const;
  Bond addBond(const Atom &a, const Atom &b, unsigned char bondOrder = 1);
  void removeBond(size_t index);
  void removeBond(const Bond &bond);
  void removeBond(const Atom &a, const Atom &b);
  Bond bond(size_t index) const;
  Bond bond(const Atom &a, const Atom &b) const;
  size_t bondCount() const;

private:
  Graph m_graph;
  VariantMap m_data;
  std::vector<unsigned char> m_atomicNumbers;
  std::vector<std::pair<size_t, size_t> > m_bondPairs;
  std::vector<unsigned char> m_bondOrders;
};

} // end MolCore namespace

#endif // MOLCORE_MOLECULE_H
