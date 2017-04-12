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

#include "moleculeserializer.h"

#include "matrixserialization.h"
#include <avogadro/io/fileformatmanager.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include <iostream>

namespace Avogadro {
namespace Core {

using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;

using google::protobuf::io::ArrayOutputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::CodedInputStream;
using google::protobuf::uint32;
using google::protobuf::uint8;

MoleculeSerializer::MoleculeSerializer(const Avogadro::Core::Molecule* molecule)
  : m_molecule(molecule)
{
}

bool MoleculeSerializer::serialize(void* data, size_t size_)
{
  ArrayOutputStream aos(data, size_);
  CodedOutputStream cos(&aos);

  // Write atomic numbers
  if (!this->serializeAtomicNumbers(&cos))
    return false;

  // Write position2d
  if (!this->serializePositons2d(&cos))
    return false;

  // Write position3d
  if (!this->serializePostions3d(&cos))
    return false;

  // Write bondPairs
  if (!this->serializeBondPairs(&cos))
    return false;

  // Write bondOrders
  if (!this->serializeBondOrders(&cos))
    return false;

  return true;
}

size_t MoleculeSerializer::size()
{
  // atomicNumbers
  size_t moleSize =
    sizeof(uint32) + m_molecule->atomicNumbers().size() * sizeof(unsigned char);

  // positions2d
  moleSize += sizeof(uint32);
  std::vector<Avogadro::Vector2> pos2d = m_molecule->atomPositions2d();
  for (std::vector<Avogadro::Vector2>::iterator it = pos2d.begin();
       it != pos2d.end(); ++it) {
    moleSize += ProtoCall::MatrixSerialization::sizeOf(*it);
  }

  // positions3d
  moleSize += sizeof(uint32);
  std::vector<Avogadro::Vector3> pos3d = m_molecule->atomPositions3d();
  for (std::vector<Avogadro::Vector3>::iterator it = pos3d.begin();
       it != pos3d.end(); ++it) {
    moleSize += ProtoCall::MatrixSerialization::sizeOf(*it);
  }

  // bondPairs
  moleSize += this->sizeOfBondPairs();
  // bondOrder
  moleSize += this->sizeOfBondOrders();

  return moleSize;
}

bool MoleculeSerializer::serializeAtomicNumbers(
  google::protobuf::io::CodedOutputStream* stream)
{
  // Write atomic numbers
  uint32 numberOfAtoms = m_molecule->atomicNumbers().size();
  stream->WriteLittleEndian32(numberOfAtoms);
  if (stream->HadError())
    return false;
  std::vector<unsigned char> atomicNumbers = m_molecule->atomicNumbers();
  stream->WriteRaw(&atomicNumbers[0], numberOfAtoms * sizeof(unsigned char));
  if (stream->HadError())
    return false;

  return true;
}

bool MoleculeSerializer::serializePositons2d(
  google::protobuf::io::CodedOutputStream* stream)
{
  std::vector<Avogadro::Vector2> pos2d = m_molecule->atomPositions2d();
  stream->WriteLittleEndian32(pos2d.size());
  if (stream->HadError())
    return false;
  for (std::vector<Avogadro::Vector2>::iterator it = pos2d.begin();
       it != pos2d.end(); ++it) {
    if (!ProtoCall::MatrixSerialization::serialize(*it, stream))
      return false;
  }

  return true;
}

bool MoleculeSerializer::serializePostions3d(
  google::protobuf::io::CodedOutputStream* stream)
{
  // position3d
  std::vector<Avogadro::Vector3> pos3d = m_molecule->atomPositions3d();
  stream->WriteLittleEndian32(pos3d.size());
  if (stream->HadError())
    return false;
  for (std::vector<Avogadro::Vector3>::iterator it = pos3d.begin();
       it != pos3d.end(); ++it) {
    if (!ProtoCall::MatrixSerialization::serialize(*it, stream))
      return false;
  }

  return true;
}

size_t MoleculeSerializer::sizeOfBondPairs()
{
  return sizeof(uint32) + m_molecule->bondPairs().size() * (2 * sizeof(uint32));
}

bool MoleculeSerializer::serializeBondPairs(
  google::protobuf::io::CodedOutputStream* stream)
{
  // Write the number of pairs
  stream->WriteLittleEndian32(m_molecule->bondPairs().size());

  if (stream->HadError())
    return false;

  for (std::vector<std::pair<size_t, size_t>>::const_iterator it =
         m_molecule->bondPairs().begin();
       it != m_molecule->bondPairs().end(); ++it) {
    std::pair<size_t, size_t> bond = *it;
    stream->WriteLittleEndian32(bond.first);
    if (stream->HadError())
      return false;
    stream->WriteLittleEndian32(bond.second);
    if (stream->HadError())
      return false;
  }

  return true;
}

size_t MoleculeSerializer::sizeOfBondOrders()
{
  return sizeof(uint32) +
         m_molecule->bondOrders().size() * sizeof(unsigned char);
}

bool MoleculeSerializer::serializeBondOrders(
  google::protobuf::io::CodedOutputStream* stream)
{
  stream->WriteLittleEndian32(m_molecule->bondOrders().size());
  if (stream->HadError())
    return false;

  stream->WriteRaw(&m_molecule->bondOrders()[0],
                   m_molecule->bondOrders().size());
  if (stream->HadError())
    return false;

  return true;
}

} // namespace Core
} // namespace Avogadro
