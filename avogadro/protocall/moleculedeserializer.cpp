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

#include "moleculedeserializer.h"

#include "matrixserialization.h"
#include <avogadro/io/fileformatmanager.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include <iostream>

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;

using google::protobuf::io::ArrayOutputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::CodedInputStream;
using google::protobuf::uint32;
using google::protobuf::uint8;

namespace Avogadro {
namespace Core {

MoleculeDeserializer::MoleculeDeserializer(Molecule* molecule)
  : m_molecule(molecule)
{
}

bool MoleculeDeserializer::deserialize(const void* data, size_t size)
{
  ArrayInputStream ais(data, size);
  CodedInputStream cis(&ais);

  // Read the atoms
  if (!this->deserializeAtomicNumbers(&cis))
    return false;

  // Read the positions2d
  if (!this->deserializePositions2d(&cis))
    return false;

  // Read the positions3d
  if (!this->deserializePostions3d(&cis))
    return false;

  // Read bond pairs
  if (!this->deserializeBondPairs(&cis))
    return false;

  // Read bond orders
  if (!this->deserializeBondOrders(&cis))
    return false;

  return true;
}

bool MoleculeDeserializer::deserializeAtomicNumbers(
  google::protobuf::io::CodedInputStream* stream)
{
  // Read the atoms
  m_molecule->clearAtoms();
  uint32 numberOfAtoms;
  if (!stream->ReadLittleEndian32(&numberOfAtoms))
    return false;
  for (uint32 i = 0; i < numberOfAtoms; i++) {
    unsigned char atom;
    if (!stream->ReadRaw(&atom, sizeof(unsigned char)))
      return false;
    m_molecule->addAtom(atom);
  }

  return true;
}

bool MoleculeDeserializer::deserializePositions2d(
  google::protobuf::io::CodedInputStream* stream)
{
  // Get the count
  uint32 posCount;
  if (!stream->ReadLittleEndian32(&posCount))
    return false;
  // Clear an current positions
  m_molecule->atomPositions2d().clear();
  for (uint32 i = 0; i < posCount; i++) {
    Avogadro::Vector2 vec2;
    if (!ProtoCall::MatrixSerialization::deserialize(vec2, stream))
      return false;
    m_molecule->atomPositions2d().push_back(vec2);
  }

  return true;
}

bool MoleculeDeserializer::deserializePostions3d(
  google::protobuf::io::CodedInputStream* stream)
{
  // Get the count
  uint32 posCount;
  if (!stream->ReadLittleEndian32(&posCount))
    return false;
  // Clear an current positions
  m_molecule->atomPositions3d().clear();
  for (uint32 i = 0; i < posCount; i++) {
    Avogadro::Vector3 vec3;
    if (!ProtoCall::MatrixSerialization::deserialize(vec3, stream))
      return false;
    m_molecule->atomPositions3d().push_back(vec3);
  }

  return true;
}

bool MoleculeDeserializer::deserializeBondPairs(
  google::protobuf::io::CodedInputStream* stream)
{
  uint32 bondCount;
  if (!stream->ReadLittleEndian32(&bondCount))
    return false;

  // Clear and bond pairs
  m_molecule->bondPairs().clear();

  for (uint32 i = 0; i < bondCount; i++) {
    uint32 from, to;
    if (!stream->ReadLittleEndian32(&from))
      return false;
    if (!stream->ReadLittleEndian32(&to))
      return false;
    std::pair<size_t, size_t> bond;
    bond.first = from;
    bond.second = to;
    m_molecule->bondPairs().push_back(bond);
  }

  return true;
}

bool MoleculeDeserializer::deserializeBondOrders(
  google::protobuf::io::CodedInputStream* stream)
{
  uint32 bondOrderCount;
  if (!stream->ReadLittleEndian32(&bondOrderCount))
    return false;

  // Clear bond order
  m_molecule->bondOrders().clear();

  for (uint32 i = 0; i < bondOrderCount; i++) {
    unsigned char bond;
    if (!stream->ReadRaw(&bond, sizeof(unsigned char)))
      return false;

    m_molecule->bondOrders().push_back(bond);
  }

  return true;
}

} // namespace Core
} // namespace Avogadro
