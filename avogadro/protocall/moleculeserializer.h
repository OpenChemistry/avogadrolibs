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

#ifndef AVOGADRO_PROTOCALL_MOLECULESERIALIZER_H
#define AVOGADRO_PROTOCALL_MOLECULESERIALIZER_H

#include "avogadro/core/molecule.h"
#include "avogadroprotocallexport.h"

#include <google/protobuf/io/coded_stream.h>
#include <protocall/serialization/serializer.h>

namespace Avogadro {
namespace Core {

/**
 * @class MoleculeSerializer moleculeserializer.h
 *  <avogadro/protocall/moleculeserializer.h>
 * @brief Implementation of ProtoCall::Serialization::Serializer
 *
 */
class AVOGADROPROTOCALL_EXPORT MoleculeSerializer
  : public ProtoCall::Serialization::Serializer
{
public:
  /**
   * @param molecule The molecule being serialized
   */
  MoleculeSerializer(const Avogadro::Core::Molecule* molecule);

  /**
   * Serialize the molecule to that buffer provided.
   *
   * @param data The buffer to serialize the molecule into.
   * @param size The size of the buffer.
   *
   * @return true if successful, false otherwise.
   */
  bool serialize(void* data, size_t size);

  /**
   * @return The size of the serialized molecule when written to byte stream.
   */
  size_t size();

private:
  /**
   * @return The size of the bond pairs will take in the byte stream.
   */
  size_t sizeOfBondPairs();

  /**
   * Serialize the bond pairs to the stream.
   *
   * @return true if successful, false otherwise.
   */
  bool serializeBondPairs(google::protobuf::io::CodedOutputStream* stream);

  /**
   * @return The size of the bond orders will take in the byte stream.
   */
  size_t sizeOfBondOrders();

  /**
   * Serialize the bond pairs to the stream.
   *
   * @return true if successful, false otherwise.
   */
  bool serializeBondOrders(google::protobuf::io::CodedOutputStream* stream);

  /**
   * Serialize the atomic numbers to the stream.
   *
   * @return true if successful, false otherwise.
   */
  bool serializeAtomicNumbers(google::protobuf::io::CodedOutputStream* stream);

  /**
   * Serialize the 2d positions to the stream.
   *
   * @return true if successful, false otherwise.
   */
  bool serializePositons2d(google::protobuf::io::CodedOutputStream* stream);

  /**
   * Serialize the 3d positions to the stream.
   *
   * @return true if successful, false otherwise.
   */
  bool serializePostions3d(google::protobuf::io::CodedOutputStream* stream);

  const Avogadro::Core::Molecule* m_molecule;
};

} // namespace Core
} // namespace Avogadro

#endif
