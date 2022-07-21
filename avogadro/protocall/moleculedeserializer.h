/******************************************************************************
 This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
 ******************************************************************************/

#ifndef AVOGADRO_PROTOCALL_MOLECULEDESERIALIZER_H
#define AVOGADRO_PROTOCALL_MOLECULEDESERIALIZER_H

#include "avogadro/core/molecule.h"
#include "avogadroprotocallexport.h"
#include <google/protobuf/io/coded_stream.h>
#include <protocall/serialization/deserializer.h>

namespace Avogadro {
namespace Core {

/**
 * @class MoleculeDeserializer moleculedeserializer.h
 *  <avogadro/protocall/moleculdeeserializer.h>
 * @brief Implementation of ProtoCall::Serialization::Deserializer
 *
 */
class AVOGADROPROTOCALL_EXPORT MoleculeDeserializer
  : public ProtoCall::Serialization::Deserializer
{
public:
  /**
   * @param molecule The molecule to deserialize into.
   */
  MoleculeDeserializer(Molecule* molecule);

  /**
   * Deserialize buffer into molecules.
   *
   * @param data The buffer containing the molecule byte stream.
   * @param size The size of the buffer.
   *
   * @return true if successful, false otherwise.
   */
  bool deserialize(const void* data, size_t size);

private:
  /**
   * Deserialize bond pairs from stream.
   *
   * @return true if successful, false otherwise.
   */
  bool deserializeBondPairs(google::protobuf::io::CodedInputStream* stream);

  /**
   *
   * Deserialize bond order from stream.
   *
   * @return true if successful, false otherwise.
   */
  bool deserializeBondOrders(google::protobuf::io::CodedInputStream* stream);

  /**
   * Deserialize atomic numbers from stream.
   *
   * @return true if successful, false otherwise.
   */
  bool deserializeAtomicNumbers(google::protobuf::io::CodedInputStream* stream);

  /**
   * Deserialize 2d positions from stream.
   *
   * @return true if successful, false otherwise.
   */
  bool deserializePositions2d(google::protobuf::io::CodedInputStream* stream);

  /**
   * Deserialize 3d positions from stream.
   *
   * @return true if successful, false otherwise.
   */
  bool deserializePostions3d(google::protobuf::io::CodedInputStream* stream);

  Molecule* m_molecule;
};

} // namespace Core
} // namespace Avogadro

#endif
