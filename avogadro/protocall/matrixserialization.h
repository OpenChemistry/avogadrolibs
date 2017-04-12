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

#include "avogadroprotocallexport.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>

#ifndef AVOGADRO_PROTOCALL_MATRIXSERIALIZATION_H
#define AVOGADRO_PROTOCALL_MATRIXSERIALIZATION_H

namespace google {
namespace protobuf {
namespace io {
class CodedOutputStream;
class CodedInputStream;
}
}
}

/**
 *  Namespace contain utility methods to serialize and deserialize vectors and
 *  matrixes
 */
namespace Avogadro {
namespace ProtoCall {
namespace MatrixSerialization {

/**
 * @return the size of Avogadro::Vector2 within byte stream.
 */
AVOGADROPROTOCALL_EXPORT size_t sizeOf(const Avogadro::Vector2& vec2);

/**
 * @return the size of Avogadro::Vector3 within byte stream.
 */
AVOGADROPROTOCALL_EXPORT size_t sizeOf(const Avogadro::Vector3& vec3);

/**
 * @return the size of Avogadro::MatrixX within byte stream.
 */
AVOGADROPROTOCALL_EXPORT size_t sizeOf(const Avogadro::MatrixX& matrix);

/**
 *  Serialize Avogadro::Vector2 instance to buffer.
 *
 *  @param vec2 The vector to serialize.
 *  @param data The buffer to serialize into.
 *  @param size The buffer size.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool serialize(const Avogadro::Vector2& vec2,
                                        void* data, size_t size);

/**
 *  Serialize Avogadro::Vector3 instance to buffer.
 *
 *  @param vec3 The vector to serialize.
 *  @param data The buffer to serialize into.
 *  @param size The buffer size.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool serialize(const Avogadro::Vector3& vec3,
                                        void* data, size_t size);

/**
 *  Serialize Avogadro::MatrixX instance to buffer.
 *
 *  @param matrix The matrix to serialize.
 *  @param data The buffer to serialize into.
 *  @param size The buffer size.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool serialize(const Avogadro::MatrixX& matrix,
                                        void* data, size_t size);

/**
 * Serialize Avogadro::Vector2 instance to stream.
 *
 *  @param vec2 The vector to serialize.
 *  @param stream The stream to serialize into.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool serialize(
  const Avogadro::Vector2& vec2,
  google::protobuf::io::CodedOutputStream* stream);

/**
 * Serialize Avogadro::Vector3 instance to stream.
 *
 *  @param vec3 The vector to serialize.
 *  @param stream The stream to serialize into.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool serialize(
  const Avogadro::Vector3& vec3,
  google::protobuf::io::CodedOutputStream* stream);

/**
 * Serialize Avogadro::MatrixX instance to stream.
 *
 *  @param matrix The matrix to serialize.
 *  @param stream The stream to serialize into.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool serialize(
  const Avogadro::MatrixX& matrix,
  google::protobuf::io::CodedOutputStream* stream);

/**
 * Deserialize Avogadro::Vector2 instance from buffer.
 *
 *  @param vec2 The vector to deserialize into.
 *  @param data The buffer to read the instance from.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool deserialize(Avogadro::Vector2& vec2,
                                          const void* data);

/**
 * Deserialize Avogadro::Vector3 instance from buffer.
 *
 *  @param vec3 The vector to deserialize into.
 *  @param data The buffer to read the instance from.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool deserialize(Avogadro::Vector3& vec3,
                                          const void* data);

/**
 * Deserialize Avogadro::MatrixX instance from buffer.
 *
 *  @param matrix The matrix to deserialize into.
 *  @param data The buffer to read the instance from.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool deserialize(Avogadro::MatrixX& matrix,
                                          const void* data, size_t size);

/**
 * Deserialize Avogadro::Vector2 instance from stream.
 *
 *  @param vec2 The vector to deserialize into.
 *  @param stream The stream to read the instance from.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool deserialize(
  Avogadro::Vector2& vec2, google::protobuf::io::CodedInputStream* stream);

/**
 * Deserialize Avogadro::Vector3 instance from stream.
 *
 *  @param vec3 The vector to deserialize into.
 *  @param stream The stream to read the instance from.
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool deserialize(
  Avogadro::Vector3& vec3, google::protobuf::io::CodedInputStream* stream);

/**
 * Deserialize Avogadro::MatrixX instance from stream.
 *
 *  @param matrix The matrix to deserialize into.
 *  @param stream The stream to read the instance from.
 *
 *
 * @return true if successful, false otherwise.
 */
AVOGADROPROTOCALL_EXPORT bool deserialize(
  Avogadro::MatrixX& matrix, google::protobuf::io::CodedInputStream* stream);

} // namespace MatrixSerialization
} // namespace ProtoCall
} // namespace Avogadro

#endif /* MATRIXSERIALIZATION_H_ */
