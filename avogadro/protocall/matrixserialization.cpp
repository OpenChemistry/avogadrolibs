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

#include "matrixserialization.h"

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <iostream>

#include "utils.h"

namespace Avogadro {
namespace ProtoCall {
namespace MatrixSerialization {

using google::protobuf::uint32;
using google::protobuf::uint64;
using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::ArrayOutputStream;

size_t sizeOf(const Avogadro::Vector2& vec2)
{
  AVO_UNUSED(vec2);

  return 2 * sizeof(uint64);
}

size_t sizeOf(const Avogadro::Vector3& vec3)
{
  AVO_UNUSED(vec3);

  return 3 * sizeof(uint64);
}

size_t sizeOf(const Avogadro::MatrixX& matrix)
{
  // TODO varint encode the size ? ...
  return (2 * sizeof(uint32)) +
         (matrix.rows() * matrix.cols() * sizeof(uint64));
}

bool serializeInternal(const Avogadro::MatrixX& matrix,
                       google::protobuf::io::CodedOutputStream* stream)
{
  for (int row = 0; row < matrix.rows(); row++) {
    for (int col = 0; col < matrix.cols(); col++) {
      uint64 value = Utils::encodeDouble(matrix(row, col));

      stream->WriteLittleEndian64(value);
      if (stream->HadError())
        return false;
    }
  }

  return true;
}

bool serialize(const Avogadro::Vector2& vec2, void* data, size_t size)
{
  ArrayOutputStream aos(data, size);
  CodedOutputStream cos(&aos);

  return serialize(vec2, &cos);
}

bool serialize(const Avogadro::Vector3& vec3, void* data, size_t size)
{
  ArrayOutputStream aos(data, size);
  CodedOutputStream cos(&aos);

  return serialize(vec3, &cos);
}

bool serialize(const Avogadro::MatrixX& matrix, void* data, size_t size)
{
  ArrayOutputStream aos(data, size);
  CodedOutputStream cos(&aos);

  return serialize(matrix, &cos);
}

bool serialize(const Avogadro::Vector2& vec2,
               google::protobuf::io::CodedOutputStream* stream)
{
  return serializeInternal(vec2, stream);
}

bool serialize(const Avogadro::Vector3& vec3,
               google::protobuf::io::CodedOutputStream* stream)
{
  return serializeInternal(vec3, stream);
}

bool serialize(const Avogadro::MatrixX& matrix,
               google::protobuf::io::CodedOutputStream* stream)
{
  stream->WriteLittleEndian32(matrix.rows());
  if (stream->HadError())
    return false;

  stream->WriteLittleEndian32(matrix.cols());
  if (stream->HadError())
    return false;

  return serializeInternal(matrix, stream);
}

bool deserialize(Avogadro::Vector2& vec2, const void* data)
{
  size_t size = sizeOf(vec2);
  ArrayInputStream ais(data, size);
  CodedInputStream cis(&ais);

  return deserialize(vec2, &cis);
}

bool deserialize(Avogadro::Vector3& vec3, const void* data)
{
  size_t size = sizeOf(vec3);
  ArrayInputStream ais(data, size);
  CodedInputStream cis(&ais);

  return deserialize(vec3, &cis);
}

bool deserialize(Avogadro::MatrixX& matrix, const void* data, size_t size)
{
  ArrayInputStream ais(data, size);
  CodedInputStream cis(&ais);

  return deserialize(matrix, &cis);
}

bool deserialize(Avogadro::Vector2& vec2,
                 google::protobuf::io::CodedInputStream* stream)
{
  for (int row = 0; row < 2; row++) {
    uint64 tmp;
    if (!stream->ReadLittleEndian64(&tmp))
      return false;

    vec2[row] = Utils::decodeDouble(tmp);
  }

  return true;
}

bool deserialize(Avogadro::Vector3& vec3,
                 google::protobuf::io::CodedInputStream* stream)
{
  for (int row = 0; row < 3; row++) {
    uint64 tmp;
    if (!stream->ReadLittleEndian64(&tmp))
      return false;

    vec3[row] = Utils::decodeDouble(tmp);
  }

  return true;
}

bool deserialize(Avogadro::MatrixX& matrix,
                 google::protobuf::io::CodedInputStream* stream)
{
  uint32 rows;
  uint32 cols;

  if (!stream->ReadLittleEndian32(&rows)) {
    return false;
  }

  if (!stream->ReadLittleEndian32(&cols))
    return false;

  matrix.resize(rows, cols);

  for (uint32 row = 0; row < rows; row++) {
    for (uint32 col = 0; col < cols; col++) {
      uint64 tmp;
      if (!stream->ReadLittleEndian64(&tmp))
        return false;

      matrix(row, col) = Utils::decodeDouble(tmp);
    }
  }

  return true;
}

} // namespace MatrixSerialization
} // namespace ProtoCall
} // namespace Avogadro
