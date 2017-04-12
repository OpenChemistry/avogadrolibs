#include <google/protobuf/stubs/common.h>

/**
 * namespace containing utility functions for encoding and decoding
 * floats and doubles.
 */
namespace Avogadro {
namespace ProtoCall {
namespace Utils {

using google::protobuf::uint32;
using google::protobuf::uint64;

inline uint32 encodeFloat(float value)
{
  union
  {
    float f;
    uint32 i;
  };
  f = value;
  return i;
}

inline float decodeFloat(uint32 value)
{
  union
  {
    float f;
    uint32 i;
  };
  i = value;
  return f;
}

inline uint64 encodeDouble(double value)
{
  union
  {
    double f;
    uint64 i;
  };
  f = value;
  return i;
}

inline double decodeDouble(uint64 value)
{
  union
  {
    double f;
    uint64 i;
  };
  i = value;
  return f;
}

} // Utils namespace
} // ProtoCall namespace
} // Avogadro namespace
