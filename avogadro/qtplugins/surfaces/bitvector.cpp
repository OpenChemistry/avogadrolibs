#include "bitvector.h"
#include <Eigen/Dense>

namespace Avogadro {

namespace QtPlugins {

// Constructor - takes a vector representing dimensions
BitVector::BitVector(Vector3i dimensions)
{
  BitVector(dimensions[0], dimensions[1], dimensions[2]);
}

// Constructor - takes ints length, width, and height
BitVector::BitVector(int length, int width, int height)
{
  m_length = length;
  m_width = width;
  m_height = height;
  byteArray = new unsigned char[length * width * height / 8 + 1];
  for (int i = 0; i < length * width * height / 8 + 1; i++) {
    byteArray[i] = byteArray[i] & 0;
  }
}

BitVector::~BitVector()
{
  delete[] byteArray;
}

// returns value at location
bool BitVector::value(Vector3i location)
{
  return value(location[0], location[1], location[2]);
}

// returns value at x, y, z
bool BitVector::value(int x, int y, int z)
{
  int byteIndex = findIndex(x, y, z) / 8;
  int bitIndex = findIndex(x, y, z) % 8;
  unsigned char a = byteArray[byteIndex] >> bitIndex;
  unsigned char b = a & 1;
  if (b == 1) {
    return true;
  } else if (b == 0) {
    return false;
  }
  return false;
  // shouldn't ever happen, but we have to make the compiler happy
  // we could also avoid the shifting and use greater than less than
  // rather than equal to
}

// sets value at location equal to value
void BitVector::setValue(Vector3i location, bool value)
{
  setValue(location[0], location[1], location[2], value);
}

// sets value at x, y, z equal to value
void BitVector::setValue(int x, int y, int z, bool value)
{
  int byteIndex = findIndex(x, y, z) / 8;
  int bitIndex = findIndex(x, y, z) % 8;
  unsigned char bitMask = pow(2, bitIndex);
  // to set a 1
  if (value) {
    byteArray[byteIndex] = byteArray[byteIndex] | bitMask;
  }

  // to set a zero
  else {
    bitMask = ~bitMask;
    byteArray[byteIndex] = byteArray[byteIndex] & bitMask;
  }
}

int BitVector::findIndex(Vector3i location)
{
  return findIndex(location[0], location[1], location[2]);
}

int BitVector::findIndex(int x, int y, int z)
{
  return x * m_width * m_height + y * m_height % m_width + z;
}

} // namespace QtPlugins

} // namespace Avogadro
