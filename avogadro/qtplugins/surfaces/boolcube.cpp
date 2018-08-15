#include "boolcube.h"
#include <Eigen/Dense>

namespace Avogadro {

namespace QtPlugins {

// Constructor - takes a vector representing dimensions
BoolCube::BoolCube(Vector3i dimensions)
{
  BoolCube(dimensions[0], dimensions[1], dimensions[2]);
}

// Constructor - takes ints length, width, and height
BoolCube::BoolCube(int length, int width, int height)
{
  m_length = length;
  m_width = width;
  m_height = height;

  bools = new bool**[length];
  for (int i = 0; i < length; i++) {
    bools[i] = new bool*[width];
    for (int j = 0; j < width; j++) {
      bools[i][j] = new bool[height];
      for (int k = 0; k < height; k++) {
        bools[i][j][k] = false;
      }
    }
  }
}

BoolCube::~BoolCube()
{
  for (int i = 0; i < m_length; i++) {
    for (int j = 0; j < m_width; j++) {
      delete[] bools[i][j];
    }
    delete[] bools[i];
  }
  delete[] bools;
}

// returns value at location
bool BoolCube::value(Vector3i location)
{
  return value(location[0], location[1], location[2]);
}

// returns value at x, y, z
bool BoolCube::value(int x, int y, int z)
{
  return bools[x][y][z];
}

// sets value at location equal to value
void BoolCube::setValue(Vector3i location, bool value)
{
  setValue(location[0], location[1], location[2], value);
  return;
}

// sets value at x, y, z equal to value
void BoolCube::setValue(int x, int y, int z, bool value)
{
  bools[x][y][z] = value;
  return;
}

} // namespace QtPlugins

} // namespace Avogadro
