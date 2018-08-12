#ifndef AVOGADRO_QTPLUGINS_BOOLCUBE_H
#define AVOGADRO_QTPLUGINS_BOOLCUBE_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

namespace Avogadro{
namespace QtPlugins{

class BoolCube{
public:

  //Constructor - takes a vector representing dimensions
  BoolCube(Vector3i dimensions);

  //Constructor - takes ints length, width, and height
  BoolCube(int length, int width, int height);

  //destructor
  virtual ~BoolCube();

  //returns value at location
  bool value(Vector3i location);

  //returns value at x, y, z
  bool value(int x, int y, int z);

  //sets value at location equal to value
  void setValue(Vector3i location, bool value);

  //sets value at x, y, z equal to value
  void setValue(int x, int y, int z, bool value);


private:

  int m_length, m_width, m_height;

  bool*** bools;
};//end class BoolCube

}//end namespace QtPlugins
}//end namespace Avogadro

#endif
