/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/rendering/shaderprogram.h>
#include <avogadro/rendering/texture2d.h>

#include <iostream>
#include <vector>

using namespace Avogadro;
using namespace Avogadro::Rendering;

// Run under Node without a GL context: rejected inputs must return before
// issuing any GL calls or allocating a texture/program handle.
int main()
{
  Texture2D texture;
  const std::vector<unsigned char> pixel{ 1, 2, 3, 255 };
  for (auto format : { Texture2D::IncomingBGR, Texture2D::IncomingBGRA }) {
    if (texture.upload(pixel, Vector2i(1, 1), format,
                       Texture2D::InternalRGBA) ||
        texture.error().find("BGR") == std::string::npos ||
        texture.handle() != 0) {
      std::cerr << "BGR/BGRA input was not rejected before upload\n";
      return 1;
    }
  }
  ShaderProgram program;
  if (program.useAttributeArray("position", 0, 3 * sizeof(double), DoubleType,
                                3, ShaderProgram::NoNormalize) ||
      program.error().find("double") == std::string::npos) {
    std::cerr << "Double attributes were not rejected before GL lookup\n";
    return 1;
  }
  const std::vector<double> vertex{ 1., 2., 3. };
  if (program.setAttributeArray("position", vertex, 3,
                                ShaderProgram::NoNormalize) ||
      program.error().find("double") == std::string::npos) {
    std::cerr << "Double client arrays were not rejected before GL lookup\n";
    return 1;
  }
  std::cout << "BGR, BGRA and double input rejection passed\n";
  return 0;
}
