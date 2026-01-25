/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_PACKEDVERTEX_H
#define AVOGADRO_RENDERING_PACKEDVERTEX_H

#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

/**
 * @struct PackedVertex packedvertex.h <avogadro/rendering/packedvertex.h>
 * @brief Packed vertex structure for efficient GPU transfer.
 *
 * This structure packs color, normal, and vertex data into a 32-byte aligned
 * format that is ideal for GPU memory access patterns.
 */
struct PackedVertex
{
  Vector4ub color;          //  4 bytes
  Vector3f normal;          // 12 bytes
  Vector3f vertex;          // 12 bytes
  unsigned char padding[4]; //  4 bytes

  PackedVertex() : color(0, 0, 0, 255), normal(0, 0, 1), vertex(0, 0, 0) {}

  PackedVertex(const Vector4ub& c, const Vector3f& n, const Vector3f& v)
    : color(c), normal(n), vertex(v)
  {
  }

  static int colorOffset() { return 0; }
  static int normalOffset() { return static_cast<int>(sizeof(Vector4ub)); }
  static int vertexOffset()
  {
    return normalOffset() + static_cast<int>(sizeof(Vector3f));
  }
}; // 32 bytes total size - 16/32/64 are ideal for alignment.

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_PACKEDVERTEX_H
