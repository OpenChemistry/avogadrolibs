/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_CARTOON_H
#define AVOGADRO_RENDERING_CARTOON_H

#include "bsplinegeometry.h"

#include <avogadro/core/residue.h>

namespace Avogadro {
namespace Rendering {

enum CartoonType
{
  Undefined = -1, // constant small radius
  Body = 0,       // constant big radius
  Arrow = 3,      // arrow head
  Head = 2,       // decreasing
  Tail = 1        // increasing
};

class AVOGADRORENDERING_EXPORT Cartoon : public BSplineGeometry
{

public:
  struct PackedVertex
  {
    Vector4ub color;          //  4 bytes
    Vector3f normal;          // 12 bytes
    Vector3f vertex;          // 12 bytes
    unsigned char padding[4]; //  4 bytes

    PackedVertex(const Vector4ub& c, const Vector3f& n, const Vector3f& v)
      : color(c)
      , normal(n)
      , vertex(v)
    {}

    static int colorOffset() { return 0; }
    static int normalOffset() { return static_cast<int>(sizeof(Vector4ub)); }
    static int vertexOffset()
    {
      return normalOffset() + static_cast<int>(sizeof(Vector3f));
    }
  }; // 32 bytes total size - 16/32/64 are ideal for alignment.


  Cartoon();
  Cartoon(float minRadius, float maxRadius);
  static const float ELIPSE_RATIO;

  void addPoint(const Vector3f& pos, const Vector3ub& color, size_t group,
                size_t id, Core::Residue::SecondaryStructure sec);

protected:
  // create an ellipsis and adapt it to the affine A
  std::vector<ColorNormalVertex> computeCirclePoints(const Eigen::Affine3f& a,
                                                     const Eigen::Affine3f& b,
                                                     bool flat) const override;

  float computeScale(size_t index, float t, float scale) const override;
  void render(const Camera& camera) override;
  void update();


  std::vector<std::pair<CartoonType, size_t>> m_type;
  float m_minRadius, m_maxRadius;
};
} // namespace Rendering
} // namespace Avogadro

#endif
