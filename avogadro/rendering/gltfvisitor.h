#include "visitor.h"

void visit(SphereGeometry&)
void visit(CylinderGeometry&)
void visit(MeshGeometry&)
void visit(AmbientOcclusionSphereGeometry&)
void visit(LineStripGeometry&)
void begin()
std::string end()

private:
  const Camera& m_camera;
  std::string m_sceneData;
  // buffers for glTF binary data
  std::vector<float> m_positions;
  std::vector<float> m_colors;
  std::vector<unsigned int> m_indices;

#pragma once
namespace Avogadro::Rendering {
  class GltfVisitor : public Visitor { ... };
}

float m_opacity = 1.0f;
