/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "povrayvisitor.h"

#include "ambientocclusionspheregeometry.h"
#include "cylindergeometry.h"
#include "linestripgeometry.h"
#include "meshgeometry.h"
#include "spheregeometry.h"

#include <iostream>
#include <ostream>

namespace Avogadro {
namespace Rendering {

using std::cout;
using std::string;
using std::endl;
using std::ostringstream;
using std::ostream;
using std::ofstream;

namespace {
ostream& operator<<(ostream& os, const Vector3f& v)
{
  os << v[0] << ", " << v[1] << ", " << v[2];
  return os;
}

ostream& operator<<(ostream& os, const Vector3ub& color)
{
  os << color[0] / 255.0f << ", " << color[1] / 255.0f << ", "
     << color[2] / 255.0f;
  return os;
}
}

POVRayVisitor::POVRayVisitor(const Camera& c)
  : m_camera(c), m_backgroundColor(255, 255, 255),
    m_ambientColor(100, 100, 100), m_aspectRatio(800.0f / 600.0f)
{
}

POVRayVisitor::~POVRayVisitor()
{
}

void POVRayVisitor::begin()
{
  // Initialise our POV-Ray scene
  // The POV-Ray camera basically has the same matrix elements - we just need to
  // translate
  // FIXME Still working on getting the translation to POV-Ray right...
  Vector3f cameraT = -(m_camera.modelView().linear().adjoint() *
                       m_camera.modelView().translation());
  Vector3f cameraX =
    m_camera.modelView().linear().row(0).transpose().normalized();
  Vector3f cameraY =
    m_camera.modelView().linear().row(1).transpose().normalized();
  Vector3f cameraZ =
    -m_camera.modelView().linear().row(2).transpose().normalized();

  double huge = 100;

  Vector3f light0pos =
    huge * (m_camera.modelView().linear().adjoint() * Vector3f(0, 1, 0));

  // Output the POV-Ray initialisation code
  ostringstream str;
  str << "global_settings {\n"
      << "\tambient_light rgb <" << m_ambientColor << ">\n"
      << "\tmax_trace_level 15\n}\n\n"
      << "background { color rgb <" << m_backgroundColor << "> }\n\n"
      << "camera {\n"
      << "\tperspective\n"
      << "\tlocation <" << cameraT.x() << ", " << cameraT.y() << ", "
      << cameraT.z() << ">\n"
      << "\tangle 70\n"
      << "\tup <" << cameraY.x() << ", " << cameraY.y() << ", " << cameraY.z()
      << ">\n"
      << "\tright <" << cameraX.x() << ", " << cameraX.y() << ", "
      << cameraX.z() << "> * " << m_aspectRatio << '\n'
      << "\tdirection <" << cameraZ.x() << ", " << cameraZ.y() << ", "
      << cameraZ.z() << "> }\n\n"

      << "light_source {\n"
      << "\t<" << light0pos[0] << ", " << light0pos[1] << ", " << light0pos[2]
      << ">\n"
      << "\tcolor rgb <1.0, 1.0, 1.0>\n"
      << "\tfade_distance " << 2 * huge << '\n'
      << "\tfade_power 0\n"
      << "\tparallel\n"
      << "\tpoint_at <" << -light0pos[0] << ", " << -light0pos[1] << ", "
      << -light0pos[2] << ">\n"
      << "}\n\n"

      << "#default {\n\tfinish {ambient .8 diffuse 1 specular 1 roughness .005 "
         "metallic 0.5}\n}\n\n";

  m_sceneData = str.str();
}

string POVRayVisitor::end()
{
  return m_sceneData;
}

void POVRayVisitor::visit(Drawable& geometry)
{
  // geometry.render(m_camera);
}

void POVRayVisitor::visit(SphereGeometry& geometry)
{
  ostringstream str;
  for (size_t i = 0; i < geometry.spheres().size(); ++i) {
    Rendering::SphereColor s = geometry.spheres()[i];
    str << "sphere {\n\t<" << s.center << ">, " << s.radius
        << "\n\tpigment { rgbt <" << s.color << ", 0.0> }\n}\n";
  }
  m_sceneData += str.str();
}

void POVRayVisitor::visit(AmbientOcclusionSphereGeometry& geometry)
{
  // geometry.render(m_camera);
}

void POVRayVisitor::visit(CylinderGeometry& geometry)
{
  ostringstream str;
  for (size_t i = 0; i < geometry.cylinders().size(); ++i) {
    Rendering::CylinderColor c = geometry.cylinders()[i];
    str << "cylinder {\n"
        << "\t<" << c.end1 << ">,\n"
        << "\t<" << c.end2 << ">, " << c.radius << "\n\tpigment { rgbt <"
        << c.color << ", 0.0> }\n}\n";
  }
  m_sceneData += str.str();
}

void POVRayVisitor::visit(MeshGeometry& geometry)
{
  ostringstream str;
  str << "mesh2 {\n";
  Core::Array<Rendering::MeshGeometry::PackedVertex> v = geometry.vertices();
  Core::Array<unsigned int> tris = geometry.triangles();
  str << "vertex_vectors{" << v.size() << ",\n";
  for (size_t i = 0; i < v.size(); ++i) {
    str << "<" << v[i].vertex << ">,";
    if (i != 0 && i % 3)
      str << "\n";
  }
  str << "\n}\n";
  str << "normal_vectors{" << v.size() << ",\n";
  for (size_t i = 0; i < v.size(); ++i) {
    str << "<" << v[i].normal << ">,";
    if (i != 0 && i % 3)
      str << "\n";
  }
  str << "\n}\n";
  str << "texture_list{" << v.size() << ",\n";
  for (size_t i = 0; i < v.size(); ++i)
    str << "texture{pigment{rgb<" << v[i].normal << ">}\n";
  str << "\n}\n";
  str << "face_indices{" << tris.size() / 3 << ",\n";
  for (size_t i = 0; i < tris.size(); i += 3) {
    str << "<" << tris[i] << "," << tris[i + 1] << "," << tris[i + 2] << ">";
    if (i != tris.size() - 3)
      str << ", ";
    if (i != 0 && ((i + 1) / 3) % 3 == 0)
      str << '\n';
  }
  str << "\n}\n";
  str << "\tpigment { rgbt <1.0, 0.0, 0.0, 1.0> }\n"
      << "}\n\n";
}

void POVRayVisitor::visit(LineStripGeometry& geometry)
{
  // geometry.render(m_camera);
}

} // End namespace Rendering
} // End namespace Avogadro
