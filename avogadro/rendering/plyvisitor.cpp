/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plyvisitor.h"

namespace Avogadro::Rendering {
using std::ofstream;
using std::ostream;
using std::ostringstream;
using std::string;
using std::vector;

namespace {
ostream& operator<<(ostream& os, const Vector3f& v)
{
  os << v[0] << " " << v[1] << " " << v[2];
  return os;
}

ostream& operator<<(ostream& os, const Vector3ub& color)
{
  // PLY expects same number of parameters every time, so if no alpha given use
  // 1
  os << color[0] / 255.0f << " " << color[1] / 255.0f << " "
     << color[2] / 255.0f << " " << 1;
  return os;
}

ostream& operator<<(ostream& os, const Vector4ub& color)
{
  os << color[0] / 255.0f << " " << color[1] / 255.0f << " "
     << color[2] / 255.0f << " " << color[3] / 255.0f;
  return os;
}
} // namespace

PLYVisitor::PLYVisitor(const Camera& c)
  : m_camera(c), m_backgroundColor(255, 255, 255),
    m_ambientColor(100, 100, 100), m_aspectRatio(800.0f / 600.0f)
{
}

PLYVisitor::~PLYVisitor() {}

void PLYVisitor::begin() {}

string PLYVisitor::end()
{
  // Adds the PLY header after the final counts are known
  ostringstream header;

  // Header format
  header << "ply" << '\n'
         << "format ascii 1.0" << '\n'

         << "element vertex " << m_vertexCount << '\n'
         << "property float x" << '\n'
         << "property float y" << '\n'
         << "property float z" << '\n'
         << "property float red" << '\n'
         << "property float green" << '\n'
         << "property float blue" << '\n'
         << "property float alpha" << '\n'

         << "element face " << m_faceCount << '\n'
         << "property list uchar uint vertex_index" << '\n'
         << "end_header" << '\n';

  // Add the vertices and faces
  return header.str() + m_sceneVertices + m_sceneFaces;
}

void PLYVisitor::visit(Drawable&) {}

void PLYVisitor::visit(SphereGeometry& geometry)
{
  for (const auto& s : geometry.spheres()) {
    // Uses an Icosphere method (logic and new functions could be added here to
    // pick different methods)
    visitSphereIcosphereRecursionMethod(s, 5);
  }
}

void PLYVisitor::visitSphereIcosphereRecursionMethod(const SphereColor& sphere,
                                                     unsigned int subdivisions)
{
  Vector3f center = sphere.center;
  float radius = sphere.radius;

  // Defines an Icosahedron Vertices and Faces
  float phi = (1.0f + sqrt(5.0f)) / 2.0f;
  float a = 1.0f;
  float b = 1.0f / phi;

  vector<Vector3f> vertices = { Vector3f(0, b, -a),  Vector3f(b, a, 0),
                                Vector3f(-b, a, 0),  Vector3f(0, b, a),
                                Vector3f(0, -b, a),  Vector3f(-a, 0, b),
                                Vector3f(0, -b, -a), Vector3f(a, 0, -b),
                                Vector3f(a, 0, b),   Vector3f(-a, 0, -b),
                                Vector3f(b, -a, 0),  Vector3f(-b, -a, 0) };

  // Local Indexes for the faces
  vector<vector<unsigned int>> faces = {
    vector<unsigned int>{ 2, 1, 0 },   vector<unsigned int>{ 1, 2, 3 },
    vector<unsigned int>{ 5, 4, 3 },   vector<unsigned int>{ 4, 8, 3 },
    vector<unsigned int>{ 7, 6, 0 },   vector<unsigned int>{ 6, 9, 0 },
    vector<unsigned int>{ 11, 10, 4 }, vector<unsigned int>{ 10, 11, 6 },
    vector<unsigned int>{ 9, 5, 2 },   vector<unsigned int>{ 5, 9, 11 },
    vector<unsigned int>{ 8, 7, 1 },   vector<unsigned int>{ 7, 8, 10 },
    vector<unsigned int>{ 2, 5, 3 },   vector<unsigned int>{ 8, 1, 3 },
    vector<unsigned int>{ 9, 2, 0 },   vector<unsigned int>{ 1, 7, 0 },
    vector<unsigned int>{ 11, 9, 6 },  vector<unsigned int>{ 7, 10, 6 },
    vector<unsigned int>{ 5, 11, 4 },  vector<unsigned int>{ 10, 8, 4 }
  };

  // For every subdivision
  for (unsigned int i = 0; i < subdivisions; ++i) {
    // Prerecord face size so doesn't change mid loop
    int facesSize = faces.size();

    // For every face
    for (int j = 0; j < facesSize; ++j) {
      // Face vertices
      Vector3f faceVertexOne(vertices.at(faces.at(j).at(0)));
      Vector3f faceVertexTwo(vertices.at(faces.at(j).at(1)));
      Vector3f faceVertexThree(vertices.at(faces.at(j).at(2)));
      unsigned int faceIndexOne = faces.at(j).at(0);
      unsigned int faceIndexTwo = faces.at(j).at(1);
      unsigned int faceIndexThree = faces.at(j).at(2);

      // Get the vertex at the midpoint between One and Two and its Index
      Vector3f vertexOneTwo((faceVertexOne[0] + faceVertexTwo[0]) / 2.0f,
                            (faceVertexOne[1] + faceVertexTwo[1]) / 2.0f,
                            (faceVertexOne[2] + faceVertexTwo[2]) / 2.0f);
      unsigned int indexOneTwo = vertices.size();
      vertices.push_back(vertexOneTwo);

      // Get the vertex at the midpoint between Two and Three and its Index
      Vector3f vertexTwoThree((faceVertexTwo[0] + faceVertexThree[0]) / 2.0f,
                              (faceVertexTwo[1] + faceVertexThree[1]) / 2.0f,
                              (faceVertexTwo[2] + faceVertexThree[2]) / 2.0f);
      unsigned int indexTwoThree = vertices.size();
      vertices.push_back(vertexTwoThree);

      // Get the vertex at the midpoint between One and Three and its Index
      Vector3f vertexOneThree((faceVertexOne[0] + faceVertexThree[0]) / 2.0f,
                              (faceVertexOne[1] + faceVertexThree[1]) / 2.0f,
                              (faceVertexOne[2] + faceVertexThree[2]) / 2.0f);
      unsigned int indexOneThree = vertices.size();
      vertices.push_back(vertexOneThree);

      // Replace the original face with one new face and push the others to the
      // back
      vector<unsigned int> subdividedFaceOne = { faceIndexOne, indexOneTwo,
                                                 indexOneThree };
      vector<unsigned int> subdividedFaceTwo = { faceIndexTwo, indexTwoThree,
                                                 indexOneTwo };
      vector<unsigned int> subdividedFaceThree = { faceIndexThree,
                                                   indexOneThree,
                                                   indexTwoThree };
      vector<unsigned int> subdividedFaceFour = { indexOneTwo, indexTwoThree,
                                                  indexOneThree };
      faces.at(j) = subdividedFaceOne;
      faces.push_back(subdividedFaceTwo);
      faces.push_back(subdividedFaceThree);
      faces.push_back(subdividedFaceFour);
    }
  }

  ostringstream vertexStr;
  ostringstream faceStr;

  // Project every vertex onto the sphere and record it
  for (unsigned int i = 0; i < vertices.size(); ++i) {
    // Normalize the vertex and then project it
    float x = vertices.at(i)[0];
    float y = vertices.at(i)[1];
    float z = vertices.at(i)[2];
    float distance = std::hypot(x, y, z);
    vertices.at(i)[0] = (x / distance) * radius;
    vertices.at(i)[1] = (y / distance) * radius;
    vertices.at(i)[2] = (z / distance) * radius;

    // Adjust to be around sphere's radius
    vertices.at(i)[0] += center[0];
    vertices.at(i)[1] += center[1];
    vertices.at(i)[2] += center[2];

    // Add the vertex
    vertexStr << vertices.at(i) << " " << sphere.color << '\n';
  }

  // Adjust every face to have indices for the PLY file and add it
  for (unsigned int i = 0; i < faces.size(); ++i) {
    faceStr << 3 << " " << faces.at(i)[0] + m_vertexCount << " "
            << faces.at(i)[1] + m_vertexCount << " "
            << faces.at(i)[2] + m_vertexCount << '\n';
  }

  // Adjust the counts and add the new vertices and faces
  m_vertexCount += vertices.size();
  m_faceCount += faces.size();
  m_sceneVertices += vertexStr.str();
  m_sceneFaces += faceStr.str();
}

void PLYVisitor::visit(AmbientOcclusionSphereGeometry&) {}

void PLYVisitor::visit(CylinderGeometry& geometry)
{
  for (const auto& c : geometry.cylinders()) {
    // Uses an Icosphere method (logic and new functions could be added here to
    // pick different methods)
    visitCylinderLateralMethod(c, 20);
  }
}

void PLYVisitor::visitCylinderLateralMethod(const CylinderColor& geometry,
                                            unsigned int lateralFaces)
{
  ostringstream vertexStr;
  ostringstream faceStr;

  // Add each end of the cylinder to the vertices
  Vector3f end1 = geometry.end1;
  Vector3f end2 = geometry.end2;
  vertexStr << end1 << " " << geometry.color << '\n';
  vertexStr << end2 << " " << geometry.color << '\n';
  m_vertexCount += 2;

  // Radius and the length vector of cylinder
  float radius = geometry.radius;
  float length =
    std::hypot(end1[0] - end2[0], end1[1] - end2[1], end1[2] - end2[2]);

  // Normalize the plane vector of the cylinder
  Vector3f normalVector((end1[0] - end2[0]) / length,
                        (end1[1] - end2[1]) / length,
                        (end1[2] - end2[2]) / length);

  // Find a basis vector orthogonal to the plane vector
  Vector3f u;

  // If the Plane Vector doesn't point entirely in the y direction
  if (normalVector[1] != 1.0f) {
    // Choose a orthogonal vector for the y-axis (if plane vector points
    // entirely in y, this will be 0-vector)
    u[0] = normalVector[2];
    u[1] = 0;
    u[2] = -1 * normalVector[0];
  }
  // Otherwise, must use different orthogonal vector since y-axis one would be
  // 0-vector
  else {
    u[0] = 0;
    u[1] = normalVector[2];
    u[2] = -1 * normalVector[1];
  }

  // Length of u vector
  float uLength = std::hypot(u[0], u[1], u[2]);

  // Normalize the vector
  u[0] /= uLength;
  u[1] /= uLength;
  u[2] /= uLength;

  // Find the other basis vector orthogonal to the plane vector via u x v =
  // normalVector
  Vector3f v;
  v[0] = normalVector[1] * u[2] - normalVector[2] * u[1];
  v[1] = normalVector[2] * u[0] - normalVector[0] * u[2];
  v[2] = normalVector[0] * u[1] - normalVector[1] * u[0];

  // Angle between each lateral face
  float baseAngle = 2 * 3.14159265359 / lateralFaces;

  // Find the vertices and faces for each lateral face
  for (unsigned int i = 0; i < lateralFaces; ++i) {
    // Current angle
    float angle = baseAngle * i;

    // Code works by assuming there are 2 * lateralFaces vertices in the
    // cylinder (not including the ends). i corresponds to the lateral face
    // number, to which there are two corresponding vertices (top and bottom).

    // Place the top and bottom lateral face vertex into the file (p = center +
    // R*(u*cos(a) + v*sin(a)))
    vertexStr << Vector3f(end1[0] + radius * u[0] * cos(angle) +
                            radius * v[0] * sin(angle),
                          end1[1] + radius * u[1] * cos(angle) +
                            radius * v[1] * sin(angle),
                          end1[2] + radius * u[2] * cos(angle) +
                            radius * v[2] * sin(angle))
              << " " << geometry.color << '\n';
    vertexStr << Vector3f(end2[0] + radius * u[0] * cos(angle) +
                            radius * v[0] * sin(angle),
                          end2[1] + radius * u[1] * cos(angle) +
                            radius * v[1] * sin(angle),
                          end2[2] + radius * u[2] * cos(angle) +
                            radius * v[2] * sin(angle))
              << " " << geometry.color << '\n';

    // Code then needs to create the two lateral faces these vertices create
    // with the next vertices 2 * i gives the index of the first vertex, plus 1
    // for second vertex, plus 2 or 3 for next faces vertex Modulo included for
    // +2 or +3 to prevent going out of bounds

    // Lateral face made up of the next face's first vertex, first vertex, and
    // second vertex
    faceStr << 3 << " " << (2 * i + 2) % (2 * lateralFaces) + m_vertexCount
            << " " << 2 * i + m_vertexCount << " " << 2 * i + 1 + m_vertexCount
            << '\n';
    // Lateral face made up of next face's first vertex, second vertex, and next
    // face's second vertex
    faceStr << 3 << " " << (2 * i + 2) % (2 * lateralFaces) + m_vertexCount
            << " " << 2 * i + 1 + m_vertexCount << " "
            << (2 * i + 3) % (2 * lateralFaces) + m_vertexCount << '\n';

    // Code needs to deal with faces on top and bottom of cylinder
    // To turn local indices to the indices of the PLY file, -2 is used for end1
    // and -1 is used for end2

    // Top face made up of end1, first vertex, and next face's first vertex
    faceStr << 3 << " " << -2 + m_vertexCount << " " << 2 * i + m_vertexCount
            << " " << (2 * i + 2) % (2 * lateralFaces) + m_vertexCount << '\n';
    // Bottom face made up of next face's second vertex, second vertex, and end2
    faceStr << 3 << " " << (2 * i + 3) % (2 * lateralFaces) + m_vertexCount
            << " " << 2 * i + 1 + m_vertexCount << " " << -1 + m_vertexCount
            << '\n';
  }

  // Adjust the counts and add the new vertices and faces
  m_vertexCount += 2 * lateralFaces;
  m_faceCount += 4 * lateralFaces;
  m_sceneVertices += vertexStr.str();
  m_sceneFaces += faceStr.str();
}

void PLYVisitor::visit(MeshGeometry& geometry)
{
  Core::Array<Rendering::MeshGeometry::PackedVertex> v = geometry.vertices();
  Core::Array<unsigned int> tris = geometry.triangles();
  ostringstream vertexStr;
  ostringstream faceStr;

  // Record every vertex in the mesh
  for (size_t i = 0; i < v.size(); ++i) {
    vertexStr << v[i].vertex << " " << v[i].color << '\n';
  }

  // Record every face and adjust the indices
  for (size_t i = 0; i < tris.size(); i += 3) {
    faceStr << 3 << " " << tris[i] + m_vertexCount << " "
            << tris[i + 1] + m_vertexCount << " " << tris[i + 2] + m_vertexCount
            << '\n';
  }

  // Adjust the counts and add the vertices and faces
  // I think the vertex order on the meshes are messed up for the Coordinate
  // System Mesh resulting in mismatched normals, since my code shouldn't be
  // doing anything to it.
  m_vertexCount += v.size();
  m_faceCount += tris.size() / 3;
  m_sceneVertices += vertexStr.str();
  m_sceneFaces += faceStr.str();
}

void PLYVisitor::visit(LineStripGeometry&) {}

} // namespace Avogadro::Rendering
