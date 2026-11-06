/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/beziergeometry.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/gltfvisitor.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/spheregeometry.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Core::Array;
using Avogadro::Rendering::BezierGeometry;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::CylinderGeometry;
using Avogadro::Rendering::GltfVisitor;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::SphereGeometry;
using Eigen::Matrix4f;
using Json = nlohmann::json;

namespace {

std::uint32_t readU32(const std::string& s, size_t pos)
{
  std::uint32_t v = 0;
  for (int i = 3; i >= 0; --i)
    v = (v << 8) | static_cast<unsigned char>(s[pos + i]);
  return v;
}

std::uint16_t readU16(const std::string& s, size_t pos)
{
  return static_cast<std::uint16_t>(
    static_cast<unsigned char>(s[pos]) |
    (static_cast<unsigned char>(s[pos + 1]) << 8));
}

float readF32(const std::string& s, size_t pos)
{
  std::uint32_t bits = readU32(s, pos);
  float f;
  static_assert(sizeof(f) == sizeof(bits), "float size");
  std::memcpy(&f, &bits, sizeof(f));
  return f;
}

// A parsed .glb file. Parsing checks the container structure.
struct Glb
{
  Json json;
  std::string bin; // BIN chunk contents, including padding
  bool hasBin = false;

  // Byte offset of the accessor's data in `bin`, its component count and
  // component size.
  size_t accessorOffset(int accessor) const
  {
    const Json& a = json["accessors"][accessor];
    const Json& v = json["bufferViews"][a["bufferView"].get<int>()];
    return v["byteOffset"].get<size_t>() + a.value("byteOffset", 0);
  }

  static int components(const std::string& type)
  {
    if (type == "SCALAR")
      return 1;
    if (type == "VEC3")
      return 3;
    if (type == "VEC4")
      return 4;
    return 0;
  }

  static int componentBytes(int componentType)
  {
    switch (componentType) {
      case 5126:
      case 5125:
        return 4;
      case 5123:
        return 2;
      default:
        return 0;
    }
  }

  std::vector<double> values(int accessor) const
  {
    const Json& a = json["accessors"][accessor];
    const int n = components(a["type"].get<std::string>());
    const int type = a["componentType"].get<int>();
    const int size = componentBytes(type);
    const size_t count = a["count"].get<size_t>();
    size_t pos = accessorOffset(accessor);
    std::vector<double> result;
    for (size_t i = 0; i < count * n; ++i, pos += size) {
      if (type == 5126)
        result.push_back(readF32(bin, pos));
      else if (type == 5125)
        result.push_back(readU32(bin, pos));
      else
        result.push_back(readU16(bin, pos));
    }
    return result;
  }
};

::testing::AssertionResult parseGlb(const std::string& data, Glb& glb)
{
  if (data.size() < 20)
    return ::testing::AssertionFailure() << "too short";
  if (data.substr(0, 4) != "glTF")
    return ::testing::AssertionFailure() << "bad magic";
  if (readU32(data, 4) != 2)
    return ::testing::AssertionFailure() << "bad version";
  if (readU32(data, 8) != data.size())
    return ::testing::AssertionFailure()
           << "length " << readU32(data, 8) << " != " << data.size();

  size_t pos = 12;
  bool first = true;
  while (pos < data.size()) {
    if (pos + 8 > data.size())
      return ::testing::AssertionFailure() << "truncated chunk header";
    const size_t length = readU32(data, pos);
    const std::uint32_t type = readU32(data, pos + 4);
    pos += 8;
    if (length % 4 != 0)
      return ::testing::AssertionFailure() << "chunk length not aligned";
    if (pos + length > data.size())
      return ::testing::AssertionFailure() << "chunk exceeds file";
    if (first) {
      if (type != 0x4E4F534A)
        return ::testing::AssertionFailure() << "first chunk is not JSON";
      const std::string text = data.substr(pos, length);
      // Any padding is spaces, so the whole chunk must parse as is.
      glb.json = Json::parse(text, nullptr, false);
      if (glb.json.is_discarded())
        return ::testing::AssertionFailure() << "JSON does not parse";
      first = false;
    } else {
      if (type != 0x004E4942 || glb.hasBin)
        return ::testing::AssertionFailure() << "unexpected chunk type";
      glb.bin = data.substr(pos, length);
      glb.hasBin = true;
    }
    pos += length;
  }
  if (first)
    return ::testing::AssertionFailure() << "no JSON chunk";

  // Buffer views and accessors lie within the BIN chunk.
  if (glb.json.contains("buffers")) {
    if (!glb.hasBin ||
        glb.json["buffers"][0]["byteLength"].get<size_t>() > glb.bin.size() ||
        glb.json["buffers"][0]["byteLength"].get<size_t>() + 3 < glb.bin.size())
      return ::testing::AssertionFailure() << "buffer length mismatch";
  }
  if (glb.json.contains("bufferViews")) {
    for (const auto& view : glb.json["bufferViews"]) {
      const size_t offset = view["byteOffset"].get<size_t>();
      if (offset % 4 != 0)
        return ::testing::AssertionFailure() << "bufferView not aligned";
      if (offset + view["byteLength"].get<size_t>() > glb.bin.size())
        return ::testing::AssertionFailure() << "bufferView out of range";
    }
  }
  if (glb.json.contains("accessors")) {
    for (const auto& a : glb.json["accessors"]) {
      const Json& view = glb.json["bufferViews"][a["bufferView"].get<int>()];
      const size_t stride = Glb::components(a["type"].get<std::string>()) *
                            Glb::componentBytes(a["componentType"].get<int>());
      if (stride == 0 || a.value("byteOffset", 0) % 4 != 0 ||
          a.value("byteOffset", 0) + a["count"].get<size_t>() * stride >
            view["byteLength"].get<size_t>())
        return ::testing::AssertionFailure() << "accessor out of range";
    }
  }
  return ::testing::AssertionSuccess();
}

Glb exportAndParse(GltfVisitor& visitor)
{
  std::ostringstream out;
  EXPECT_TRUE(visitor.write(out)) << visitor.error();
  Glb glb;
  EXPECT_TRUE(parseGlb(out.str(), glb));
  return glb;
}

// The index of the primitive of the mesh node with the given name.
const Json* findPrimitive(const Glb& glb, const std::string& name)
{
  for (const auto& mesh : glb.json["meshes"])
    if (mesh["name"] == name)
      return &mesh["primitives"][0];
  return nullptr;
}

MeshGeometry makeQuad(unsigned char alpha)
{
  Array<Vector3f> vertices, normals;
  Array<Vector4ub> colors;
  vertices.push_back(Vector3f(-1, 0, 0));
  vertices.push_back(Vector3f(5, 0, 0));
  vertices.push_back(Vector3f(5, 3, 0));
  vertices.push_back(Vector3f(-1, 3, 0));
  for (int i = 0; i < 4; ++i) {
    normals.push_back(Vector3f(0, 0, 2)); // not unit length on purpose
    colors.push_back(Vector4ub(10, 200, 30, alpha));
  }
  MeshGeometry mesh;
  mesh.addVertices(vertices, normals, colors);
  mesh.addTriangle(0, 1, 2);
  mesh.addTriangle(0, 2, 3);
  return mesh;
}

void buildScene(SphereGeometry& spheres, CylinderGeometry& cylinders,
                BezierGeometry& curve)
{
  spheres.addSphere(Vector3f(0, 0, 0), Vector3ub(255, 0, 0), 1.0f);
  spheres.addSphere(Vector3f(3, 1, -2), Vector3ub(0, 255, 0), 1.5f);
  cylinders.addCylinder(Vector3f(0, 0, 0), Vector3f(3, 1, -2), 0.2f,
                        Vector3ub(255, 0, 0), Vector3ub(0, 255, 0));
  for (size_t i = 0; i < 6; ++i)
    curve.addPoint(Vector3f(static_cast<float>(i), std::sin(i * 0.7f), 4.0f),
                   Vector3ub(100, 100, 255), 0.1f, 0, i);
}

} // namespace

TEST(GltfVisitorTest, containerAndAccessors)
{
  SphereGeometry spheres;
  CylinderGeometry cylinders;
  BezierGeometry curve;
  buildScene(spheres, cylinders, curve);
  MeshGeometry quad = makeQuad(255);

  GltfVisitor visitor;
  visitor.setSphereSubdivisions(2);
  visitor.begin();
  spheres.accept(visitor);
  cylinders.accept(visitor);
  quad.accept(visitor);
  curve.accept(visitor);
  ASSERT_GE(visitor.meshes().size(), static_cast<size_t>(3));

  Glb glb = exportAndParse(visitor);
  ASSERT_TRUE(glb.hasBin);
  EXPECT_EQ(glb.json["asset"]["version"], "2.0");
  EXPECT_EQ(
    glb.json["asset"]["generator"].get<std::string>().rfind("Avogadro", 0),
    static_cast<size_t>(0));

  // One node, mesh and primitive per drawable, in visiting order.
  ASSERT_EQ(glb.json["meshes"].size(), visitor.meshes().size());
  ASSERT_EQ(glb.json["nodes"].size(), visitor.meshes().size());
  for (size_t m = 0; m < visitor.meshes().size(); ++m) {
    const auto& source = visitor.meshes()[m];
    EXPECT_EQ(glb.json["nodes"][m]["name"], source.name);
    const Json& primitive = glb.json["meshes"][m]["primitives"][0];
    const int positionAccessor = primitive["attributes"]["POSITION"];
    const Json& pa = glb.json["accessors"][positionAccessor];
    ASSERT_EQ(pa["count"].get<size_t>(), source.positions.size());

    // POSITION min and max are the true extents.
    const std::vector<double> p = glb.values(positionAccessor);
    for (int k = 0; k < 3; ++k) {
      double lo = 1e30, hi = -1e30;
      for (size_t i = 0; i < source.positions.size(); ++i) {
        lo = std::min(lo, p[3 * i + k]);
        hi = std::max(hi, p[3 * i + k]);
      }
      EXPECT_EQ(pa["min"][k].get<double>(), lo);
      EXPECT_EQ(pa["max"][k].get<double>(), hi);
      EXPECT_NEAR(
        lo,
        [&] {
          double v = 1e30;
          for (const auto& q : source.positions)
            v = std::min(v, static_cast<double>(q[k]));
          return v;
        }(),
        1e-6);
    }

    // Normals are unit length.
    const std::vector<double> n =
      glb.values(primitive["attributes"]["NORMAL"].get<int>());
    ASSERT_EQ(n.size(), p.size());
    for (size_t i = 0; i < n.size(); i += 3)
      EXPECT_NEAR(
        std::sqrt(n[i] * n[i] + n[i + 1] * n[i + 1] + n[i + 2] * n[i + 2]), 1.0,
        1e-5);

    // Indices are in range; small meshes use 16-bit indices.
    const Json& ia = glb.json["accessors"][primitive["indices"].get<int>()];
    EXPECT_EQ(ia["componentType"].get<int>(), 5123);
    EXPECT_EQ(ia["count"].get<size_t>(), source.indices.size());
    for (double index : glb.values(primitive["indices"].get<int>()))
      EXPECT_LT(index, static_cast<double>(source.positions.size()));

    const Json& ca =
      glb.json["accessors"][primitive["attributes"]["COLOR_0"].get<int>()];
    EXPECT_EQ(ca["componentType"].get<int>(), 5123);
    EXPECT_TRUE(ca["normalized"].get<bool>());
    EXPECT_EQ(ca["type"], "VEC4");
  }

  EXPECT_NE(findPrimitive(glb, "spheres"), nullptr);
  EXPECT_NE(findPrimitive(glb, "cylinders"), nullptr);
  EXPECT_NE(findPrimitive(glb, "mesh"), nullptr);
}

TEST(GltfVisitorTest, normalsAreRenormalised)
{
  MeshGeometry quad = makeQuad(255);
  GltfVisitor visitor;
  visitor.begin();
  quad.accept(visitor);
  Glb glb = exportAndParse(visitor);
  const Json* primitive = findPrimitive(glb, "mesh");
  ASSERT_NE(primitive, nullptr);
  const std::vector<double> n =
    glb.values((*primitive)["attributes"]["NORMAL"].get<int>());
  ASSERT_EQ(n.size(), static_cast<size_t>(12));
  EXPECT_NEAR(n[2], 1.0, 1e-6);
}

TEST(GltfVisitorTest, colorsAreLinear)
{
  SphereGeometry spheres;
  spheres.addSphere(Vector3f(0, 0, 0), Vector3ub(128, 255, 0), 1.0f);
  GltfVisitor visitor;
  visitor.setSphereSubdivisions(1);
  visitor.begin();
  spheres.accept(visitor);
  Glb glb = exportAndParse(visitor);
  const Json* primitive = findPrimitive(glb, "spheres");
  ASSERT_NE(primitive, nullptr);
  const std::vector<double> c =
    glb.values((*primitive)["attributes"]["COLOR_0"].get<int>());
  ASSERT_GE(c.size(), static_cast<size_t>(4));
  EXPECT_NEAR(c[0] / 65535.0, 0.2158605, 1e-4); // sRGB 128
  EXPECT_NEAR(c[1] / 65535.0, 1.0, 1e-6);
  EXPECT_NEAR(c[2] / 65535.0, 0.0, 1e-6);
  EXPECT_NEAR(c[3] / 65535.0, 1.0, 1e-6); // alpha is not gamma encoded
}

TEST(GltfVisitorTest, translucentGetsBlendMaterial)
{
  SphereGeometry spheres;
  spheres.addSphere(Vector3f(0, 0, 0), Vector3ub(255, 0, 0), 1.0f);
  MeshGeometry glass = makeQuad(128);
  GltfVisitor visitor;
  visitor.setSphereSubdivisions(1);
  visitor.begin();
  spheres.accept(visitor);
  glass.accept(visitor);
  Glb glb = exportAndParse(visitor);

  const Json* sphere = findPrimitive(glb, "spheres");
  const Json* mesh = findPrimitive(glb, "mesh");
  ASSERT_NE(sphere, nullptr);
  ASSERT_NE(mesh, nullptr);
  const Json& sphereMaterial =
    glb.json["materials"][(*sphere)["material"].get<int>()];
  const Json& meshMaterial =
    glb.json["materials"][(*mesh)["material"].get<int>()];
  EXPECT_EQ(sphereMaterial["alphaMode"], "OPAQUE");
  EXPECT_FALSE(sphereMaterial["doubleSided"].get<bool>());
  EXPECT_EQ(meshMaterial["alphaMode"], "BLEND");
  EXPECT_TRUE(meshMaterial["doubleSided"].get<bool>());

  const std::vector<double> c =
    glb.values((*mesh)["attributes"]["COLOR_0"].get<int>());
  EXPECT_NEAR(c[3] / 65535.0, 128.0 / 255.0, 1e-4);
}

TEST(GltfVisitorTest, wideIndicesForLargeMeshes)
{
  const unsigned int side = 260; // 67600 vertices
  Array<Vector3f> vertices, normals;
  for (unsigned int j = 0; j < side; ++j)
    for (unsigned int i = 0; i < side; ++i) {
      vertices.push_back(
        Vector3f(static_cast<float>(i), static_cast<float>(j), 0));
      normals.push_back(Vector3f(0, 0, 1));
    }
  MeshGeometry mesh;
  mesh.addVertices(vertices, normals);
  for (unsigned int j = 0; j + 1 < side; ++j)
    for (unsigned int i = 0; i + 1 < side; ++i) {
      mesh.addTriangle(j * side + i, j * side + i + 1, (j + 1) * side + i);
    }
  GltfVisitor visitor;
  visitor.begin();
  mesh.accept(visitor);
  Glb glb = exportAndParse(visitor);
  const Json* primitive = findPrimitive(glb, "mesh");
  ASSERT_NE(primitive, nullptr);
  const int indices = (*primitive)["indices"].get<int>();
  EXPECT_EQ(glb.json["accessors"][indices]["componentType"].get<int>(), 5125);
  double largest = 0;
  for (double v : glb.values(indices))
    largest = std::max(largest, v);
  EXPECT_LT(largest, static_cast<double>(side * side));
  EXPECT_GT(largest, 65535.0);
}

TEST(GltfVisitorTest, emptySceneIsValid)
{
  GltfVisitor visitor;
  visitor.begin();
  Glb glb = exportAndParse(visitor);
  EXPECT_FALSE(glb.hasBin);
  EXPECT_FALSE(glb.json.contains("meshes"));
  EXPECT_EQ(glb.json["asset"]["version"], "2.0");
}

TEST(GltfVisitorTest, scaleAndOffsetAreAppliedAndRecorded)
{
  MeshGeometry quad = makeQuad(255); // x in [-1, 5], y in [0, 3]
  GltfVisitor visitor;
  visitor.setOffset(Vector3f(2, 1, 0));
  visitor.setScale(0.1f);
  visitor.begin();
  quad.accept(visitor);
  Glb glb = exportAndParse(visitor);

  const Json& extras = glb.json["asset"]["extras"];
  EXPECT_EQ(extras["units"], "angstrom");
  EXPECT_NEAR(extras["scale"].get<double>(), 0.1, 1e-7);
  EXPECT_NEAR(extras["offset"][0].get<double>(), 2.0, 1e-7);
  EXPECT_NEAR(extras["offset"][1].get<double>(), 1.0, 1e-7);
  EXPECT_NEAR(extras["offset"][2].get<double>(), 0.0, 1e-7);

  const Json* primitive = findPrimitive(glb, "mesh");
  ASSERT_NE(primitive, nullptr);
  const Json& pa =
    glb.json["accessors"][(*primitive)["attributes"]["POSITION"].get<int>()];
  EXPECT_NEAR(pa["min"][0].get<double>(), -0.3, 1e-6);
  EXPECT_NEAR(pa["max"][0].get<double>(), 0.3, 1e-6);
  EXPECT_NEAR(pa["min"][1].get<double>(), -0.1, 1e-6);
  EXPECT_NEAR(pa["max"][1].get<double>(), 0.2, 1e-6);

  // Invalid scales are ignored.
  visitor.setScale(-1.0f);
  EXPECT_FLOAT_EQ(visitor.scale(), 0.1f);
}

TEST(GltfVisitorTest, perspectiveCameraRoundTrips)
{
  Camera camera;
  camera.calculatePerspective(40.0f, 1.5f, 0.5f, 100.0f);
  camera.lookAt(Vector3f(1, 2, 10), Vector3f(0, 0, 0), Vector3f(0, 1, 0));

  MeshGeometry quad = makeQuad(255);
  GltfVisitor visitor;
  visitor.setCamera(camera);
  visitor.begin();
  quad.accept(visitor);
  Glb glb = exportAndParse(visitor);

  ASSERT_EQ(glb.json["cameras"].size(), static_cast<size_t>(1));
  const Json& cam = glb.json["cameras"][0];
  EXPECT_EQ(cam["type"], "perspective");
  const Json& p = cam["perspective"];
  EXPECT_NEAR(p["yfov"].get<double>(), 40.0 * M_PI / 180.0, 1e-5);
  EXPECT_NEAR(p["aspectRatio"].get<double>(), 1.5, 1e-5);
  EXPECT_NEAR(p["znear"].get<double>(), 0.5, 1e-4);
  EXPECT_NEAR(p["zfar"].get<double>(), 100.0, 1e-2);

  const Json& node = glb.json["nodes"].back();
  EXPECT_EQ(node["camera"], 0);
  ASSERT_EQ(node["matrix"].size(), static_cast<size_t>(16));
  Matrix4f world;
  for (int c = 0; c < 4; ++c)
    for (int r = 0; r < 4; ++r)
      world(r, c) = node["matrix"][c * 4 + r].get<float>();
  const Matrix4f expected = camera.modelView().matrix().inverse();
  EXPECT_TRUE(world.isApprox(expected, 1e-5f)) << world << "\n" << expected;
}

TEST(GltfVisitorTest, orthographicCameraRoundTrips)
{
  Camera camera;
  camera.calculateOrthographic(-2.0f, 2.0f, -1.5f, 1.5f, 0.1f, 50.0f);
  camera.setProjectionType(Avogadro::Rendering::Orthographic);
  camera.lookAt(Vector3f(0, 0, 8), Vector3f(1, 1, 0), Vector3f(0, 1, 0));

  MeshGeometry quad = makeQuad(255);
  GltfVisitor visitor;
  visitor.setOffset(Vector3f(1, 1, 0));
  visitor.setScale(0.1f);
  visitor.setCamera(camera);
  visitor.begin();
  quad.accept(visitor);
  Glb glb = exportAndParse(visitor);

  const Json& cam = glb.json["cameras"][0];
  EXPECT_EQ(cam["type"], "orthographic");
  const Json& o = cam["orthographic"];
  EXPECT_NEAR(o["xmag"].get<double>(), 0.2, 1e-6);
  EXPECT_NEAR(o["ymag"].get<double>(), 0.15, 1e-6);
  EXPECT_NEAR(o["znear"].get<double>(), 0.01, 1e-6);
  EXPECT_NEAR(o["zfar"].get<double>(), 5.0, 1e-4);

  // Position follows the geometry transform: the eye is at (0, 0, 8).
  const Json& matrix = glb.json["nodes"].back()["matrix"];
  EXPECT_NEAR(matrix[12].get<double>(), (0 - 1) * 0.1, 1e-6);
  EXPECT_NEAR(matrix[13].get<double>(), (0 - 1) * 0.1, 1e-6);
  EXPECT_NEAR(matrix[14].get<double>(), 0.8, 1e-6);
}

TEST(GltfVisitorTest, noCameraByDefault)
{
  MeshGeometry quad = makeQuad(255);
  GltfVisitor visitor;
  visitor.begin();
  quad.accept(visitor);
  Glb glb = exportAndParse(visitor);
  EXPECT_FALSE(glb.json.contains("cameras"));
}
