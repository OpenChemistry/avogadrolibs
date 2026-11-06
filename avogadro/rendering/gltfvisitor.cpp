/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltfvisitor.h"

#include <avogadro/core/version.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <ostream>
#include <sstream>
#include <vector>

namespace Avogadro::Rendering {

namespace {

using Json = nlohmann::json;

// glTF constants.
constexpr int kFloat = 5126;
constexpr int kUnsignedShort = 5123;
constexpr int kUnsignedInt = 5125;
constexpr int kArrayBuffer = 34962;
constexpr int kElementArrayBuffer = 34963;

constexpr std::uint32_t kGlbMagic = 0x46546C67;       // "glTF"
constexpr std::uint32_t kChunkJson = 0x4E4F534A;      // "JSON"
constexpr std::uint32_t kChunkBinary = 0x004E4942;    // "BIN\0"
constexpr std::uint64_t kMaxGlbBytes = 0xFFFFFFFFull; // uint32 length field

constexpr std::uint64_t align4(std::uint64_t n)
{
  return (n + 3) & ~static_cast<std::uint64_t>(3);
}

// Buffers output and flushes it to the stream in large pieces. Everything is
// written byte by byte, least significant byte first, so the output does not
// depend on the host byte order.
class ChunkWriter
{
public:
  explicit ChunkWriter(std::ostream& out) : m_out(out)
  {
    m_buffer.reserve(kChunk + 64);
  }
  ~ChunkWriter() { flush(); }

  void byte(unsigned char b) { m_buffer.push_back(static_cast<char>(b)); }

  void u16(std::uint16_t value)
  {
    byte(static_cast<unsigned char>(value & 0xff));
    byte(static_cast<unsigned char>((value >> 8) & 0xff));
  }

  void u32(std::uint32_t value)
  {
    for (int i = 0; i < 4; ++i)
      byte(static_cast<unsigned char>((value >> (8 * i)) & 0xff));
  }

  void f32(float value)
  {
    static_assert(sizeof(float) == 4, "glTF needs 32-bit floats");
    std::uint32_t bits;
    std::memcpy(&bits, &value, 4);
    u32(bits); // IEEE-754 bits, written least significant byte first
  }

  void text(const std::string& s)
  {
    m_buffer.insert(m_buffer.end(), s.begin(), s.end());
  }

  void pad(std::uint64_t count, unsigned char value)
  {
    for (std::uint64_t i = 0; i < count; ++i)
      byte(value);
  }

  void checkFlush()
  {
    if (m_buffer.size() >= kChunk)
      flush();
  }

  void flush()
  {
    if (!m_buffer.empty()) {
      m_out.write(m_buffer.data(),
                  static_cast<std::streamsize>(m_buffer.size()));
      m_buffer.clear();
    }
  }

private:
  static constexpr size_t kChunk = 1 << 20;
  std::ostream& m_out;
  std::vector<char> m_buffer;
};

// sRGB byte -> linear value in [0, 1] (IEC 61966-2-1).
float srgbToLinear(int value)
{
  const double c = value / 255.0;
  const double linear =
    c <= 0.04045 ? c / 12.92 : std::pow((c + 0.055) / 1.055, 2.4);
  return static_cast<float>(linear);
}

const std::array<std::uint16_t, 256>& linearTable()
{
  static const std::array<std::uint16_t, 256> table = [] {
    std::array<std::uint16_t, 256> t{};
    for (int i = 0; i < 256; ++i)
      t[i] = static_cast<std::uint16_t>(
        std::lround(static_cast<double>(srgbToLinear(i)) * 65535.0));
    return t;
  }();
  return table;
}

// The alpha channel is already linear.
std::uint16_t alphaToU16(int value)
{
  return static_cast<std::uint16_t>(std::lround(value / 255.0 * 65535.0));
}

// What is written for one mesh, and where it goes in the BIN chunk.
struct MeshPlan
{
  const TessellatedMesh* mesh = nullptr;
  size_t triangles = 0; // triangles with valid indices
  bool blend = false;
  bool doubleSided = true;
  bool wideIndices = false; // UNSIGNED_INT rather than UNSIGNED_SHORT
  Vector3f minimum = Vector3f::Zero();
  Vector3f maximum = Vector3f::Zero();
  std::uint64_t positionOffset = 0;
  std::uint64_t normalOffset = 0;
  std::uint64_t colorOffset = 0;
  std::uint64_t indexOffset = 0;
  std::uint64_t positionBytes = 0;
  std::uint64_t colorBytes = 0;
  std::uint64_t indexBytes = 0;
};

Vector3f finiteOrZero(const Vector3f& v)
{
  Vector3f result = v;
  for (int k = 0; k < 3; ++k)
    if (!std::isfinite(result[k]))
      result[k] = 0.0f;
  return result;
}

Vector3f unitNormal(const Vector3f& n)
{
  const Vector3f clean = finiteOrZero(n);
  const float length = clean.norm();
  if (length > 1.0e-12f)
    return clean / length;
  return Vector3f(0.0f, 0.0f, 1.0f);
}

bool validTriangle(const TessellatedMesh& mesh, size_t i)
{
  const size_t count = mesh.positions.size();
  return mesh.indices[i] < count && mesh.indices[i + 1] < count &&
         mesh.indices[i + 2] < count;
}

Json vec3Json(const Vector3f& v)
{
  return Json::array({ v[0], v[1], v[2] });
}

} // namespace

GltfVisitor::GltfVisitor() = default;

GltfVisitor::~GltfVisitor() = default;

void GltfVisitor::setOffset(const Vector3f& offset)
{
  m_offset = finiteOrZero(offset);
}

void GltfVisitor::setScale(float scale)
{
  if (std::isfinite(scale) && scale > 0.0f)
    m_scale = scale;
}

void GltfVisitor::setCamera(const Camera& camera)
{
  m_camera = camera;
  m_hasCamera = true;
}

bool GltfVisitor::write(std::ostream& out) const
{
  m_error.clear();
  const Vector3f offset = m_offset;
  const float scale = m_scale;
  auto transformed = [&](const Vector3f& p) {
    return finiteOrZero((finiteOrZero(p) - offset) * scale);
  };

  // Pass 1: decide what is written, and lay out the BIN chunk.
  std::vector<MeshPlan> plans;
  std::uint64_t binBytes = 0;
  for (const auto& mesh : meshes()) {
    if (mesh.positions.empty() ||
        mesh.normals.size() != mesh.positions.size() ||
        mesh.colors.size() != mesh.positions.size())
      continue;
    MeshPlan plan;
    plan.mesh = &mesh;
    for (size_t i = 0; i + 2 < mesh.indices.size(); i += 3)
      if (validTriangle(mesh, i))
        ++plan.triangles;
    if (plan.triangles == 0)
      continue;

    plan.blend = false;
    for (const auto& c : mesh.colors)
      if (c[3] < 255) {
        plan.blend = true;
        break;
      }
    // Spheres are closed; everything else (tubes, surfaces, ribbons) may be
    // seen from inside or from behind.
    plan.doubleSided = mesh.name != "spheres";
    plan.wideIndices = mesh.positions.size() >= 65536;

    plan.minimum = transformed(mesh.positions[0]);
    plan.maximum = plan.minimum;
    for (const auto& p : mesh.positions) {
      const Vector3f q = transformed(p);
      plan.minimum = plan.minimum.cwiseMin(q);
      plan.maximum = plan.maximum.cwiseMax(q);
    }

    const std::uint64_t vertices = mesh.positions.size();
    plan.positionBytes = vertices * 12;
    plan.colorBytes = vertices * 8;
    plan.indexBytes = static_cast<std::uint64_t>(plan.triangles) * 3 *
                      (plan.wideIndices ? 4 : 2);

    plan.positionOffset = binBytes;
    binBytes += align4(plan.positionBytes);
    plan.normalOffset = binBytes;
    binBytes += align4(plan.positionBytes);
    plan.colorOffset = binBytes;
    binBytes += align4(plan.colorBytes);
    plan.indexOffset = binBytes;
    binBytes += align4(plan.indexBytes);
    if (binBytes > kMaxGlbBytes) {
      m_error = "The scene is too large for a glTF binary (.glb) file, "
                "which is limited to 4 GB.";
      return false;
    }
    plans.push_back(plan);
  }

  // The JSON chunk.
  Json root;
  root["asset"] = {
    { "version", "2.0" },
    { "generator", std::string("Avogadro ") + Avogadro::version() },
    { "extras",
      { { "units", "angstrom" },
        { "scale", scale },
        { "offset", vec3Json(offset) },
        { "transform", "output = (angstrom - offset) * scale" } } }
  };

  Json nodes = Json::array();
  Json meshesJson = Json::array();
  Json accessors = Json::array();
  Json bufferViews = Json::array();
  // Materials, created on first use: index by [blend][doubleSided].
  int materialIndex[2][2] = { { -1, -1 }, { -1, -1 } };
  Json materials = Json::array();

  for (size_t m = 0; m < plans.size(); ++m) {
    const MeshPlan& plan = plans[m];
    const TessellatedMesh& mesh = *plan.mesh;
    const size_t vertices = mesh.positions.size();

    int& material = materialIndex[plan.blend ? 1 : 0][plan.doubleSided ? 1 : 0];
    if (material < 0) {
      material = static_cast<int>(materials.size());
      std::string name = plan.blend ? "translucent" : "opaque";
      if (plan.doubleSided)
        name += "-doublesided";
      materials.push_back(
        { { "name", name },
          { "alphaMode", plan.blend ? "BLEND" : "OPAQUE" },
          { "doubleSided", plan.doubleSided },
          { "pbrMetallicRoughness",
            { { "baseColorFactor", Json::array({ 1.0, 1.0, 1.0, 1.0 }) },
              { "metallicFactor", 0.0 },
              { "roughnessFactor", 0.5 } } } });
    }

    const int view = static_cast<int>(bufferViews.size());
    auto addView = [&](std::uint64_t byteOffset, std::uint64_t byteLength,
                       int target) {
      bufferViews.push_back({ { "buffer", 0 },
                              { "byteOffset", byteOffset },
                              { "byteLength", byteLength },
                              { "target", target } });
    };
    addView(plan.positionOffset, plan.positionBytes, kArrayBuffer);
    addView(plan.normalOffset, plan.positionBytes, kArrayBuffer);
    addView(plan.colorOffset, plan.colorBytes, kArrayBuffer);
    addView(plan.indexOffset, plan.indexBytes, kElementArrayBuffer);

    const int accessor = static_cast<int>(accessors.size());
    accessors.push_back({ { "bufferView", view },
                          { "componentType", kFloat },
                          { "count", vertices },
                          { "type", "VEC3" },
                          { "min", vec3Json(plan.minimum) },
                          { "max", vec3Json(plan.maximum) } });
    accessors.push_back({ { "bufferView", view + 1 },
                          { "componentType", kFloat },
                          { "count", vertices },
                          { "type", "VEC3" } });
    accessors.push_back({ { "bufferView", view + 2 },
                          { "componentType", kUnsignedShort },
                          { "normalized", true },
                          { "count", vertices },
                          { "type", "VEC4" } });
    accessors.push_back(
      { { "bufferView", view + 3 },
        { "componentType", plan.wideIndices ? kUnsignedInt : kUnsignedShort },
        { "count", plan.triangles * 3 },
        { "type", "SCALAR" } });

    Json primitive = { { "attributes",
                         { { "POSITION", accessor },
                           { "NORMAL", accessor + 1 },
                           { "COLOR_0", accessor + 2 } } },
                       { "indices", accessor + 3 },
                       { "material", material },
                       { "mode", 4 } };
    meshesJson.push_back(
      { { "name", mesh.name }, { "primitives", Json::array({ primitive }) } });
    nodes.push_back({ { "name", mesh.name },
                      { "mesh", static_cast<int>(meshesJson.size()) - 1 } });
  }

  // The camera node.
  Json camerasJson = Json::array();
  if (m_hasCamera) {
    const Eigen::Matrix4f P = m_camera.projection().matrix();
    const Eigen::Matrix4f M = m_camera.modelView().matrix();
    const Eigen::Matrix3d A = M.topLeftCorner<3, 3>().cast<double>();
    const Eigen::Vector3d t = M.topRightCorner<3, 1>().cast<double>();
    // Perspective zooming scales the model view uniformly; undo that.
    const double s = A.col(0).norm();
    const double p00 = P(0, 0), p11 = P(1, 1), p22 = P(2, 2), p23 = P(2, 3);
    const bool perspective = std::abs(P(3, 3)) < 0.5f;
    if (std::isfinite(s) && s > 0.0 && std::isfinite(p00) && p00 != 0.0 &&
        std::isfinite(p11) && p11 != 0.0 && std::isfinite(p22) &&
        std::isfinite(p23) && M.allFinite()) {
      // Camera-to-world rotation (R^T) and position, in output units.
      const Eigen::Matrix3d rotation = (A / s).transpose();
      const Eigen::Vector3d eye = -(rotation * t) / s;
      Eigen::Vector3d position =
        (eye - offset.cast<double>()) * static_cast<double>(scale);
      const double k = static_cast<double>(scale) / s; // eye units -> output

      Json camera;
      bool ok = false;
      if (perspective) {
        double n = p23 / (p22 - 1.0);
        double f = p23 / (p22 + 1.0);
        if (std::isfinite(f) && f > 0.0 && !(n > 0.0))
          n = f * 1.0e-3;
        if (std::isfinite(n) && n > 0.0) {
          Json persp = { { "yfov", 2.0 * std::atan(1.0 / std::abs(p11)) },
                         { "aspectRatio", std::abs(p11 / p00) },
                         { "znear", n * k } };
          if (std::isfinite(f) && f > n)
            persp["zfar"] = f * k;
          camera = { { "name", "camera" },
                     { "type", "perspective" },
                     { "perspective", persp } };
          ok = true;
        }
      } else if (p22 != 0.0) {
        const double n = (p23 + 1.0) / p22;
        const double f = (p23 - 1.0) / p22;
        if (std::isfinite(n) && std::isfinite(f) && f > n) {
          // Avogadro's orthographic near plane is often behind the eye, but
          // glTF needs znear >= 0: move the camera back (along +Z, towards
          // the viewer) so that the visible volume stays the same.
          double znear = n * k;
          double zfar = f * k;
          if (n < 0.0) {
            position += rotation.col(2) * (-n * k);
            znear = 0.0;
            zfar = (f - n) * k;
          }
          camera = { { "name", "camera" },
                     { "type", "orthographic" },
                     { "orthographic",
                       { { "xmag", std::abs(k / p00) },
                         { "ymag", std::abs(k / p11) },
                         { "znear", znear },
                         { "zfar", zfar } } } };
          ok = true;
        }
      }
      if (ok) {
        // Column-major node matrix.
        Json matrix = Json::array();
        for (int col = 0; col < 3; ++col) {
          for (int row = 0; row < 3; ++row)
            matrix.push_back(rotation(row, col));
          matrix.push_back(0.0);
        }
        for (int row = 0; row < 3; ++row)
          matrix.push_back(position[row]);
        matrix.push_back(1.0);
        camerasJson.push_back(camera);
        nodes.push_back(
          { { "name", "camera" }, { "camera", 0 }, { "matrix", matrix } });
      }
    }
  }

  if (!nodes.empty()) {
    Json sceneNodes = Json::array();
    for (size_t i = 0; i < nodes.size(); ++i)
      sceneNodes.push_back(i);
    root["scene"] = 0;
    root["scenes"] =
      Json::array({ { { "name", "Avogadro" }, { "nodes", sceneNodes } } });
    root["nodes"] = nodes;
  }
  if (!meshesJson.empty()) {
    root["meshes"] = meshesJson;
    root["materials"] = materials;
    root["accessors"] = accessors;
    root["bufferViews"] = bufferViews;
    root["buffers"] = Json::array({ { { "byteLength", binBytes } } });
  }
  if (!camerasJson.empty())
    root["cameras"] = camerasJson;

  std::string json = root.dump();
  const std::uint64_t jsonBytes = align4(json.size());
  json.append(static_cast<size_t>(jsonBytes - json.size()), ' ');

  std::uint64_t total = 12 + 8 + jsonBytes;
  if (binBytes > 0)
    total += 8 + binBytes;
  if (total > kMaxGlbBytes) {
    m_error = "The scene is too large for a glTF binary (.glb) file, "
              "which is limited to 4 GB.";
    return false;
  }

  // Pass 2: write.
  ChunkWriter writer(out);
  writer.u32(kGlbMagic);
  writer.u32(2);
  writer.u32(static_cast<std::uint32_t>(total));
  writer.u32(static_cast<std::uint32_t>(jsonBytes));
  writer.u32(kChunkJson);
  writer.text(json);
  json.clear();
  json.shrink_to_fit();

  if (binBytes > 0) {
    writer.u32(static_cast<std::uint32_t>(binBytes));
    writer.u32(kChunkBinary);
    const auto& linear = linearTable();
    for (const MeshPlan& plan : plans) {
      const TessellatedMesh& mesh = *plan.mesh;
      for (const auto& p : mesh.positions) {
        const Vector3f q = transformed(p);
        for (int k = 0; k < 3; ++k)
          writer.f32(q[k]);
        writer.checkFlush();
      }
      writer.pad(align4(plan.positionBytes) - plan.positionBytes, 0);
      for (const auto& n : mesh.normals) {
        const Vector3f u = unitNormal(n);
        for (int k = 0; k < 3; ++k)
          writer.f32(u[k]);
        writer.checkFlush();
      }
      writer.pad(align4(plan.positionBytes) - plan.positionBytes, 0);
      for (const auto& c : mesh.colors) {
        writer.u16(linear[c[0]]);
        writer.u16(linear[c[1]]);
        writer.u16(linear[c[2]]);
        writer.u16(alphaToU16(c[3]));
        writer.checkFlush();
      }
      writer.pad(align4(plan.colorBytes) - plan.colorBytes, 0);
      for (size_t i = 0; i + 2 < mesh.indices.size(); i += 3) {
        if (!validTriangle(mesh, i))
          continue;
        for (size_t k = 0; k < 3; ++k) {
          if (plan.wideIndices)
            writer.u32(static_cast<std::uint32_t>(mesh.indices[i + k]));
          else
            writer.u16(static_cast<std::uint16_t>(mesh.indices[i + k]));
        }
        writer.checkFlush();
      }
      writer.pad(align4(plan.indexBytes) - plan.indexBytes, 0);
    }
  }

  writer.flush();
  out.flush();
  if (!out) {
    m_error = "Writing the glTF data to the output failed.";
    return false;
  }
  return true;
}

std::string GltfVisitor::end()
{
  std::ostringstream out;
  if (!write(out))
    return std::string();
  return out.str();
}

} // namespace Avogadro::Rendering
