/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltfvisitor.h"

#include "chunkwriter_p.h"

#include <avogadro/core/version.h>

#include <nlohmann/json.hpp>

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <utility>
#include <string>
#include <ostream>
#include <streambuf>
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

// The alpha channel is already linear: 65535 / 255 = 257.
std::uint16_t alphaToU16(int value)
{
  return static_cast<std::uint16_t>(value * 257);
}

// Pad what was written (@p bytes) up to a multiple of four.
void padToAlignment(ChunkWriter& writer, std::uint64_t bytes)
{
  writer.pad(align4(bytes) - bytes);
}

std::uint32_t packColor(const Vector4ub& c)
{
  return (static_cast<std::uint32_t>(c[0]) << 24) |
         (static_cast<std::uint32_t>(c[1]) << 16) |
         (static_cast<std::uint32_t>(c[2]) << 8) |
         static_cast<std::uint32_t>(c[3]);
}

Json vec3Json(const Vector3f& v)
{
  return Json::array({ v[0], v[1], v[2] });
}

// A std::ostream buffer that appends to a string.
class StringBuf : public std::streambuf
{
public:
  explicit StringBuf(std::string& target) : m_target(target) {}
  void reserve(std::uint64_t bytes)
  {
    m_target.reserve(static_cast<size_t>(bytes));
  }

protected:
  std::streamsize xsputn(const char* data, std::streamsize count) override
  {
    m_target.append(data, static_cast<size_t>(count));
    return count;
  }

  int_type overflow(int_type ch) override
  {
    if (!traits_type::eq_int_type(ch, traits_type::eof()))
      m_target.push_back(traits_type::to_char_type(ch));
    return traits_type::not_eof(ch);
  }

private:
  std::string& m_target;
};

// Describe @p camera as a glTF camera and the node that places it. The node
// matrix and the clipping distances are in output units; @p scale / viewScale
// converts eye space (zoomed Angstrom) to them. Returns false if the matrices
// do not describe a usable camera.
bool cameraJson(const Camera& camera, const Vector3f& offset, float scale,
                Json& cameraOut, Json& nodeOut)
{
  const double zoom = camera.viewScale();
  const Eigen::Matrix3f rotation = camera.viewRotation();
  const Vector3f eye = camera.eyePosition();
  if (!std::isfinite(zoom) || !(zoom > 0.0) || !rotation.allFinite() ||
      !eye.allFinite())
    return false;

  const double k = static_cast<double>(scale) / zoom; // eye units -> output
  Eigen::Vector3d position =
    (eye.cast<double>() - offset.cast<double>()) * static_cast<double>(scale);
  const double n = camera.nearPlane();
  const double f = camera.farPlane();

  if (camera.isOrthographic()) {
    const Vector2f half = camera.orthographicHalfExtents();
    if (!half.allFinite() || !(half.minCoeff() > 0.0f) || !std::isfinite(n) ||
        !std::isfinite(f) || !(f > n))
      return false;
    // Avogadro's orthographic near plane is often behind the eye, but glTF
    // needs znear >= 0: move the camera back (along +Z, towards the viewer)
    // so that the visible volume stays the same.
    double znear = n * k;
    double zfar = f * k;
    if (n < 0.0) {
      position += rotation.col(2).cast<double>() * (-n * k);
      znear = 0.0;
      zfar = (f - n) * k;
    }
    // glTF's orthographic volume is centred on the view axis: move the camera
    // sideways to the centre of an off-axis (asymmetric) volume.
    const Vector2f center = camera.orthographicCenter();
    if (!center.allFinite())
      return false;
    position += rotation.col(0).cast<double>() * (center[0] * k) +
                rotation.col(1).cast<double>() * (center[1] * k);
    cameraOut = { { "name", "camera" },
                  { "type", "orthographic" },
                  { "orthographic",
                    { { "xmag", half[0] * k },
                      { "ymag", half[1] * k },
                      { "znear", znear },
                      { "zfar", zfar } } } };
  } else {
    // glTF cannot express an off-axis perspective frustum: it is centred.
    const double fov = camera.verticalFieldOfView();
    const double aspect = camera.aspectRatio();
    double nearDistance = n;
    // glTF needs 0 < znear < zfar: guard against a degenerate near plane.
    if (std::isfinite(f) && f > 0.0 && !(nearDistance > 0.0))
      nearDistance = f * 1.0e-3;
    if (!(fov > 0.0) || !std::isfinite(fov) || !(aspect > 0.0) ||
        !std::isfinite(aspect) || !std::isfinite(nearDistance) ||
        !(nearDistance > 0.0))
      return false;
    Json perspective = { { "yfov", fov * M_PI / 180.0 },
                         { "aspectRatio", aspect },
                         { "znear", nearDistance * k } };
    if (std::isfinite(f) && f > nearDistance)
      perspective["zfar"] = f * k;
    cameraOut = { { "name", "camera" },
                  { "type", "perspective" },
                  { "perspective", perspective } };
  }

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
  nodeOut = { { "name", "camera" }, { "camera", 0 }, { "matrix", matrix } };
  return true;
}

constexpr const char* kTooLarge = "The scene is too large for a glTF binary "
                                  "(.glb) file, which is limited to 4 GB.";

} // namespace

GltfVisitor::GltfVisitor() = default;

GltfVisitor::~GltfVisitor() = default;

bool GltfVisitor::write(std::ostream& out) const
{
  m_error.clear();
  const Vector3f offset = this->offset();
  const float scale = this->scale(); // always > 0

  Json nodes = Json::array();
  Json meshesJson = Json::array();
  Json accessors = Json::array();
  Json bufferViews = Json::array();
  Json materials = Json::array();
  // Materials are created on first use. Flat-colour materials are keyed by
  // (rgba, doubleSided); vertex-colour materials (white base colour, COLOR_0
  // supplies the colour) by (blend, doubleSided).
  std::map<std::pair<std::uint32_t, bool>, int> flatMaterials;
  int vertexMaterials[2][2] = { { -1, -1 }, { -1, -1 } };
  auto flatMaterial = [&](const Vector4ub& rgba, bool doubleSided) {
    const auto key = std::make_pair(packColor(rgba), doubleSided);
    const auto found = flatMaterials.find(key);
    if (found != flatMaterials.end())
      return found->second;
    const int index = static_cast<int>(materials.size());
    flatMaterials[key] = index;
    const bool blend = rgba[3] < 255;
    char name[16];
    std::snprintf(name, sizeof(name), "#%02X%02X%02X", rgba[0], rgba[1],
                  rgba[2]);
    std::string label = name;
    if (blend) {
      std::snprintf(name, sizeof(name), "%02X", rgba[3]);
      label += name;
    }
    if (doubleSided)
      label += "-doublesided";
    materials.push_back(
      { { "name", label },
        { "alphaMode", blend ? "BLEND" : "OPAQUE" },
        { "doubleSided", doubleSided },
        { "pbrMetallicRoughness",
          { { "baseColorFactor",
              Json::array({ srgbToLinear(rgba[0]), srgbToLinear(rgba[1]),
                            srgbToLinear(rgba[2]), rgba[3] / 255.0 }) },
            { "metallicFactor", 0.0 },
            { "roughnessFactor", 0.5 } } } });
    return index;
  };
  auto vertexMaterial = [&](bool blend, bool doubleSided) {
    int& index = vertexMaterials[blend ? 1 : 0][doubleSided ? 1 : 0];
    if (index < 0) {
      index = static_cast<int>(materials.size());
      std::string name = blend ? "translucent" : "opaque";
      if (doubleSided)
        name += "-doublesided";
      materials.push_back(
        { { "name", name },
          { "alphaMode", blend ? "BLEND" : "OPAQUE" },
          { "doubleSided", doubleSided },
          { "pbrMetallicRoughness",
            { { "baseColorFactor", Json::array({ 1.0, 1.0, 1.0, 1.0 }) },
              { "metallicFactor", 0.0 },
              { "roughnessFactor", 0.5 } } } });
    }
    return index;
  };

  // The BIN chunk is laid out here, in one place; the data is written in the
  // same order below.
  std::uint64_t binBytes = 0;
  auto place = [&](std::uint64_t bytes) {
    const std::uint64_t at = binBytes;
    binBytes += align4(bytes);
    return at;
  };
  // A buffer view for the next @p bytes of the BIN chunk, and the accessor
  // (from @p accessor, which lacks the view) that reads it. Returns the
  // accessor index, which is also the view's.
  auto addAccessor = [&](std::uint64_t bytes, int target, Json accessor) {
    const int index = static_cast<int>(accessors.size());
    bufferViews.push_back({ { "buffer", 0 },
                            { "byteOffset", place(bytes) },
                            { "byteLength", bytes },
                            { "target", target } });
    accessor["bufferView"] = index;
    accessors.push_back(std::move(accessor));
    return index;
  };

  // The triangles of one mesh that share a primitive: those of one flat
  // colour, or (mixed) those whose vertices differ in colour.
  struct Group
  {
    bool mixed = false;
    Vector4ub color = Vector4ub::Zero();
    std::vector<unsigned int> indices;
  };
  struct Written
  {
    const TessellatedMesh* mesh;
    bool wideIndices; // UNSIGNED_INT rather than UNSIGNED_SHORT
    bool hasColors;   // some primitive uses COLOR_0
    std::vector<Group> groups;
  };
  std::vector<Written> written;

  for (const auto& mesh : meshes()) {
    const size_t vertices = mesh.positions.size();

    // The extents. The scale is positive, so the extents of the output
    // positions are those of the input, transformed.
    Vector3f lo = mesh.positions[0], hi = lo;
    for (size_t i = 0; i < vertices; ++i) {
      lo = lo.cwiseMin(mesh.positions[i]);
      hi = hi.cwiseMax(mesh.positions[i]);
    }
    lo = (lo - offset) * scale;
    hi = (hi - offset) * scale;
    // Huge coordinates can overflow single precision once transformed. Every
    // vertex lies between the extremes, so checking them is enough.
    if (!lo.allFinite() || !hi.allFinite()) {
      m_error = "The scene has coordinates too large to export as glTF "
                "(they overflow when offset and scaled).";
      return false;
    }

    // Sort the triangles into groups, in order of first appearance.
    Written item{ &mesh, vertices >= 65536, false, {} };
    std::map<std::uint32_t, size_t> flatGroups;
    int mixedGroup = -1;
    bool mixedBlend = false;
    for (size_t i = 0; i + 2 < mesh.indices.size(); i += 3) {
      const unsigned int a = mesh.indices[i], b = mesh.indices[i + 1],
                         c = mesh.indices[i + 2];
      const Vector4ub& ca = mesh.colors[a];
      Group* group = nullptr;
      if (ca == mesh.colors[b] && ca == mesh.colors[c]) {
        auto found = flatGroups.find(packColor(ca));
        if (found == flatGroups.end()) {
          found = flatGroups.emplace(packColor(ca), item.groups.size()).first;
          item.groups.emplace_back();
          item.groups.back().color = ca;
        }
        group = &item.groups[found->second];
      } else {
        if (mixedGroup < 0) {
          mixedGroup = static_cast<int>(item.groups.size());
          item.groups.emplace_back();
          item.groups.back().mixed = true;
        }
        group = &item.groups[mixedGroup];
        mixedBlend = mixedBlend || ca[3] < 255 || mesh.colors[b][3] < 255 ||
                     mesh.colors[c][3] < 255;
      }
      group->indices.push_back(a);
      group->indices.push_back(b);
      group->indices.push_back(c);
    }
    item.hasColors = mixedGroup >= 0;

    // Tubes, surfaces and ribbons may be seen from inside or from behind.
    const bool doubleSided = !mesh.closed;

    // The vertex data is shared by all primitives of the mesh.
    const int position = addAccessor(vertices * 12, kArrayBuffer,
                                     { { "componentType", kFloat },
                                       { "count", vertices },
                                       { "type", "VEC3" },
                                       { "min", vec3Json(lo) },
                                       { "max", vec3Json(hi) } });
    const int normal = addAccessor(vertices * 12, kArrayBuffer,
                                   { { "componentType", kFloat },
                                     { "count", vertices },
                                     { "type", "VEC3" } });
    int color = -1;
    if (item.hasColors)
      color = addAccessor(vertices * 8, kArrayBuffer,
                          { { "componentType", kUnsignedShort },
                            { "normalized", true },
                            { "count", vertices },
                            { "type", "VEC4" } });

    Json primitives = Json::array();
    for (const Group& group : item.groups) {
      const int indices = addAccessor(
        static_cast<std::uint64_t>(group.indices.size()) *
          (item.wideIndices ? 4 : 2),
        kElementArrayBuffer,
        { { "componentType", item.wideIndices ? kUnsignedInt : kUnsignedShort },
          { "count", group.indices.size() },
          { "type", "SCALAR" } });
      Json attributes = { { "POSITION", position }, { "NORMAL", normal } };
      int material;
      if (group.mixed) {
        attributes["COLOR_0"] = color;
        material = vertexMaterial(mixedBlend, doubleSided);
      } else {
        material = flatMaterial(group.color, doubleSided);
      }
      primitives.push_back({ { "attributes", std::move(attributes) },
                             { "indices", indices },
                             { "material", material },
                             { "mode", 4 } });
    }
    if (binBytes > kMaxGlbBytes) {
      m_error = kTooLarge;
      return false;
    }
    written.push_back(std::move(item));

    meshesJson.push_back(
      { { "name", mesh.name }, { "primitives", std::move(primitives) } });
    nodes.push_back({ { "name", mesh.name },
                      { "mesh", static_cast<int>(meshesJson.size()) - 1 } });
  }

  Json camerasJson = Json::array();
  if (m_camera) {
    Json camera, node;
    if (cameraJson(*m_camera, offset, scale, camera, node)) {
      camerasJson.push_back(std::move(camera));
      nodes.push_back(std::move(node));
    }
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
  if (!nodes.empty()) {
    Json sceneNodes = Json::array();
    for (size_t i = 0; i < nodes.size(); ++i)
      sceneNodes.push_back(i);
    root["scene"] = 0;
    root["scenes"] = Json::array(
      { { { "name", "Avogadro" }, { "nodes", std::move(sceneNodes) } } });
    root["nodes"] = std::move(nodes);
  }
  if (!meshesJson.empty()) {
    root["meshes"] = std::move(meshesJson);
    root["materials"] = std::move(materials);
    root["accessors"] = std::move(accessors);
    root["bufferViews"] = std::move(bufferViews);
    root["buffers"] = Json::array({ { { "byteLength", binBytes } } });
  }
  if (!camerasJson.empty())
    root["cameras"] = std::move(camerasJson);

  std::string json = root.dump();
  const std::uint64_t jsonBytes = align4(json.size());
  json.append(static_cast<size_t>(jsonBytes - json.size()), ' ');

  std::uint64_t total = 12 + 8 + jsonBytes;
  if (binBytes > 0)
    total += 8 + binBytes;
  if (total > kMaxGlbBytes) {
    m_error = kTooLarge;
    return false;
  }
  if (auto* target = dynamic_cast<StringBuf*>(out.rdbuf()))
    target->reserve(total);

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
    for (const Written& item : written) {
      const TessellatedMesh& mesh = *item.mesh;
      const std::uint64_t vertices = mesh.positions.size();
      for (const auto& p : mesh.positions) {
        const Vector3f q = (p - offset) * scale;
        writer.floats(q.data(), 3);
      }
      padToAlignment(writer, vertices * 12);
      for (const auto& n : mesh.normals)
        writer.floats(n.data(), 3);
      padToAlignment(writer, vertices * 12);
      if (item.hasColors) {
        for (const auto& c : mesh.colors) {
          writer.u16(linear[c[0]]);
          writer.u16(linear[c[1]]);
          writer.u16(linear[c[2]]);
          writer.u16(alphaToU16(c[3]));
        }
        padToAlignment(writer, vertices * 8);
      }
      for (const Group& group : item.groups) {
        for (unsigned int index : group.indices) {
          if (item.wideIndices)
            writer.u32(static_cast<std::uint32_t>(index));
          else
            writer.u16(static_cast<std::uint16_t>(index));
        }
        padToAlignment(writer,
                       static_cast<std::uint64_t>(group.indices.size()) *
                         (item.wideIndices ? 4 : 2));
      }
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
  std::string result;
  StringBuf buffer(result);
  std::ostream out(&buffer);
  if (!write(out))
    result.clear();
  return result;
}

} // namespace Avogadro::Rendering
