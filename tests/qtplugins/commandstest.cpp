/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "command.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/spheregeometry.h>

#include <gtest/gtest.h>

#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QTemporaryDir>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Core::Array;
using Avogadro::QtPlugins::Command;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::Scene;
using Avogadro::Rendering::SphereGeometry;

namespace {

// The JSON chunk of a .glb file, or an empty object if it is malformed.
QJsonObject readJsonChunk(const QString& fileName)
{
  QFile file(fileName);
  if (!file.open(QIODevice::ReadOnly))
    return QJsonObject();
  const QByteArray data = file.readAll();
  if (data.size() < 20 || data.left(4) != "glTF" || data.mid(16, 4) != "JSON")
    return QJsonObject();
  const auto* bytes = reinterpret_cast<const unsigned char*>(data.constData());
  const qsizetype length =
    bytes[12] | (bytes[13] << 8) | (bytes[14] << 16) | (bytes[15] << 24);
  if (20 + length > data.size())
    return QJsonObject();
  return QJsonDocument::fromJson(data.mid(20, length)).object();
}

QJsonObject meshPrimitive(const QJsonObject& json, const QString& name)
{
  for (const QJsonValue& mesh : json["meshes"].toArray()) {
    if (mesh.toObject()["name"].toString() == name)
      return mesh.toObject()["primitives"].toArray().at(0).toObject();
  }
  return QJsonObject();
}

} // namespace

TEST(CommandSceneTest, writesSceneInAvogadroFrame)
{
  // A translucent quad away from the origin, and a sphere.
  Array<Vector3f> vertices, normals;
  Array<Vector4ub> colors;
  vertices.push_back(Vector3f(10, 20, 30));
  vertices.push_back(Vector3f(15, 20, 30));
  vertices.push_back(Vector3f(15, 23, 30));
  vertices.push_back(Vector3f(10, 23, 30));
  for (int i = 0; i < 4; ++i) {
    normals.push_back(Vector3f(0, 0, 1));
    colors.push_back(Vector4ub(10, 200, 30, 128));
  }
  // The node owns its drawables.
  auto* mesh = new MeshGeometry;
  mesh->addVertices(vertices, normals, colors);
  mesh->addTriangle(0, 1, 2);
  mesh->addTriangle(0, 2, 3);
  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(10, 20, 30), Vector3ub(255, 0, 0), 1.0f);

  Scene scene;
  auto* node = new GeometryNode;
  node->addDrawable(mesh);
  node->addDrawable(spheres);
  scene.rootNode().addChild(node);
  Camera camera;

  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  const QString path = dir.filePath("scene.glb");
  ASSERT_TRUE(Command::writeSceneGlb(&scene, &camera, path));

  const QJsonObject json = readJsonChunk(path);
  ASSERT_FALSE(json.isEmpty());

  // Avogadro's frame and units: no scale, no centering.
  const QJsonObject extras = json["asset"].toObject()["extras"].toObject();
  EXPECT_EQ(extras["units"].toString(), "angstrom");
  EXPECT_DOUBLE_EQ(extras["scale"].toDouble(), 1.0);
  const QJsonArray offset = extras["offset"].toArray();
  ASSERT_EQ(offset.size(), 3);
  for (int i = 0; i < 3; ++i)
    EXPECT_DOUBLE_EQ(offset[i].toDouble(), 0.0);

  // The mesh node keeps its name and its vertices.
  const QJsonObject mp = meshPrimitive(json, "mesh");
  ASSERT_FALSE(mp.isEmpty());
  const int position = mp["attributes"].toObject()["POSITION"].toInt(-1);
  ASSERT_GE(position, 0);
  const QJsonObject accessor =
    json["accessors"].toArray().at(position).toObject();
  EXPECT_DOUBLE_EQ(accessor["min"].toArray().at(0).toDouble(), 10.0);
  EXPECT_DOUBLE_EQ(accessor["max"].toArray().at(0).toDouble(), 15.0);
  EXPECT_DOUBLE_EQ(accessor["min"].toArray().at(1).toDouble(), 20.0);
  EXPECT_DOUBLE_EQ(accessor["max"].toArray().at(1).toDouble(), 23.0);
  EXPECT_DOUBLE_EQ(accessor["min"].toArray().at(2).toDouble(), 30.0);
  EXPECT_DOUBLE_EQ(accessor["max"].toArray().at(2).toDouble(), 30.0);

  // The translucent mesh is blended; the sphere is present and opaque.
  const QJsonObject material =
    json["materials"].toArray().at(mp["material"].toInt()).toObject();
  EXPECT_EQ(material["alphaMode"].toString(), "BLEND");
  const QJsonObject sp = meshPrimitive(json, "spheres");
  ASSERT_FALSE(sp.isEmpty());
  EXPECT_EQ(json["materials"]
              .toArray()
              .at(sp["material"].toInt())
              .toObject()["alphaMode"]
              .toString(),
            "OPAQUE");
}

TEST(CommandSceneTest, failsWithoutSceneCameraOrDestination)
{
  Scene scene;
  Camera camera;
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  const QString path = dir.filePath("scene.glb");
  EXPECT_FALSE(Command::writeSceneGlb(nullptr, &camera, path));
  EXPECT_FALSE(Command::writeSceneGlb(&scene, nullptr, path));
  EXPECT_FALSE(QFile::exists(path));
  EXPECT_FALSE(
    Command::writeSceneGlb(&scene, &camera, dir.filePath("no/such/dir.glb")));
}
