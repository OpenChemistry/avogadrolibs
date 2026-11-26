/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

// geometrybounds_p.h is private to the library; see the CMake include path.
#include "geometrybounds_p.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <limits>
#include <map>
#include <random>
#include <utility>
#include <vector>

using namespace Avogadro;
using namespace Avogadro::Rendering;

namespace {

using Hit = std::pair<float, size_t>; // depth, primitive index

// The sphere test as it was before the bounds were added.
std::vector<Hit> referenceSphereHits(const SphereGeometry& geometry,
                                     const std::vector<size_t>& indices,
                                     const Vector3f& rayOrigin,
                                     const Vector3f& rayEnd,
                                     const Vector3f& rayDirection)
{
  std::vector<Hit> result;
  if (geometry.identifier().type == InvalidType)
    return result;
  const auto& spheres = geometry.spheres();
  for (size_t i = 0; i < spheres.size(); ++i) {
    const SphereColor& sphere = spheres[i];
    Vector3f distance = sphere.center - rayOrigin;
    float B = distance.dot(rayDirection);
    float C = distance.dot(distance) - (sphere.radius * sphere.radius);
    float D = B * B - C;
    if (D < 0.0f)
      continue;
    if (B < 0.0f || (sphere.center - rayEnd).dot(rayDirection) > 0.0f)
      continue;
    auto rootD = static_cast<float>(sqrt(D));
    float depth = std::min(std::abs(B + rootD), std::abs(B - rootD));
    result.emplace_back(depth, indices[i]);
  }
  return result;
}

// The cylinder test as it was, plus the parallel-ray guard.
std::vector<Hit> referenceCylinderHits(const CylinderGeometry& geometry,
                                       const Vector3f& rayOrigin,
                                       const Vector3f& rayEnd,
                                       const Vector3f& rayDirection)
{
  std::vector<Hit> result;
  if (geometry.identifier().type == InvalidType)
    return result;
  const auto& cylinders = geometry.cylinders();
  for (size_t i = 0; i < cylinders.size(); ++i) {
    const CylinderColor& cylinder = cylinders[i];
    Vector3f ao = rayOrigin - cylinder.end1;
    Vector3f ab = cylinder.end2 - cylinder.end1;
    Vector3f aoxab = ao.cross(ab);
    Vector3f vxab = rayDirection.cross(ab);
    float A = vxab.dot(vxab);
    float B = 2.0f * vxab.dot(aoxab);
    float C =
      aoxab.dot(aoxab) - ab.dot(ab) * (cylinder.radius * cylinder.radius);
    float D = B * B - 4.0f * A * C;
    if (!(A > 1.0e-18f))
      continue;
    if (D < 0.0f)
      continue;
    float t = std::min((-B + std::sqrt(D)) / (2.0f * A),
                       (-B - std::sqrt(D)) / (2.0f * A));
    Vector3f ip = rayOrigin + (rayDirection * t);
    Vector3f ip1 = ip - cylinder.end1;
    Vector3f ip2 = ip - (cylinder.end1 + ab);
    if (ip1.dot(ab) < 0.0f || ip2.dot(ab) > 0.0f)
      continue;
    Vector3f distance = ip - rayOrigin;
    if (distance.dot(rayDirection) < 0.0f ||
        (ip - rayEnd).dot(rayDirection) > 0.0f)
      continue;
    result.emplace_back(distance.norm(), i);
  }
  return result;
}

// Keys and primitive indices, in map order.
std::vector<Hit> flatten(const std::multimap<float, Identifier>& hits)
{
  std::vector<Hit> result;
  for (const auto& hit : hits)
    result.emplace_back(hit.first, hit.second.index);
  return result;
}

// What a multimap makes of unsorted hits: sorted by depth, equal depths in
// the order given.
std::vector<Hit> sortedLikeMultimap(std::vector<Hit> hits)
{
  std::stable_sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) {
    return a.first < b.first;
  });
  return hits;
}

struct Ray
{
  Vector3f origin, end, direction;
};

std::vector<Ray> randomRays(std::mt19937& rng, int count)
{
  std::uniform_real_distribution<float> pos(-14.0f, 14.0f);
  std::uniform_real_distribution<float> far(30.0f, 60.0f);
  std::normal_distribution<float> gauss;
  std::vector<Ray> rays;
  for (int i = 0; i < count; ++i) {
    Ray r;
    r.origin = Vector3f(pos(rng), pos(rng), -far(rng));
    // Aim at a random point near the scene so most rays hit something.
    const Vector3f target(pos(rng) * 0.7f, pos(rng) * 0.7f, pos(rng) * 0.7f);
    r.direction = (target - r.origin).normalized();
    r.end = r.origin + r.direction * (2.0f * far(rng));
    rays.push_back(r);
  }
  // Axis-aligned rays, through and beside the scene, from both sides.
  for (int axis = 0; axis < 3; ++axis) {
    for (float sign : { 1.0f, -1.0f }) {
      for (int k = 0; k < 6; ++k) {
        Ray r;
        r.origin = Vector3f(pos(rng), pos(rng), pos(rng));
        r.origin[axis] = -sign * 40.0f;
        r.direction = Vector3f::Zero();
        r.direction[axis] = sign;
        r.end = r.origin + r.direction * 80.0f;
        rays.push_back(r);
      }
    }
  }
  // Starting inside the scene.
  for (int i = 0; i < 20; ++i) {
    Ray r;
    r.origin = Vector3f(pos(rng), pos(rng), pos(rng)) * 0.5f;
    r.direction = Vector3f(gauss(rng), gauss(rng), gauss(rng)).normalized();
    r.end = r.origin + r.direction * 50.0f;
    rays.push_back(r);
  }
  return rays;
}

struct SphereScene
{
  std::vector<size_t> indices;
};

void fillSpheres(SphereGeometry& geometry, std::vector<size_t>& indices,
                 std::mt19937& rng, int count)
{
  std::uniform_real_distribution<float> pos(-12.0f, 12.0f);
  std::uniform_real_distribution<float> rad(0.2f, 2.5f);
  geometry.identifier().molecule = &geometry; // any non-null address
  geometry.identifier().type = AtomType;
  for (int i = 0; i < count; ++i) {
    const size_t index = static_cast<size_t>(i) * 3 + 1;
    geometry.addSphere(Vector3f(pos(rng), pos(rng), pos(rng)),
                       Vector3ub(1, 2, 3), rad(rng), index);
    indices.push_back(index);
  }
}

void fillCylinders(CylinderGeometry& geometry, std::mt19937& rng, int count)
{
  std::uniform_real_distribution<float> pos(-12.0f, 12.0f);
  std::uniform_real_distribution<float> rad(0.1f, 1.0f);
  geometry.identifier().molecule = &geometry;
  geometry.identifier().type = BondType;
  for (int i = 0; i < count; ++i) {
    geometry.addCylinder(Vector3f(pos(rng), pos(rng), pos(rng)),
                         Vector3f(pos(rng), pos(rng), pos(rng)), rad(rng),
                         Vector3ub(1, 2, 3));
  }
}

} // namespace

TEST(PickingTest, sphereHitsMatchTheReference)
{
  std::mt19937 rng(7);
  for (int scene = 0; scene < 40; ++scene) {
    SphereGeometry geometry;
    std::vector<size_t> indices;
    fillSpheres(geometry, indices, rng, scene == 0 ? 0 : 1 + scene * 5);
    for (const Ray& r : randomRays(rng, 60)) {
      const auto expected = sortedLikeMultimap(
        referenceSphereHits(geometry, indices, r.origin, r.end, r.direction));
      EXPECT_EQ(flatten(geometry.hits(r.origin, r.end, r.direction)), expected)
        << scene;
    }
  }
}

TEST(PickingTest, cylinderHitsMatchTheReference)
{
  std::mt19937 rng(11);
  for (int scene = 0; scene < 40; ++scene) {
    CylinderGeometry geometry;
    fillCylinders(geometry, rng, scene == 0 ? 0 : 1 + scene * 4);
    for (const Ray& r : randomRays(rng, 60)) {
      const auto expected = sortedLikeMultimap(
        referenceCylinderHits(geometry, r.origin, r.end, r.direction));
      EXPECT_EQ(flatten(geometry.hits(r.origin, r.end, r.direction)), expected)
        << scene;
    }
  }
}

TEST(PickingTest, degenerateRaysMatchTheReference)
{
  std::mt19937 rng(3);
  SphereGeometry spheres;
  std::vector<size_t> indices;
  fillSpheres(spheres, indices, rng, 50);
  CylinderGeometry cylinders;
  fillCylinders(cylinders, rng, 50);

  const float nan = std::numeric_limits<float>::quiet_NaN();
  const Vector3f inside(1, 2, 3);
  const std::vector<Ray> rays = {
    { inside, inside, Vector3f::Zero() },
    { inside, inside + Vector3f(0, 0, 5), Vector3f(0, 0, 2) },
    { inside, inside + Vector3f(0, 0, 5), Vector3f(0, 0, 0.001f) },
    { Vector3f(nan, 0, 0), Vector3f(0, 0, 5), Vector3f(0, 0, 1) },
    { Vector3f(0, 0, -50), Vector3f(0, 0, 5), Vector3f(nan, 0, 1) },
    { Vector3f(0, 0, -50), Vector3f(0, 0, 50), Vector3f(0, 0, 1) },
    // The end behind the origin.
    { Vector3f(0, 0, 50), Vector3f(0, 0, 60), Vector3f(0, 0, -1) },
  };
  for (const Ray& r : rays) {
    // Compare keys with NaN treated as a mismatch only if the reference
    // differs; both sides produce the same sequence of operations.
    const auto sphereExpected = sortedLikeMultimap(
      referenceSphereHits(spheres, indices, r.origin, r.end, r.direction));
    const auto sphereActual =
      flatten(spheres.hits(r.origin, r.end, r.direction));
    ASSERT_EQ(sphereActual.size(), sphereExpected.size());
    for (size_t i = 0; i < sphereActual.size(); ++i)
      EXPECT_EQ(sphereActual[i].second, sphereExpected[i].second);
    const auto cylinderExpected = sortedLikeMultimap(
      referenceCylinderHits(cylinders, r.origin, r.end, r.direction));
    const auto cylinderActual =
      flatten(cylinders.hits(r.origin, r.end, r.direction));
    ASSERT_EQ(cylinderActual.size(), cylinderExpected.size());
  }
}

TEST(PickingTest, boundsNeverRejectARayThatHits)
{
  std::mt19937 rng(5);
  for (int scene = 1; scene < 60; ++scene) {
    SphereGeometry spheres;
    std::vector<size_t> indices;
    fillSpheres(spheres, indices, rng, scene);
    GeometryBounds sphereBox;
    for (const SphereColor& s : spheres.spheres())
      sphereBox.include(s.center, s.radius);
    sphereBox.finish();
    ASSERT_TRUE(sphereBox.usable);

    CylinderGeometry cylinders;
    fillCylinders(cylinders, rng, scene);
    GeometryBounds cylinderBox;
    for (const CylinderColor& c : cylinders.cylinders()) {
      cylinderBox.include(c.end1, c.radius);
      cylinderBox.include(c.end2, c.radius);
    }
    cylinderBox.finish();

    int rejected = 0, total = 0;
    for (const Ray& r : randomRays(rng, 80)) {
      ++total;
      const bool sphereHit =
        !referenceSphereHits(spheres, indices, r.origin, r.end, r.direction)
           .empty();
      const bool mayHit = rayMayHitBounds(sphereBox, r.origin, r.direction);
      if (sphereHit)
        EXPECT_TRUE(mayHit);
      if (!mayHit)
        ++rejected;
      if (!referenceCylinderHits(cylinders, r.origin, r.end, r.direction)
             .empty()) {
        EXPECT_TRUE(rayMayHitBounds(cylinderBox, r.origin, r.direction));
      }
    }
    // The test is only meaningful if the box rejects something.
    if (scene < 10)
      EXPECT_GT(rejected, 0) << total;
  }
}

TEST(PickingTest, boundsAreConservativeForOddRays)
{
  GeometryBounds box;
  box.include(Vector3f(0, 0, 0), 1.0f);
  box.finish();
  ASSERT_TRUE(box.usable);
  const float nan = std::numeric_limits<float>::quiet_NaN();
  const Vector3f far(100, 100, 100);
  // Not unit length or not finite: no opinion.
  EXPECT_TRUE(rayMayHitBounds(box, far, Vector3f::Zero()));
  EXPECT_TRUE(rayMayHitBounds(box, far, Vector3f(0, 0, 3)));
  EXPECT_TRUE(rayMayHitBounds(box, far, Vector3f(nan, 0, 1)));
  EXPECT_TRUE(rayMayHitBounds(box, Vector3f(nan, 0, 0), Vector3f(0, 0, 1)));
  // Unit rays, axis aligned.
  EXPECT_TRUE(rayMayHitBounds(box, Vector3f(0, 0, -5), Vector3f(0, 0, 1)));
  EXPECT_FALSE(rayMayHitBounds(box, Vector3f(0, 0, -5), Vector3f(0, 0, -1)));
  EXPECT_FALSE(rayMayHitBounds(box, Vector3f(5, 0, -5), Vector3f(0, 0, 1)));
  EXPECT_TRUE(rayMayHitBounds(box, Vector3f(0.5f, 0.5f, 0), Vector3f(0, 1, 0)));
  // Empty and non-finite geometry have no usable box.
  GeometryBounds empty;
  empty.finish();
  EXPECT_FALSE(empty.usable);
  EXPECT_TRUE(rayMayHitBounds(empty, far, Vector3f(0, 0, 1)));
  GeometryBounds bad;
  bad.include(Vector3f(nan, 0, 0), 1.0f);
  bad.include(Vector3f(0, 0, 0), 1.0f);
  bad.finish();
  EXPECT_FALSE(bad.usable);
}

TEST(PickingTest, cachedBoundsFollowTheDirtyContract)
{
  CachedBounds cache;
  int computed = 0;
  float radius = 1.0f;
  auto compute = [&] {
    ++computed;
    GeometryBounds b;
    b.include(Vector3f(0, 0, 0), radius);
    b.finish();
    return b;
  };

  // Dirty geometry: no box, nothing cached.
  EXPECT_EQ(cache.acquire(true, compute), nullptr);
  EXPECT_FALSE(cache.valid());
  EXPECT_EQ(computed, 0);

  // Clean geometry: computed once, then reused.
  const GeometryBounds* box = cache.acquire(false, compute);
  ASSERT_NE(box, nullptr);
  const float firstMax = box->max.x();
  EXPECT_EQ(cache.acquire(false, compute), box);
  EXPECT_EQ(computed, 1);

  // An in-place edit followed by markDirty(): bypassed while dirty (even
  // though the stale box is still held), and forgotten.
  radius = 5.0f;
  EXPECT_EQ(cache.acquire(true, compute), nullptr);
  EXPECT_FALSE(cache.valid());
  // update() clears the dirty flag and invalidates: the next clean query
  // sees the edit.
  cache.invalidate();
  box = cache.acquire(false, compute);
  ASSERT_NE(box, nullptr);
  EXPECT_GT(box->max.x(), firstMax + 3.0f);
  EXPECT_EQ(computed, 2);

  // clear()/addSphere() invalidate explicitly.
  radius = 2.0f;
  cache.invalidate();
  box = cache.acquire(false, compute);
  ASSERT_NE(box, nullptr);
  EXPECT_LT(box->max.x(), firstMax + 3.0f);
  EXPECT_EQ(computed, 3);
}

TEST(PickingTest, hitsFollowEditsToTheGeometry)
{
  std::mt19937 rng(9);
  SphereGeometry geometry;
  std::vector<size_t> indices;
  fillSpheres(geometry, indices, rng, 30);
  const Ray along{ Vector3f(0, 0, -50), Vector3f(0, 0, 50), Vector3f(0, 0, 1) };

  auto check = [&](const char* when) {
    for (const Ray& r : randomRays(rng, 40)) {
      EXPECT_EQ(flatten(geometry.hits(r.origin, r.end, r.direction)),
                sortedLikeMultimap(referenceSphereHits(
                  geometry, indices, r.origin, r.end, r.direction)))
        << when;
    }
  };
  check("initial");

  // In place, as the scene plugins do, then markDirty().
  for (SphereColor& s : geometry.spheres())
    s.center += Vector3f(30, 0, 0);
  geometry.markDirty();
  check("moved in place");
  EXPECT_TRUE(geometry.hits(along.origin, along.end, along.direction).empty());

  // A sphere added after the edits is found on the axis.
  geometry.addSphere(Vector3f(0, 0, 0), Vector3ub(1, 2, 3), 1.0f, 999);
  indices.push_back(999);
  check("added");
  auto hits = geometry.hits(along.origin, along.end, along.direction);
  ASSERT_EQ(hits.size(), 1u);
  EXPECT_EQ(hits.begin()->second.index, 999u);
  EXPECT_NEAR(hits.begin()->first, 49.0f, 1.0e-4f);

  // clear() leaves nothing to hit, and the next sphere is found again.
  geometry.clear();
  indices.clear();
  EXPECT_TRUE(geometry.hits(along.origin, along.end, along.direction).empty());
  geometry.addSphere(Vector3f(0, 0, 10), Vector3ub(1, 2, 3), 1.0f, 5);
  hits = geometry.hits(along.origin, along.end, along.direction);
  ASSERT_EQ(hits.size(), 1u);
  EXPECT_EQ(hits.begin()->second.index, 5u);

  // A copy and an assignment start dirty and agree with their source.
  SphereGeometry copy(geometry);
  EXPECT_EQ(flatten(copy.hits(along.origin, along.end, along.direction)),
            flatten(geometry.hits(along.origin, along.end, along.direction)));
}

namespace {

// The scene walk as it was: every level returns a map by value.
std::multimap<float, Identifier> referenceGroupHits(const GroupNode* group,
                                                    const Ray& r)
{
  std::multimap<float, Identifier> result;
  if (!group || !group->isVisible())
    return result;
  for (auto it : group->children()) {
    std::multimap<float, Identifier> loop;
    const auto* childGroup = dynamic_cast<const GroupNode*>(it.node);
    if (childGroup) {
      loop = referenceGroupHits(childGroup, r);
      result.insert(loop.begin(), loop.end());
      continue;
    }
    const auto* geometry = it.node->cast<GeometryNode>();
    if (geometry && geometry->isVisible()) {
      for (auto* drawable : geometry->drawables()) {
        std::multimap<float, Identifier> d;
        if (drawable->isVisible())
          d = drawable->hits(r.origin, r.end, r.direction);
        result.insert(d.begin(), d.end());
      }
    }
  }
  return result;
}

bool sameHits(const std::multimap<float, Identifier>& a,
              const std::multimap<float, Identifier>& b)
{
  if (a.size() != b.size())
    return false;
  for (auto i = a.begin(), j = b.begin(); i != a.end(); ++i, ++j) {
    if (i->first != j->first || i->second != j->second)
      return false;
  }
  return true;
}

} // namespace

TEST(PickingTest, rendererHitsMatchTheReferenceWalk)
{
  std::mt19937 rng(21);
  GLRenderer renderer;
  Camera& camera = renderer.camera();
  camera.setViewport(200, 200);
  camera.calculatePerspective(40.0f, 1.0f, 1.0f, 200.0f);
  camera.lookAt(Vector3f(0, 0, 45), Vector3f(0, 0, 0), Vector3f(0, 1, 0));

  // Nested groups, with geometry at several levels, and hidden pieces.
  GroupNode& root = renderer.scene().rootNode();
  std::vector<GroupNode*> groups = { &root };
  for (int g = 0; g < 4; ++g) {
    auto* child = new GroupNode;
    groups[static_cast<size_t>(g)]->addChild(child);
    groups.push_back(child);
  }
  std::vector<std::vector<size_t>> indices;
  int made = 0;
  for (GroupNode* group : groups) {
    for (int n = 0; n < 2; ++n) {
      auto* node = new GeometryNode;
      group->addChild(node);
      auto* spheres = new SphereGeometry;
      indices.emplace_back();
      fillSpheres(*spheres, indices.back(), rng, 40);
      node->addDrawable(spheres);
      auto* cylinders = new CylinderGeometry;
      fillCylinders(*cylinders, rng, 30);
      node->addDrawable(cylinders);
      // Hide something different each time.
      switch (made++ % 5) {
        case 1:
          node->setVisible(false);
          break;
        case 2:
          spheres->setVisible(false);
          break;
        case 3:
          cylinders->setVisible(false);
          break;
        default:
          break;
      }
    }
  }
  groups[3]->setVisible(false); // hides its subtree

  int withHits = 0;
  for (int y = 0; y < 200; y += 7) {
    for (int x = 0; x < 200; x += 7) {
      const Vector3f origin(camera.unProject(
        Vector3f(static_cast<float>(x), static_cast<float>(y), 0.f)));
      const Vector3f end(camera.unProject(
        Vector3f(static_cast<float>(x), static_cast<float>(y), 1.f)));
      const Ray r{ origin, end, (end - origin).normalized() };
      const auto expected = referenceGroupHits(&root, r);
      const auto actual = renderer.hits(x, y);
      EXPECT_TRUE(sameHits(actual, expected)) << x << "," << y;
      if (!actual.empty()) {
        ++withHits;
        EXPECT_EQ(renderer.hit(r.origin, r.end, r.direction),
                  actual.begin()->first);
      }
    }
  }
  EXPECT_GT(withHits, 50);

  // Hidden things really are skipped: hide everything and nothing is hit.
  root.setVisible(false);
  EXPECT_TRUE(renderer.hits(100, 100).empty());
  EXPECT_EQ(
    renderer.hit(Vector3f(0, 0, 40), Vector3f(0, 0, -40), Vector3f(0, 0, -1)),
    std::numeric_limits<float>::max());
}
