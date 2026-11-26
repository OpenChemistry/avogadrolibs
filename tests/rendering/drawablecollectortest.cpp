/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// These tests make no GL calls: there is no GL context here.

#include <gtest/gtest.h>

#include <drawablecollector_p.h>

#include <avogadro/rendering/beziergeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <memory>
#include <vector>

using namespace Avogadro::Rendering;

namespace {

// One of every drawable type that Visitor has an overload for, plus the
// subclasses (CurveGeometry is abstract, so Bezier and BSpline stand in).
std::vector<Drawable*> makeOneOfEach()
{
  return { new Drawable,          new SphereGeometry,   new CylinderGeometry,
           new MeshGeometry,      new TextLabel2D,      new TextLabel3D,
           new LineStripGeometry, new WideLineGeometry, new DashedLineGeometry,
           new ArrowGeometry,     new VolumeGeometry,   new BezierGeometry,
           new BSplineGeometry };
}

} // namespace

// A type missing from DrawableCollector's overloads is silently never
// rendered; this catches it.
TEST(DrawableCollectorTest, collectsEveryDrawableType)
{
  GeometryNode* node = new GeometryNode;
  const std::vector<Drawable*> drawables = makeOneOfEach();
  for (Drawable* drawable : drawables) {
    drawable->setRenderPass(OpaquePass);
    node->addDrawable(drawable);
  }
  DrawableCollector collector;
  node->accept(collector);
  EXPECT_EQ(collector.bucket(OpaquePass), drawables);
  EXPECT_TRUE(collector.bucket(SolidPass).empty());
  delete node;
}

TEST(DrawableCollectorTest, bucketsByPassInSceneOrder)
{
  GroupNode root;
  auto* group = new GroupNode;
  auto* first = new GeometryNode;
  auto* second = new GeometryNode;
  root.addChild(first);
  root.addChild(group);
  group->addChild(second);

  auto* a = new SphereGeometry;
  auto* b = new SphereGeometry;
  auto* c = new SphereGeometry;
  auto* d = new SphereGeometry;
  auto* hidden = new SphereGeometry;
  auto* none = new SphereGeometry;
  a->setRenderPass(SolidPass);
  b->setRenderPass(TranslucentPass);
  c->setRenderPass(SolidPass);
  d->setRenderPass(Overlay2DPass);
  hidden->setRenderPass(SolidPass);
  hidden->setVisible(false);
  none->setRenderPass(NotRendering);
  first->addDrawable(a);
  first->addDrawable(b);
  first->addDrawable(hidden);
  second->addDrawable(c);
  second->addDrawable(d);
  second->addDrawable(none);

  DrawableCollector collector;
  root.accept(collector);
  EXPECT_EQ(collector.bucket(SolidPass), (std::vector<Drawable*>{ a, c }));
  EXPECT_EQ(collector.bucket(TranslucentPass), (std::vector<Drawable*>{ b }));
  EXPECT_EQ(collector.bucket(Overlay2DPass), (std::vector<Drawable*>{ d }));
  EXPECT_TRUE(collector.bucket(OpaquePass).empty());
  EXPECT_TRUE(collector.bucket(Overlay3DPass).empty());
  EXPECT_TRUE(collector.bucket(NotRendering).empty());

  collector.clear();
  EXPECT_TRUE(collector.bucket(SolidPass).empty());
}

TEST(DrawableCollectorTest, skipsHiddenSubtrees)
{
  GroupNode root;
  auto* hiddenGroup = new GroupNode;
  auto* nestedVisible = new GroupNode;
  auto* nestedGeometry = new GeometryNode;
  auto* hiddenGeometry = new GeometryNode;
  auto* shownGeometry = new GeometryNode;
  root.addChild(hiddenGroup);
  hiddenGroup->addChild(nestedVisible);
  nestedVisible->addChild(nestedGeometry);
  root.addChild(hiddenGeometry);
  root.addChild(shownGeometry);

  auto* a = new SphereGeometry;
  auto* b = new SphereGeometry;
  auto* c = new SphereGeometry;
  auto* d = new SphereGeometry;
  nestedGeometry->addDrawable(a);
  hiddenGeometry->addDrawable(b);
  shownGeometry->addDrawable(c);
  hiddenGroup->addChild(new GeometryNode);
  static_cast<GeometryNode*>(hiddenGroup->child(1))->addDrawable(d);

  hiddenGroup->setVisible(false);
  hiddenGeometry->setVisible(false);
  // A visible group inside a hidden group is still hidden.
  EXPECT_TRUE(nestedVisible->isVisible());

  DrawableCollector collector;
  root.accept(collector);
  EXPECT_EQ(collector.bucket(SolidPass), (std::vector<Drawable*>{ c }));

  hiddenGroup->setVisible(true);
  collector.clear();
  root.accept(collector);
  EXPECT_EQ(collector.bucket(SolidPass), (std::vector<Drawable*>{ a, d, c }));

  hiddenGeometry->setVisible(true);
  collector.clear();
  root.accept(collector);
  EXPECT_EQ(collector.bucket(SolidPass),
            (std::vector<Drawable*>{ a, d, b, c }));
}
