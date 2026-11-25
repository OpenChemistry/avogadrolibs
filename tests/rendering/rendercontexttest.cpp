/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// These tests make no GL calls: there is no GL context here.

#include <gtest/gtest.h>

#include <rendercontext_p.h>

#include <cstdint>
#include <set>

using Avogadro::Rendering::FallbackRenderContext;
using Avogadro::Rendering::RenderContext;
using Avogadro::Rendering::ScopedRenderContext;

TEST(RenderContextTest, noCurrentContextOutsideAScope)
{
  EXPECT_EQ(RenderContext::current(), nullptr);
}

TEST(RenderContextTest, scopeSetsAndRestoresCurrent)
{
  RenderContext context;
  {
    ScopedRenderContext scope(&context);
    EXPECT_EQ(RenderContext::current(), &context);
  }
  EXPECT_EQ(RenderContext::current(), nullptr);
}

TEST(RenderContextTest, scopesNest)
{
  RenderContext outer;
  RenderContext inner;
  {
    ScopedRenderContext outerScope(&outer);
    EXPECT_EQ(RenderContext::current(), &outer);
    {
      ScopedRenderContext innerScope(&inner);
      EXPECT_EQ(RenderContext::current(), &inner);
      {
        // A null scope hides the current context, and is undone too.
        ScopedRenderContext nullScope(nullptr);
        EXPECT_EQ(RenderContext::current(), nullptr);
      }
      EXPECT_EQ(RenderContext::current(), &inner);
    }
    EXPECT_EQ(RenderContext::current(), &outer);
  }
  EXPECT_EQ(RenderContext::current(), nullptr);
}

TEST(RenderContextTest, notInitializedHasIdZero)
{
  RenderContext context;
  EXPECT_EQ(context.id(), 0u);
}

TEST(RenderContextTest, initializeAssignsAFreshId)
{
  RenderContext a;
  RenderContext b;
  std::set<std::uint64_t> ids;
  for (int i = 0; i < 3; ++i) {
    a.initialize();
    b.initialize();
    EXPECT_NE(a.id(), 0u);
    EXPECT_NE(b.id(), 0u);
    EXPECT_TRUE(ids.insert(a.id()).second) << "id reused";
    EXPECT_TRUE(ids.insert(b.id()).second) << "id reused";
  }
}

TEST(RenderContextTest, releaseResourcesClearsTheId)
{
  // With no programs built, releasing makes no GL calls.
  RenderContext context;
  context.initialize();
  const std::uint64_t first = context.id();
  context.releaseResources();
  EXPECT_EQ(context.id(), 0u);
  context.releaseResources(); // idempotent
  context.initialize();
  EXPECT_NE(context.id(), 0u);
  EXPECT_NE(context.id(), first);
}

TEST(RenderContextTest, fallbackIsOnlyUsedWithoutACurrentContext)
{
  ASSERT_EQ(RenderContext::current(), nullptr);
  {
    FallbackRenderContext fallback;
    RenderContext* temporary = RenderContext::current();
    ASSERT_NE(temporary, nullptr);
    // A fallback context is never "initialized", so drawables do not take it
    // for a new GL context.
    EXPECT_EQ(temporary->id(), 0u);
    {
      FallbackRenderContext nested;
      EXPECT_EQ(RenderContext::current(), temporary);
    }
    EXPECT_EQ(RenderContext::current(), temporary);
  }
  EXPECT_EQ(RenderContext::current(), nullptr);
}

TEST(RenderContextTest, fallbackLeavesARealContextAlone)
{
  RenderContext context;
  context.initialize();
  ScopedRenderContext scope(&context);
  {
    FallbackRenderContext fallback;
    EXPECT_EQ(RenderContext::current(), &context);
  }
  EXPECT_EQ(RenderContext::current(), &context);
  EXPECT_NE(context.id(), 0u);
}
