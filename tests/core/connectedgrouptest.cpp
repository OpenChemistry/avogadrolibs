/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/connectedgroup.h>

using namespace Avogadro::Core;

namespace {}

TEST(ConnectedGroupTest, elements)
{
  ConnectedGroup group;
  std::vector<std::set<size_t>> control();
  EXPECT_EQ(group.getAllGroups(), control);

  group.addElement();
  control.push_back(std::set<size_t>({ 0 }));
  EXPECT_EQ(group.getAllGroups(), control);

  group.addElements(4);
  control.push_back(std::set<size_t>({ 1 }));
  control.push_back(std::set<size_t>({ 2 }));
  control.push_back(std::set<size_t>({ 3 }));
  control.push_back(std::set<size_t>({ 4 }));
  EXPECT_EQ(group.getAllGroups(), control);

  group.removeElement(4);
  control.pop_back();
  EXPECT_EQ(group.getAllGroups(), control);

  group.clear();
  control.clear();
  EXPECT_EQ(group.getAllGroups(), control);
}

TEST(ConnectedGroupTest, connections)
{
  ConnectedGroup group;
  std::vector<std::set<size_t>> control;

  group.addElements(5);
  control.push_back(std::set<size_t>({ 0, 1 }));
  control.push_back(std::set<size_t>({ 2 }));
  control.push_back(std::set<size_t>({ 3 }));
  control.push_back(std::set<size_t>({ 4 }));
  group.addConnection(1, 2);
  EXPECT_EQ(group.getAllGroups(), control);

  group.addConnection(3, 4);
  control.pop_back();
  control.pop_back();
  control.push_back(std::set<size_t>({ 3, 4 }));
  EXPECT_EQ(group.getAllGroups(), control);

  group.addConnection(0, 4);
  control.clear();
  control.push_back(std::set<size_t>({ 0, 1, 2, 3, 4 }));
  EXPECT_EQ(group.getAllGroups(), control);

  group.removeConnection(2, { 0, 1, 3, 4 }, 3, { 0, 1, 2, 4 });
  control.clear();
  control.push_back(std::set<size_t>({ 0, 1, 2, 3, 4 }));
  EXPECT_EQ(group.getAllGroups(), control);

  group.addConnection(2, 3);
  group.removeConnection(2, { 0, 1, 3 }, 3, { 2, 4 });
  control.clear();
  control.push_back(std::set<size_t>({ 0, 1, 2 }));
  control.push_back(std::set<size_t>({ 3, 4 }));
  EXPECT_EQ(group.getAllGroups(), control);

  group.removeConnection(2);
  control.clear();
  control.push_back(std::set<size_t>({ 0, 1 }));
  control.push_back(std::set<size_t>({ 3, 4 }));
  control.push_back(std::set<size_t>({ 2 }));
  EXPECT_EQ(group.getAllGroups(), control);

  group.removeConnections();
  control.clear();
  control.push_back(std::set<size_t>({ 0 }));
  control.push_back(std::set<size_t>({ 1 }));
  control.push_back(std::set<size_t>({ 2 }));
  control.push_back(std::set<size_t>({ 3 }));
  control.push_back(std::set<size_t>({ 4 }));
  EXPECT_EQ(group.getAllGroups(), control);
}
