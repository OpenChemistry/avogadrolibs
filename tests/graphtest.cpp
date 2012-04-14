/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <graph.h>

TEST(GraphTest, size)
{
  Avogadro::Core::Graph graph;
  EXPECT_EQ(graph.size(), 0);

  Avogadro::Core::Graph graph2(12);
  EXPECT_EQ(graph2.size(), 12);
}

TEST(GraphTest, setSize)
{
  Avogadro::Core::Graph graph;
  EXPECT_EQ(graph.size(), 0);

  graph.setSize(100);
  EXPECT_EQ(graph.size(), 100);

  graph.setSize(50);
  EXPECT_EQ(graph.size(), 50);
}

TEST(GraphTest, isEmpty)
{
  Avogadro::Core::Graph graph;
  EXPECT_EQ(graph.isEmpty(), true);

  graph.addVertex();
  EXPECT_EQ(graph.isEmpty(), false);

  graph.clear();
  EXPECT_EQ(graph.isEmpty(), true);
}

TEST(GraphTest, clear)
{
}

TEST(GraphTest, addVertex)
{
  Avogadro::Core::Graph graph;
  size_t index = graph.addVertex();
  EXPECT_EQ(index, 0);
  EXPECT_EQ(graph.size(), 1);

  index = graph.addVertex();
  EXPECT_EQ(index, 1);

  index = graph.addVertex();
  EXPECT_EQ(index, 2);
}

TEST(GraphTest, removeVertex)
{
  Avogadro::Core::Graph graph(4);
  EXPECT_EQ(graph.size(), 4);

  graph.removeVertex(0);
  EXPECT_EQ(graph.size(), 3);

  graph.removeVertex(2);
  EXPECT_EQ(graph.size(), 2);
}

TEST(GraphTest, vertexCount)
{
  Avogadro::Core::Graph graph;
  EXPECT_EQ(graph.vertexCount(), 0);

  graph.addVertex();
  EXPECT_EQ(graph.vertexCount(), 1);

  graph.addVertex();
  EXPECT_EQ(graph.vertexCount(), 2);

  graph.removeVertex(1);
  EXPECT_EQ(graph.vertexCount(), 1);

  graph.clear();
  EXPECT_EQ(graph.vertexCount(), 0);
}

TEST(GraphTest, addEdge)
{
  Avogadro::Core::Graph graph(5);
  EXPECT_EQ(graph.edgeCount(), 0);

  graph.addEdge(0, 1);
  EXPECT_EQ(graph.edgeCount(), 1);
  EXPECT_EQ(graph.containsEdge(0, 1), true);

  graph.addEdge(1, 4);
  EXPECT_EQ(graph.edgeCount(), 2);
  EXPECT_EQ(graph.containsEdge(1, 4), true);
}

TEST(GraphTest, removeEdge)
{
  Avogadro::Core::Graph graph(5);
  graph.addEdge(0, 1);
  graph.addEdge(1, 4);
}

TEST(GraphTest, edgeCount)
{
  Avogadro::Core::Graph graph(3);
  EXPECT_EQ(graph.edgeCount(), 0);

  graph.addEdge(0, 1);
  EXPECT_EQ(graph.edgeCount(), 1);

  graph.addEdge(0, 2);
  EXPECT_EQ(graph.edgeCount(), 2);

  graph.addEdge(1, 2);
  EXPECT_EQ(graph.edgeCount(), 3);

  graph.removeEdge(0, 1);
  EXPECT_EQ(graph.edgeCount(), 2);

  graph.clear();
  EXPECT_EQ(graph.edgeCount(), 0);
}

TEST(GraphTest, connectedComponents)
{
  Avogadro::Core::Graph graph(6);
  EXPECT_EQ(graph.connectedComponents().size(), 6);

  graph.addEdge(0, 1);
  graph.addEdge(1, 2);
  graph.addEdge(3, 4);
  EXPECT_EQ(graph.connectedComponents().size(), 3);

  graph.addEdge(4, 5);
  EXPECT_EQ(graph.connectedComponents().size(), 2);

  graph.addEdge(3, 2);
  EXPECT_EQ(graph.connectedComponents().size(), 1);
}
