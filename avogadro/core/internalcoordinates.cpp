/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "internalcoordinates.h"
#include "matrix.h"

#include <cmath>

namespace Avogadro::Core {

Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords)
{
  Array<Vector3> coords(molecule.atomCount());
  Vector3 ab;
  Vector3 bc;
  Vector3 n;
  Matrix3 m;

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Real sinTheta, cosTheta, sinPhi, cosPhi;
    Real length = internalCoords[i].length;
    Real angle = internalCoords[i].angle;
    Real dihedral = internalCoords[i].dihedral;
    // Index i represents the current atom
    Index a = internalCoords[i].a; // i will be some distance to a
    Index b = internalCoords[i].b; // i-a-b is an angle
    Index c = internalCoords[i].c; // i-a-b-c is a dihedral

    switch (i) {
      case 0:
        coords[i] = Vector3(0.0, 0.0, 0.0);
        break;
      case 1:
        coords[i] = Vector3(length, 0.0, 0.0);
        break;
      case 2: {
        sinTheta = std::sin(angle * DEG_TO_RAD);
        cosTheta = std::cos(angle * DEG_TO_RAD);
        ab = (coords[b] - coords[a]).normalized();

        // We want to place atom i at distance 'length' from atom a
        // at angle 'angle' from the a-b direction

        // Perpendicular to ab in the xy-plane
        Vector3 perpendicular(-ab.y(), ab.x(), 0.0);
        if (perpendicular.norm() > 1e-6) {
          perpendicular.normalize();
        } else {
          // ab is along z-axis, use x-axis as perpendicular
          perpendicular = Vector3(1.0, 0.0, 0.0);
        }

        // Place atom i: start from a, extend in direction
        // that makes angle with ab
        coords[i] =
          coords[a] + length * (cosTheta * ab + sinTheta * perpendicular);
        break;
      }
      default:
        // NeRF formula
        // see J. Comp. Chem. Vol. 26, No. 10, p. 1063-1068 (2005)
        // https://doi.org/10.1002/jcc.20237
        sinTheta = std::sin(angle * DEG_TO_RAD);
        cosTheta = std::cos(angle * DEG_TO_RAD);
        sinPhi = std::sin(dihedral * DEG_TO_RAD);
        cosPhi = std::cos(dihedral * DEG_TO_RAD);

        // Place atom i relative to atoms a, b, c
        // - i bonds to a at distance 'length'
        // - angle at a between i-a-b is 'angle'
        // - dihedral i-a-b-c is 'dihedral'

        // Vector from a to b (the bond direction for angle reference)
        ab = (coords[b] - coords[a]).normalized();

        // Vector from b to c (needed for dihedral plane)
        bc = (coords[c] - coords[b]).normalized();

        // Normal to the plane defined by a-b-c
        Vector3 n = ab.cross(bc);
        Real n_norm = n.norm();

        if (n_norm > 1e-10) {
          n.normalize();
        } else {
          // Atoms a, b, c are collinear - choose arbitrary perpendicular
          // Find a vector perpendicular to ab
          if (std::abs(ab.x()) < 0.9) {
            n = Vector3(1.0, 0.0, 0.0).cross(ab).normalized();
          } else {
            n = Vector3(0.0, 1.0, 0.0).cross(ab).normalized();
          }
        }

        // Vector perpendicular to both ab and n
        // (in the plane perpendicular to ab)
        Vector3 n_perp = n.cross(ab);

        // Local coordinate system at atom a:
        // - ab direction: along the a-b bond (reference for angle)
        // - n_perp direction: perpendicular to ab, in plane for 0° dihedral
        // - n direction: perpendicular to ab, for rotating out of plane

        // Position in local frame using NeRF formula (page 1066, eq. 2)
        // We place atom i relative to atom a
        // The angle is measured from the ab direction
        // The dihedral rotates around the ab axis
        Vector3 localPos(length * cosTheta, length * sinTheta * cosPhi,
                         length * sinTheta * sinPhi);

        // Build rotation matrix with columns [ab, n_perp, n]
        Matrix3 m;
        m.col(0) = ab;
        m.col(1) = n_perp;
        m.col(2) = n;

        // Transform to global coordinates and translate to atom a
        coords[i] = m * localPos + coords[a];
        break;
    }
  }

  return coords;
}

// Helper structure to store the connectivity tree
struct ConnectivityTree
{
  Array<Index> parent;      // parent[i] = atom that i bonds to (atom a)
  Array<Index> grandparent; // grandparent[i] = parent's parent (atom b)
  Array<Index>
    greatgrandparent; // greatgrandparent[i] = grandparent's parent (atom c)
};

// Build a spanning tree of the molecule using BFS
// Handles disconnected fragments by building a separate tree for each component
ConnectivityTree buildConnectivityTree(const Molecule& molecule)
{
  Index atomCount = molecule.atomCount();
  ConnectivityTree tree;
  tree.parent.resize(atomCount);
  tree.grandparent.resize(atomCount);
  tree.greatgrandparent.resize(atomCount);

  // Initialize all to -1 (invalid index)
  for (Index i = 0; i < atomCount; ++i) {
    tree.parent[i] = static_cast<Index>(-1);
    tree.grandparent[i] = static_cast<Index>(-1);
    tree.greatgrandparent[i] = static_cast<Index>(-1);
  }

  // Get connected components from the molecule's graph
  const Graph& graph = molecule.graph();
  std::vector<std::set<size_t>> components = graph.connectedComponents();

  // Process each connected component separately
  for (const auto& component : components) {
    if (component.empty())
      continue;

    // Pick the first atom in this component as root
    Index root = *component.begin();

    // BFS from this root
    std::vector<bool> visited(atomCount, false);
    std::vector<Index> queue;
    queue.push_back(root);
    visited[root] = true;

    while (!queue.empty()) {
      Index current = queue.front();
      queue.erase(queue.begin());

      // Get neighbors from the graph
      std::vector<size_t> neighborIndices = graph.neighbors(current);

      for (Index neighbor : neighborIndices) {
        if (!visited[neighbor]) {
          visited[neighbor] = true;
          tree.parent[neighbor] = current;

          // Set grandparent if parent has a parent
          if (tree.parent[current] != static_cast<Index>(-1)) {
            tree.grandparent[neighbor] = tree.parent[current];

            // Set great-grandparent if grandparent has a parent
            Index grandparentIdx = tree.parent[current];
            if (tree.parent[grandparentIdx] != static_cast<Index>(-1)) {
              tree.greatgrandparent[neighbor] = tree.parent[grandparentIdx];
            }
          }

          queue.push_back(neighbor);
        }
      }
    }
  }

  return tree;
}

Array<InternalCoordinate> cartesianToInternal(const Molecule& molecule)
{
  Array<InternalCoordinate> internalCoords(molecule.atomCount());

  if (molecule.atomCount() < 1)
    return internalCoords;

  // Build connectivity tree using the molecule's graph
  ConnectivityTree tree = buildConnectivityTree(molecule);

  // Convert each atom to internal coordinates based on tree
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    InternalCoordinate coord;
    coord.a = tree.parent[i];
    coord.b = tree.grandparent[i];
    coord.c = tree.greatgrandparent[i];

    if (tree.parent[i] == static_cast<Index>(-1)) {
      // Root of a fragment - place at origin
      coord.length = 0.0;
      coord.angle = 0.0;
      coord.dihedral = 0.0;
    } else {
      // Calculate distance from i to parent (atom a)
      Vector3 vec_i_to_a = molecule.atom(tree.parent[i]).position3d() -
                           molecule.atom(i).position3d();
      coord.length = vec_i_to_a.norm();

      if (tree.grandparent[i] == static_cast<Index>(-1)) {
        // Second atom in fragment - has distance only
        coord.angle = 0.0;
        coord.dihedral = 0.0;
      } else {
        // Calculate angle i-a-b (at atom a, between i-a and a-b bonds)
        Index a = tree.parent[i];
        Index b = tree.grandparent[i];

        Vector3 vec_a_to_i = -vec_i_to_a; // from a to i
        Vector3 vec_a_to_b =
          molecule.atom(b).position3d() - molecule.atom(a).position3d();

        Real dot = vec_a_to_i.dot(vec_a_to_b);
        Real len_product = vec_a_to_i.norm() * vec_a_to_b.norm();

        if (len_product > 1e-8) {
          Real cosAngle = dot / len_product;
          // Clamp to avoid numerical issues with acos
          cosAngle = std::clamp(cosAngle, -1.0, 1.0);
          coord.angle = std::acos(cosAngle) * RAD_TO_DEG;
        } else {
          coord.angle = 0.0;
        }

        if (tree.greatgrandparent[i] == static_cast<Index>(-1)) {
          // Third atom in fragment - has distance and angle only
          coord.dihedral = 0.0;
        } else {
          // Calculate dihedral i-a-b-c
          Index c = tree.greatgrandparent[i];

          Vector3 p_i = molecule.atom(i).position3d();
          Vector3 p_a = molecule.atom(a).position3d();
          Vector3 p_b = molecule.atom(b).position3d();
          Vector3 p_c = molecule.atom(c).position3d();

          // Vectors along bonds
          Vector3 b1 = p_a - p_i; // i -> a
          Vector3 b2 = p_b - p_a; // a -> b
          Vector3 b3 = p_c - p_b; // b -> c

          // Normals to planes
          Vector3 n1 = b1.cross(b2); // plane containing i-a-b
          Vector3 n2 = b2.cross(b3); // plane containing a-b-c

          Real n1_norm = n1.norm();
          Real n2_norm = n2.norm();

          if (n1_norm > 1e-8 && n2_norm > 1e-8) {
            n1 = n1 / n1_norm;
            n2 = n2 / n2_norm;

            Real cos_dihedral = n1.dot(n2);
            // Clamp to avoid numerical issues
            cos_dihedral = std::clamp(cos_dihedral, -1.0, 1.0);

            // Determine sign using triple product
            Real sign = (n1.cross(n2)).dot(b2);

            coord.dihedral = std::acos(cos_dihedral) * RAD_TO_DEG;
            if (sign < 0) {
              coord.dihedral = -coord.dihedral;
            }
          } else {
            // Atoms are collinear
            coord.dihedral = 0.0;
          }
        }
      }
    }

    internalCoords[i] = coord;
  }

  return internalCoords;
}

} // end namespace Avogadro::Core
