/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "qtaimengine.h"

#include <avogadro/qtgui/molecule.h>

#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QDebug>

using namespace Avogadro;
using namespace Avogadro::Rendering;

namespace Avogadro::QtPlugins {

QTAIMEngine::QTAIMEngine(QObject* aParent)
  : QtGui::ScenePlugin(aParent), m_enabled(false)
{
}

void QTAIMEngine::process(const QtGui::Molecule& molecule,
                          Rendering::GroupNode& node)
{
  // Create sphere/cylinder nodes.
  auto* geometry = new GeometryNode;
  node.addChild(geometry);
  auto* spheres = new SphereGeometry;
  geometry->addDrawable(spheres);
  auto* cylinders = new CylinderGeometry;
  geometry->addDrawable(cylinders);

  // Render the bond paths
  if (molecule.property("QTAIMFirstNCPIndexVariantList").isValid() &&
      molecule.property("QTAIMSecondNCPIndexVariantList").isValid() &&
      molecule.property("QTAIMLaplacianAtBondCriticalPoints").isValid() &&
      molecule.property("QTAIMEllipticityAtBondCriticalPoints").isValid() &&
      molecule.property("QTAIMBondPathSegmentStartIndex").isValid() &&
      molecule.property("QTAIMBondPathSegmentEndIndex").isValid() &&
      molecule.property("QTAIMXBondPaths").isValid() &&
      molecule.property("QTAIMYBondPaths").isValid() &&
      molecule.property("QTAIMZBondPaths").isValid()) {
    QVariant firstNCPIndexVariant =
      molecule.property("QTAIMFirstNCPIndexVariantList");
    QVariant secondNCPIndexVariant =
      molecule.property("QTAIMSecondNCPIndexVariantList");
    QVariant laplacianAtBondCriticalPointsVariant =
      molecule.property("QTAIMLaplacianAtBondCriticalPoints");
    QVariant ellipticityAtBondCriticalPointsVariant =
      molecule.property("QTAIMEllipticityAtBondCriticalPoints");
    QVariant bondPathSegmentStartIndexVariant =
      molecule.property("QTAIMBondPathSegmentStartIndex");
    QVariant bondPathSegmentEndIndexVariant =
      molecule.property("QTAIMBondPathSegmentEndIndex");
    QVariant xBondPathsVariant = molecule.property("QTAIMXBondPaths");
    QVariant yBondPathsVariant = molecule.property("QTAIMYBondPaths");
    QVariant zBondPathsVariant = molecule.property("QTAIMZBondPaths");

    QVariantList firstNCPIndexVariantList = firstNCPIndexVariant.toList();
    QVariantList secondNCPIndexVariantList = secondNCPIndexVariant.toList();
    QVariantList laplacianAtBondCriticalPointsVariantList =
      laplacianAtBondCriticalPointsVariant.toList();
    QVariantList ellipticityAtBondCriticalPointsVariantList =
      ellipticityAtBondCriticalPointsVariant.toList();
    QVariantList bondPathSegmentStartIndexVariantList =
      bondPathSegmentStartIndexVariant.toList();
    QVariantList bondPathSegmentEndIndexVariantList =
      bondPathSegmentEndIndexVariant.toList();
    QVariantList xBondPathsVariantList = xBondPathsVariant.toList();
    QVariantList yBondPathsVariantList = yBondPathsVariant.toList();
    QVariantList zBondPathsVariantList = zBondPathsVariant.toList();

    for (qint64 i = 0; i < firstNCPIndexVariantList.length(); ++i) {

      qint64 start = bondPathSegmentStartIndexVariantList.at(i).toLongLong();
      qint64 end = bondPathSegmentEndIndexVariantList.at(i).toLongLong();

      if (laplacianAtBondCriticalPointsVariantList.at(i).toReal() > 0.0) {

        const qint64 step = 4;

        Vector3f xyz;
        Vector3ub color(255, 255, 255);
        for (qint64 j = start; j < end - 1; j = j + step) {
          xyz << xBondPathsVariantList.at(j).toFloat(),
            yBondPathsVariantList.at(j).toFloat(),
            zBondPathsVariantList.at(j).toFloat();
          spheres->addSphere(xyz, color, 0.025f);
        }
      } else {

        const qint64 step = 1;

        Vector3ub color(255, 255, 255);
        double radius = 0.025;

        Vector3f v1;
        Vector3f v2;
        Vector3f direction;
        for (qint64 j = start; j < end - 1; j = j + step) {

          v1 << xBondPathsVariantList.at(j).toFloat(),
            yBondPathsVariantList.at(j).toFloat(),
            zBondPathsVariantList.at(j).toFloat();
          v2 << xBondPathsVariantList.at(j + 1).toFloat(),
            yBondPathsVariantList.at(j + 1).toFloat(),
            zBondPathsVariantList.at(j + 1).toFloat();

          direction = v2 - v1;
          float length = direction.norm();
          direction /= length;

          cylinders->addCylinder(v1, v2, radius, color);
        }
      }
    } // bond path
  }

  if (molecule.property("QTAIMXNuclearCriticalPoints").isValid() &&
      molecule.property("QTAIMYNuclearCriticalPoints").isValid() &&
      molecule.property("QTAIMZNuclearCriticalPoints").isValid()) {
    QVariant xNuclearCriticalPointsVariant =
      molecule.property("QTAIMXNuclearCriticalPoints");
    QVariant yNuclearCriticalPointsVariant =
      molecule.property("QTAIMYNuclearCriticalPoints");
    QVariant zNuclearCriticalPointsVariant =
      molecule.property("QTAIMZNuclearCriticalPoints");
    QVariantList xNuclearCriticalPointsVariantList =
      xNuclearCriticalPointsVariant.toList();
    QVariantList yNuclearCriticalPointsVariantList =
      yNuclearCriticalPointsVariant.toList();
    QVariantList zNuclearCriticalPointsVariantList =
      zNuclearCriticalPointsVariant.toList();
    if (xNuclearCriticalPointsVariantList.length() ==
          yNuclearCriticalPointsVariantList.length() &&
        xNuclearCriticalPointsVariantList.length() ==
          zNuclearCriticalPointsVariantList.length()) {
      Vector3f xyz;
      Vector3ub color(255, 64, 255);
      for (qint64 i = 0; i < xNuclearCriticalPointsVariantList.length(); ++i) {
        xyz << xNuclearCriticalPointsVariantList.at(i).toFloat(),
          yNuclearCriticalPointsVariantList.at(i).toFloat(),
          zNuclearCriticalPointsVariantList.at(i).toFloat();

        // map->setFromPrimitive(ncp);

        spheres->addSphere(xyz, color, 0.1f);
      }
    }
  }

  if (molecule.property("QTAIMXBondCriticalPoints").isValid() &&
      molecule.property("QTAIMYBondCriticalPoints").isValid() &&
      molecule.property("QTAIMZBondCriticalPoints").isValid()) {
    QVariant xBondCriticalPointsVariant =
      molecule.property("QTAIMXBondCriticalPoints");
    QVariant yBondCriticalPointsVariant =
      molecule.property("QTAIMYBondCriticalPoints");
    QVariant zBondCriticalPointsVariant =
      molecule.property("QTAIMZBondCriticalPoints");
    QVariantList xBondCriticalPointsVariantList =
      xBondCriticalPointsVariant.toList();
    QVariantList yBondCriticalPointsVariantList =
      yBondCriticalPointsVariant.toList();
    QVariantList zBondCriticalPointsVariantList =
      zBondCriticalPointsVariant.toList();
    if (xBondCriticalPointsVariantList.length() ==
          yBondCriticalPointsVariantList.length() &&
        xBondCriticalPointsVariantList.length() ==
          zBondCriticalPointsVariantList.length()) {
      Vector3ub color(255, 255, 32);
      Vector3f xyz;
      for (qint64 i = 0; i < xBondCriticalPointsVariantList.length(); ++i) {
        xyz << xBondCriticalPointsVariantList.at(i).toFloat(),
          yBondCriticalPointsVariantList.at(i).toFloat(),
          zBondCriticalPointsVariantList.at(i).toFloat();

        // map->setFromPrimitive(ncp);

        spheres->addSphere(xyz, color, 0.1f);
      }
    }
  }

  if (molecule.property("QTAIMXElectronDensitySources").isValid() &&
      molecule.property("QTAIMYElectronDensitySources").isValid() &&
      molecule.property("QTAIMZElectronDensitySources").isValid()) {
    QVariant xElectronDensitySourcesVariant =
      molecule.property("QTAIMXElectronDensitySources");
    QVariant yElectronDensitySourcesVariant =
      molecule.property("QTAIMYElectronDensitySources");
    QVariant zElectronDensitySourcesVariant =
      molecule.property("QTAIMZElectronDensitySources");
    QVariantList xElectronDensitySourcesVariantList =
      xElectronDensitySourcesVariant.toList();
    QVariantList yElectronDensitySourcesVariantList =
      yElectronDensitySourcesVariant.toList();
    QVariantList zElectronDensitySourcesVariantList =
      zElectronDensitySourcesVariant.toList();
    if (xElectronDensitySourcesVariantList.length() ==
          yElectronDensitySourcesVariantList.length() &&
        xElectronDensitySourcesVariantList.length() ==
          zElectronDensitySourcesVariantList.length()) {
      Vector3ub color(64, 64, 255);
      Vector3f xyz;
      for (qint64 i = 0; i < xElectronDensitySourcesVariantList.length(); ++i) {
        xyz << xElectronDensitySourcesVariantList.at(i).toFloat(),
          yElectronDensitySourcesVariantList.at(i).toFloat(),
          zElectronDensitySourcesVariantList.at(i).toFloat();

        // map->setFromPrimitive(ncp);

        spheres->addSphere(xyz, color, 0.1f);
      }
    }
  }
}

} // end namespace Avogadro
