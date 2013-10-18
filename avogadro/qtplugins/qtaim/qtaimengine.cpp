/**********************************************************************
  QTAIMEngine - Dynamic detail engine for QTAIM display

  Copyright (C) 2007 Donald Ephraim Curtis
  Copyright (C) 2010 Eric C. Brown

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  Avogadro is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Avogadro is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.
 **********************************************************************/

#include "qtaimengine.h"

#include <avogadro/camera.h>
#include <avogadro/painter.h>
#include <avogadro/painterdevice.h>
#include <avogadro/color.h>

#include <avogadro/atom.h>
#include <avogadro/bond.h>
#include <avogadro/molecule.h>

#include <QGLWidget> // for OpenGL bits
#include <QDebug>

#include <openbabel/mol.h>

using namespace std;
using namespace Eigen;

namespace Avogadro
{
  QTAIMEngine::QTAIMEngine(QObject *parent) : Engine(parent),
      m_settingsWidget(0), m_atomRadiusPercentage(0.3), m_bondRadius(0.1),
      m_atomRadiusType(1), m_alpha(1.)
  {  }

  Engine *QTAIMEngine::clone() const
  {
    QTAIMEngine *engine = new QTAIMEngine(parent());
    engine->setAlias(alias());
    engine->m_atomRadiusPercentage = m_atomRadiusPercentage;
    engine->m_bondRadius = m_bondRadius;
    engine->m_atomRadiusType = m_atomRadiusType;
    engine->m_alpha = m_alpha;
    engine->setEnabled(isEnabled());

    return engine;
  }

  QTAIMEngine::~QTAIMEngine()
  {
    if ( m_settingsWidget ) {
      m_settingsWidget->deleteLater();
    }
  }

  bool QTAIMEngine::renderOpaque( PainterDevice *pd )
  {
//    glPushAttrib( GL_TRANSFORM_BIT );

    // Render the opaque balls & sticks if m_alpha is 1
    if (m_alpha < 0.999) {
      return true;
    }
    Color *map = colorMap(); // possible custom color map
    if (!map) map = pd->colorMap(); // fall back to global color map

    // Render the bond paths
    if(
        m_molecule->property("QTAIMFirstNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMSecondNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMLaplacianAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMEllipticityAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentStartIndex").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentEndIndex").isValid() &&
        m_molecule->property("QTAIMXBondPaths").isValid() &&
        m_molecule->property("QTAIMYBondPaths").isValid() &&
        m_molecule->property("QTAIMZBondPaths").isValid()
        )
    {
      QVariant firstNCPIndexVariant=m_molecule->property("QTAIMFirstNCPIndexVariantList");
      QVariant secondNCPIndexVariant=m_molecule->property("QTAIMSecondNCPIndexVariantList");
      QVariant laplacianAtBondCriticalPointsVariant=m_molecule->property("QTAIMLaplacianAtBondCriticalPoints");
      QVariant ellipticityAtBondCriticalPointsVariant=m_molecule->property("QTAIMEllipticityAtBondCriticalPoints");
      QVariant bondPathSegmentStartIndexVariant=m_molecule->property("QTAIMBondPathSegmentStartIndex");
      QVariant bondPathSegmentEndIndexVariant=m_molecule->property("QTAIMBondPathSegmentEndIndex");
      QVariant xBondPathsVariant=m_molecule->property("QTAIMXBondPaths");
      QVariant yBondPathsVariant=m_molecule->property("QTAIMYBondPaths");
      QVariant zBondPathsVariant=m_molecule->property("QTAIMZBondPaths");

      QVariantList firstNCPIndexVariantList=firstNCPIndexVariant.toList();
      QVariantList secondNCPIndexVariantList=secondNCPIndexVariant.toList();
      QVariantList laplacianAtBondCriticalPointsVariantList=laplacianAtBondCriticalPointsVariant.toList();
      QVariantList ellipticityAtBondCriticalPointsVariantList=ellipticityAtBondCriticalPointsVariant.toList();
      QVariantList bondPathSegmentStartIndexVariantList=bondPathSegmentStartIndexVariant.toList();
      QVariantList bondPathSegmentEndIndexVariantList=bondPathSegmentEndIndexVariant.toList();
      QVariantList xBondPathsVariantList=xBondPathsVariant.toList();
      QVariantList yBondPathsVariantList=yBondPathsVariant.toList();
      QVariantList zBondPathsVariantList=zBondPathsVariant.toList();

      for( qint64 i=0 ;  i < firstNCPIndexVariantList.length() ; ++i )
      {

        qint64 start=bondPathSegmentStartIndexVariantList.at(i).toLongLong();
        qint64 end=bondPathSegmentEndIndexVariantList.at(i).toLongLong();

        if( laplacianAtBondCriticalPointsVariantList.at(i).toReal() > 0.0 )
        {

          const qint64 step=4;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {
            pd->painter()->setColor("White");
            Eigen::Vector3d xyz;
            xyz << xBondPathsVariantList.at(j).toReal(),
                   yBondPathsVariantList.at(j).toReal(),
                   zBondPathsVariantList.at(j).toReal();
            pd->painter()->drawSphere(xyz, 0.025 );
          }
        }
        else
        {

          const qint64 step=1;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {

            Eigen::Vector3d xyz0;
            xyz0 << xBondPathsVariantList.at(j).toReal(),
                    yBondPathsVariantList.at(j).toReal(),
                    zBondPathsVariantList.at(j).toReal();
            Eigen::Vector3d xyz1;
            xyz1 << xBondPathsVariantList.at(j+1).toReal(),
                    yBondPathsVariantList.at(j+1).toReal(),
                    zBondPathsVariantList.at(j+1).toReal();

            Vector3d v1(xyz0);
            Vector3d v2(xyz1);
            Vector3d v3( (v1 + v2) / 2. ) ;

            double shift = 0.15;
            int order = 1;
            double radius=0.025;

            pd->painter()->setColor("White");
            pd->painter()->drawMultiCylinder( v1, v2, radius, order, shift );
          }
        }
      }  // bond path
    }

    glDisable( GL_NORMALIZE );
    glEnable( GL_RESCALE_NORMAL );


    if( m_molecule->property("QTAIMXNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZNuclearCriticalPoints").isValid() )
    {
      QVariant xNuclearCriticalPointsVariant=m_molecule->property("QTAIMXNuclearCriticalPoints");
      QVariant yNuclearCriticalPointsVariant=m_molecule->property("QTAIMYNuclearCriticalPoints");
      QVariant zNuclearCriticalPointsVariant=m_molecule->property("QTAIMZNuclearCriticalPoints");
      QVariantList xNuclearCriticalPointsVariantList=xNuclearCriticalPointsVariant.toList();
      QVariantList yNuclearCriticalPointsVariantList=yNuclearCriticalPointsVariant.toList();
      QVariantList zNuclearCriticalPointsVariantList=zNuclearCriticalPointsVariant.toList();
      if( xNuclearCriticalPointsVariantList.length() == yNuclearCriticalPointsVariantList.length() &&
          xNuclearCriticalPointsVariantList.length() == zNuclearCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xNuclearCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xNuclearCriticalPointsVariantList.at(i).toReal(),
                 yNuclearCriticalPointsVariantList.at(i).toReal(),
                 zNuclearCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Purple");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }


    if( m_molecule->property("QTAIMXBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZBondCriticalPoints").isValid() )
    {
      QVariant xBondCriticalPointsVariant=m_molecule->property("QTAIMXBondCriticalPoints");
      QVariant yBondCriticalPointsVariant=m_molecule->property("QTAIMYBondCriticalPoints");
      QVariant zBondCriticalPointsVariant=m_molecule->property("QTAIMZBondCriticalPoints");
      QVariantList xBondCriticalPointsVariantList=xBondCriticalPointsVariant.toList();
      QVariantList yBondCriticalPointsVariantList=yBondCriticalPointsVariant.toList();
      QVariantList zBondCriticalPointsVariantList=zBondCriticalPointsVariant.toList();
      if( xBondCriticalPointsVariantList.length() == yBondCriticalPointsVariantList.length() &&
          xBondCriticalPointsVariantList.length() == zBondCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xBondCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xBondCriticalPointsVariantList.at(i).toReal(),
                 yBondCriticalPointsVariantList.at(i).toReal(),
                 zBondCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Yellow");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }

    // normalize normal vectors of bonds
    glDisable( GL_RESCALE_NORMAL );
    glEnable( GL_NORMALIZE );

    if( m_molecule->property("QTAIMXElectronDensitySources").isValid() &&
        m_molecule->property("QTAIMYElectronDensitySources").isValid() &&
        m_molecule->property("QTAIMZElectronDensitySources").isValid() )
    {
      QVariant xElectronDensitySourcesVariant=m_molecule->property("QTAIMXElectronDensitySources");
      QVariant yElectronDensitySourcesVariant=m_molecule->property("QTAIMYElectronDensitySources");
      QVariant zElectronDensitySourcesVariant=m_molecule->property("QTAIMZElectronDensitySources");
      QVariantList xElectronDensitySourcesVariantList=xElectronDensitySourcesVariant.toList();
      QVariantList yElectronDensitySourcesVariantList=yElectronDensitySourcesVariant.toList();
      QVariantList zElectronDensitySourcesVariantList=zElectronDensitySourcesVariant.toList();
      if( xElectronDensitySourcesVariantList.length() == yElectronDensitySourcesVariantList.length() &&
          xElectronDensitySourcesVariantList.length() == zElectronDensitySourcesVariantList.length() )
      {
        for( qint64 i=0 ; i < xElectronDensitySourcesVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xElectronDensitySourcesVariantList.at(i).toReal(),
                 yElectronDensitySourcesVariantList.at(i).toReal(),
                 zElectronDensitySourcesVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Blue");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }

    // normalize normal vectors of bonds
    glDisable( GL_RESCALE_NORMAL );
    glEnable( GL_NORMALIZE );


//    glPopAttrib();

    return true;
  }

  bool QTAIMEngine::renderTransparent(PainterDevice *pd)
  {
    // Render selections when not renderquick
    Color *map = colorMap();
    if (!map) map = pd->colorMap();

    // Render the bond paths
    if(
        m_molecule->property("QTAIMFirstNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMSecondNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMLaplacianAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMEllipticityAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentStartIndex").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentEndIndex").isValid() &&
        m_molecule->property("QTAIMXBondPaths").isValid() &&
        m_molecule->property("QTAIMYBondPaths").isValid() &&
        m_molecule->property("QTAIMZBondPaths").isValid()
        )
    {
      QVariant firstNCPIndexVariant=m_molecule->property("QTAIMFirstNCPIndexVariantList");
      QVariant secondNCPIndexVariant=m_molecule->property("QTAIMSecondNCPIndexVariantList");
      QVariant laplacianAtBondCriticalPointsVariant=m_molecule->property("QTAIMLaplacianAtBondCriticalPoints");
      QVariant ellipticityAtBondCriticalPointsVariant=m_molecule->property("QTAIMEllipticityAtBondCriticalPoints");
      QVariant bondPathSegmentStartIndexVariant=m_molecule->property("QTAIMBondPathSegmentStartIndex");
      QVariant bondPathSegmentEndIndexVariant=m_molecule->property("QTAIMBondPathSegmentEndIndex");
      QVariant xBondPathsVariant=m_molecule->property("QTAIMXBondPaths");
      QVariant yBondPathsVariant=m_molecule->property("QTAIMYBondPaths");
      QVariant zBondPathsVariant=m_molecule->property("QTAIMZBondPaths");

      QVariantList firstNCPIndexVariantList=firstNCPIndexVariant.toList();
      QVariantList secondNCPIndexVariantList=secondNCPIndexVariant.toList();
      QVariantList laplacianAtBondCriticalPointsVariantList=laplacianAtBondCriticalPointsVariant.toList();
      QVariantList ellipticityAtBondCriticalPointsVariantList=ellipticityAtBondCriticalPointsVariant.toList();
      QVariantList bondPathSegmentStartIndexVariantList=bondPathSegmentStartIndexVariant.toList();
      QVariantList bondPathSegmentEndIndexVariantList=bondPathSegmentEndIndexVariant.toList();
      QVariantList xBondPathsVariantList=xBondPathsVariant.toList();
      QVariantList yBondPathsVariantList=yBondPathsVariant.toList();
      QVariantList zBondPathsVariantList=zBondPathsVariant.toList();

      for( qint64 i=0 ;  i < firstNCPIndexVariantList.length() ; ++i )
      {

        qint64 start=bondPathSegmentStartIndexVariantList.at(i).toLongLong();
        qint64 end=bondPathSegmentEndIndexVariantList.at(i).toLongLong();

        if( laplacianAtBondCriticalPointsVariantList.at(i).toReal() > 0.0 )
        {

          const qint64 step=4;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {
            pd->painter()->setColor("White");
            Eigen::Vector3d xyz;
            xyz << xBondPathsVariantList.at(j).toReal(),
                   yBondPathsVariantList.at(j).toReal(),
                   zBondPathsVariantList.at(j).toReal();
            pd->painter()->drawSphere(xyz, 0.025 );
          }
        }
        else
        {

          const qint64 step=1;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {

            Eigen::Vector3d xyz0;
            xyz0 << xBondPathsVariantList.at(j).toReal(),
                    yBondPathsVariantList.at(j).toReal(),
                    zBondPathsVariantList.at(j).toReal();
            Eigen::Vector3d xyz1;
            xyz1 << xBondPathsVariantList.at(j+1).toReal(),
                    yBondPathsVariantList.at(j+1).toReal(),
                    zBondPathsVariantList.at(j+1).toReal();

            Vector3d v1(xyz0);
            Vector3d v2(xyz1);
            Vector3d v3( (v1 + v2) / 2. ) ;

            double shift = 0.15;
            int order = 1;
            double radius=0.025;

            pd->painter()->setColor("White");
            pd->painter()->drawMultiCylinder( v1, v2, radius, order, shift );
          }
        }
      }  // bond path
    }

    glDisable( GL_NORMALIZE );
    glEnable( GL_RESCALE_NORMAL );


    if( m_molecule->property("QTAIMXNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZNuclearCriticalPoints").isValid() )
    {
      QVariant xNuclearCriticalPointsVariant=m_molecule->property("QTAIMXNuclearCriticalPoints");
      QVariant yNuclearCriticalPointsVariant=m_molecule->property("QTAIMYNuclearCriticalPoints");
      QVariant zNuclearCriticalPointsVariant=m_molecule->property("QTAIMZNuclearCriticalPoints");
      QVariantList xNuclearCriticalPointsVariantList=xNuclearCriticalPointsVariant.toList();
      QVariantList yNuclearCriticalPointsVariantList=yNuclearCriticalPointsVariant.toList();
      QVariantList zNuclearCriticalPointsVariantList=zNuclearCriticalPointsVariant.toList();
      if( xNuclearCriticalPointsVariantList.length() == yNuclearCriticalPointsVariantList.length() &&
          xNuclearCriticalPointsVariantList.length() == zNuclearCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xNuclearCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xNuclearCriticalPointsVariantList.at(i).toReal(),
                 yNuclearCriticalPointsVariantList.at(i).toReal(),
                 zNuclearCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Purple");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }


    if( m_molecule->property("QTAIMXBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZBondCriticalPoints").isValid() )
    {
      QVariant xBondCriticalPointsVariant=m_molecule->property("QTAIMXBondCriticalPoints");
      QVariant yBondCriticalPointsVariant=m_molecule->property("QTAIMYBondCriticalPoints");
      QVariant zBondCriticalPointsVariant=m_molecule->property("QTAIMZBondCriticalPoints");
      QVariantList xBondCriticalPointsVariantList=xBondCriticalPointsVariant.toList();
      QVariantList yBondCriticalPointsVariantList=yBondCriticalPointsVariant.toList();
      QVariantList zBondCriticalPointsVariantList=zBondCriticalPointsVariant.toList();
      if( xBondCriticalPointsVariantList.length() == yBondCriticalPointsVariantList.length() &&
          xBondCriticalPointsVariantList.length() == zBondCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xBondCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xBondCriticalPointsVariantList.at(i).toReal(),
                 yBondCriticalPointsVariantList.at(i).toReal(),
                 zBondCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Yellow");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }

    // normalize normal vectors of bonds
    glDisable( GL_RESCALE_NORMAL );
    glEnable( GL_NORMALIZE );

//    glPopAttrib();

    return true;
  }

  bool QTAIMEngine::renderQuick(PainterDevice *pd)
  {
    Color *map = colorMap(); // possible custom color map
    if (!map) map = pd->colorMap(); // fall back to global color map
    Color cSel;
    cSel.setToSelectionColor();

    // Render the bond paths
    if(
        m_molecule->property("QTAIMFirstNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMSecondNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMLaplacianAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMEllipticityAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentStartIndex").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentEndIndex").isValid() &&
        m_molecule->property("QTAIMXBondPaths").isValid() &&
        m_molecule->property("QTAIMYBondPaths").isValid() &&
        m_molecule->property("QTAIMZBondPaths").isValid()
        )
    {
      QVariant firstNCPIndexVariant=m_molecule->property("QTAIMFirstNCPIndexVariantList");
      QVariant secondNCPIndexVariant=m_molecule->property("QTAIMSecondNCPIndexVariantList");
      QVariant laplacianAtBondCriticalPointsVariant=m_molecule->property("QTAIMLaplacianAtBondCriticalPoints");
      QVariant ellipticityAtBondCriticalPointsVariant=m_molecule->property("QTAIMEllipticityAtBondCriticalPoints");
      QVariant bondPathSegmentStartIndexVariant=m_molecule->property("QTAIMBondPathSegmentStartIndex");
      QVariant bondPathSegmentEndIndexVariant=m_molecule->property("QTAIMBondPathSegmentEndIndex");
      QVariant xBondPathsVariant=m_molecule->property("QTAIMXBondPaths");
      QVariant yBondPathsVariant=m_molecule->property("QTAIMYBondPaths");
      QVariant zBondPathsVariant=m_molecule->property("QTAIMZBondPaths");

      QVariantList firstNCPIndexVariantList=firstNCPIndexVariant.toList();
      QVariantList secondNCPIndexVariantList=secondNCPIndexVariant.toList();
      QVariantList laplacianAtBondCriticalPointsVariantList=laplacianAtBondCriticalPointsVariant.toList();
      QVariantList ellipticityAtBondCriticalPointsVariantList=ellipticityAtBondCriticalPointsVariant.toList();
      QVariantList bondPathSegmentStartIndexVariantList=bondPathSegmentStartIndexVariant.toList();
      QVariantList bondPathSegmentEndIndexVariantList=bondPathSegmentEndIndexVariant.toList();
      QVariantList xBondPathsVariantList=xBondPathsVariant.toList();
      QVariantList yBondPathsVariantList=yBondPathsVariant.toList();
      QVariantList zBondPathsVariantList=zBondPathsVariant.toList();

      for( qint64 i=0 ;  i < firstNCPIndexVariantList.length() ; ++i )
      {

        qint64 start=bondPathSegmentStartIndexVariantList.at(i).toLongLong();
        qint64 end=bondPathSegmentEndIndexVariantList.at(i).toLongLong();

        if( laplacianAtBondCriticalPointsVariantList.at(i).toReal() > 0.0 )
        {

          const qint64 step=4;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {
            pd->painter()->setColor("White");
            Eigen::Vector3d xyz;
            xyz << xBondPathsVariantList.at(j).toReal(),
                   yBondPathsVariantList.at(j).toReal(),
                   zBondPathsVariantList.at(j).toReal();
            pd->painter()->drawSphere(xyz, 0.025 );
          }
        }
        else
        {

          const qint64 step=1;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {

            Eigen::Vector3d xyz0;
            xyz0 << xBondPathsVariantList.at(j).toReal(),
                    yBondPathsVariantList.at(j).toReal(),
                    zBondPathsVariantList.at(j).toReal();
            Eigen::Vector3d xyz1;
            xyz1 << xBondPathsVariantList.at(j+1).toReal(),
                    yBondPathsVariantList.at(j+1).toReal(),
                    zBondPathsVariantList.at(j+1).toReal();

            Vector3d v1(xyz0);
            Vector3d v2(xyz1);
            Vector3d v3( (v1 + v2) / 2. ) ;

            double shift = 0.15;
            int order = 1;
            double radius=0.025;

            pd->painter()->setColor("White");
            pd->painter()->drawMultiCylinder( v1, v2, radius, order, shift );
          }
        }
      }  // bond path
    }

    glDisable( GL_NORMALIZE );
    glEnable( GL_RESCALE_NORMAL );


    if( m_molecule->property("QTAIMXNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZNuclearCriticalPoints").isValid() )
    {
      QVariant xNuclearCriticalPointsVariant=m_molecule->property("QTAIMXNuclearCriticalPoints");
      QVariant yNuclearCriticalPointsVariant=m_molecule->property("QTAIMYNuclearCriticalPoints");
      QVariant zNuclearCriticalPointsVariant=m_molecule->property("QTAIMZNuclearCriticalPoints");
      QVariantList xNuclearCriticalPointsVariantList=xNuclearCriticalPointsVariant.toList();
      QVariantList yNuclearCriticalPointsVariantList=yNuclearCriticalPointsVariant.toList();
      QVariantList zNuclearCriticalPointsVariantList=zNuclearCriticalPointsVariant.toList();
      if( xNuclearCriticalPointsVariantList.length() == yNuclearCriticalPointsVariantList.length() &&
          xNuclearCriticalPointsVariantList.length() == zNuclearCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xNuclearCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xNuclearCriticalPointsVariantList.at(i).toReal(),
                 yNuclearCriticalPointsVariantList.at(i).toReal(),
                 zNuclearCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Purple");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }


    if( m_molecule->property("QTAIMXBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZBondCriticalPoints").isValid() )
    {
      QVariant xBondCriticalPointsVariant=m_molecule->property("QTAIMXBondCriticalPoints");
      QVariant yBondCriticalPointsVariant=m_molecule->property("QTAIMYBondCriticalPoints");
      QVariant zBondCriticalPointsVariant=m_molecule->property("QTAIMZBondCriticalPoints");
      QVariantList xBondCriticalPointsVariantList=xBondCriticalPointsVariant.toList();
      QVariantList yBondCriticalPointsVariantList=yBondCriticalPointsVariant.toList();
      QVariantList zBondCriticalPointsVariantList=zBondCriticalPointsVariant.toList();
      if( xBondCriticalPointsVariantList.length() == yBondCriticalPointsVariantList.length() &&
          xBondCriticalPointsVariantList.length() == zBondCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xBondCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xBondCriticalPointsVariantList.at(i).toReal(),
                 yBondCriticalPointsVariantList.at(i).toReal(),
                 zBondCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Yellow");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }

    // normalize normal vectors of bonds
    glDisable( GL_RESCALE_NORMAL );
    glEnable( GL_NORMALIZE );

//    glPopAttrib();

    return true;
  }

  bool QTAIMEngine::renderPick(PainterDevice *pd)
  {
    // Render selections when not renderquick
    Color *map = colorMap();
    if (!map) map = pd->colorMap();

    // Render the bond paths
    if(
        m_molecule->property("QTAIMFirstNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMSecondNCPIndexVariantList").isValid() &&
        m_molecule->property("QTAIMLaplacianAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMEllipticityAtBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentStartIndex").isValid() &&
        m_molecule->property("QTAIMBondPathSegmentEndIndex").isValid() &&
        m_molecule->property("QTAIMXBondPaths").isValid() &&
        m_molecule->property("QTAIMYBondPaths").isValid() &&
        m_molecule->property("QTAIMZBondPaths").isValid()
        )
    {
      QVariant firstNCPIndexVariant=m_molecule->property("QTAIMFirstNCPIndexVariantList");
      QVariant secondNCPIndexVariant=m_molecule->property("QTAIMSecondNCPIndexVariantList");
      QVariant laplacianAtBondCriticalPointsVariant=m_molecule->property("QTAIMLaplacianAtBondCriticalPoints");
      QVariant ellipticityAtBondCriticalPointsVariant=m_molecule->property("QTAIMEllipticityAtBondCriticalPoints");
      QVariant bondPathSegmentStartIndexVariant=m_molecule->property("QTAIMBondPathSegmentStartIndex");
      QVariant bondPathSegmentEndIndexVariant=m_molecule->property("QTAIMBondPathSegmentEndIndex");
      QVariant xBondPathsVariant=m_molecule->property("QTAIMXBondPaths");
      QVariant yBondPathsVariant=m_molecule->property("QTAIMYBondPaths");
      QVariant zBondPathsVariant=m_molecule->property("QTAIMZBondPaths");

      QVariantList firstNCPIndexVariantList=firstNCPIndexVariant.toList();
      QVariantList secondNCPIndexVariantList=secondNCPIndexVariant.toList();
      QVariantList laplacianAtBondCriticalPointsVariantList=laplacianAtBondCriticalPointsVariant.toList();
      QVariantList ellipticityAtBondCriticalPointsVariantList=ellipticityAtBondCriticalPointsVariant.toList();
      QVariantList bondPathSegmentStartIndexVariantList=bondPathSegmentStartIndexVariant.toList();
      QVariantList bondPathSegmentEndIndexVariantList=bondPathSegmentEndIndexVariant.toList();
      QVariantList xBondPathsVariantList=xBondPathsVariant.toList();
      QVariantList yBondPathsVariantList=yBondPathsVariant.toList();
      QVariantList zBondPathsVariantList=zBondPathsVariant.toList();

      for( qint64 i=0 ;  i < firstNCPIndexVariantList.length() ; ++i )
      {

        qint64 start=bondPathSegmentStartIndexVariantList.at(i).toLongLong();
        qint64 end=bondPathSegmentEndIndexVariantList.at(i).toLongLong();

        if( laplacianAtBondCriticalPointsVariantList.at(i).toReal() > 0.0 )
        {

          const qint64 step=4;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {
            pd->painter()->setColor("White");
            Eigen::Vector3d xyz;
            xyz << xBondPathsVariantList.at(j).toReal(),
                   yBondPathsVariantList.at(j).toReal(),
                   zBondPathsVariantList.at(j).toReal();
            pd->painter()->drawSphere(xyz, 0.025 );
          }
        }
        else
        {

          const qint64 step=1;

          for( qint64 j=start ; j < end-1 ; j=j+step )
          {

            Eigen::Vector3d xyz0;
            xyz0 << xBondPathsVariantList.at(j).toReal(),
                    yBondPathsVariantList.at(j).toReal(),
                    zBondPathsVariantList.at(j).toReal();
            Eigen::Vector3d xyz1;
            xyz1 << xBondPathsVariantList.at(j+1).toReal(),
                    yBondPathsVariantList.at(j+1).toReal(),
                    zBondPathsVariantList.at(j+1).toReal();

            Vector3d v1(xyz0);
            Vector3d v2(xyz1);
            Vector3d v3( (v1 + v2) / 2. ) ;

            double shift = 0.15;
            int order = 1;
            double radius=0.025;

            pd->painter()->setColor("White");
            pd->painter()->drawMultiCylinder( v1, v2, radius, order, shift );
          }
        }
      }  // bond path
    }

    glDisable( GL_NORMALIZE );
    glEnable( GL_RESCALE_NORMAL );


    if( m_molecule->property("QTAIMXNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYNuclearCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZNuclearCriticalPoints").isValid() )
    {
      QVariant xNuclearCriticalPointsVariant=m_molecule->property("QTAIMXNuclearCriticalPoints");
      QVariant yNuclearCriticalPointsVariant=m_molecule->property("QTAIMYNuclearCriticalPoints");
      QVariant zNuclearCriticalPointsVariant=m_molecule->property("QTAIMZNuclearCriticalPoints");
      QVariantList xNuclearCriticalPointsVariantList=xNuclearCriticalPointsVariant.toList();
      QVariantList yNuclearCriticalPointsVariantList=yNuclearCriticalPointsVariant.toList();
      QVariantList zNuclearCriticalPointsVariantList=zNuclearCriticalPointsVariant.toList();
      if( xNuclearCriticalPointsVariantList.length() == yNuclearCriticalPointsVariantList.length() &&
          xNuclearCriticalPointsVariantList.length() == zNuclearCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xNuclearCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xNuclearCriticalPointsVariantList.at(i).toReal(),
                 yNuclearCriticalPointsVariantList.at(i).toReal(),
                 zNuclearCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Purple");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }


    if( m_molecule->property("QTAIMXBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMYBondCriticalPoints").isValid() &&
        m_molecule->property("QTAIMZBondCriticalPoints").isValid() )
    {
      QVariant xBondCriticalPointsVariant=m_molecule->property("QTAIMXBondCriticalPoints");
      QVariant yBondCriticalPointsVariant=m_molecule->property("QTAIMYBondCriticalPoints");
      QVariant zBondCriticalPointsVariant=m_molecule->property("QTAIMZBondCriticalPoints");
      QVariantList xBondCriticalPointsVariantList=xBondCriticalPointsVariant.toList();
      QVariantList yBondCriticalPointsVariantList=yBondCriticalPointsVariant.toList();
      QVariantList zBondCriticalPointsVariantList=zBondCriticalPointsVariant.toList();
      if( xBondCriticalPointsVariantList.length() == yBondCriticalPointsVariantList.length() &&
          xBondCriticalPointsVariantList.length() == zBondCriticalPointsVariantList.length() )
      {
        for( qint64 i=0 ; i < xBondCriticalPointsVariantList.length() ; ++i )
        {
          Eigen::Vector3d xyz;
          xyz << xBondCriticalPointsVariantList.at(i).toReal(),
                 yBondCriticalPointsVariantList.at(i).toReal(),
                 zBondCriticalPointsVariantList.at(i).toReal();

          // map->setFromPrimitive(ncp);

          pd->painter()->setColor("Yellow");
          pd->painter()->drawSphere(xyz, 0.1 );

        }
      }
    }

    // normalize normal vectors of bonds
    glDisable( GL_RESCALE_NORMAL );
    glEnable( GL_NORMALIZE );

//    glPopAttrib();

    return true;
  }

  // Protect globally declared functions in an anonymous namespace
  namespace
  {
    double radiusCovalent(const Atom *atom)
    {
      return OpenBabel::etab.GetCovalentRad(atom->atomicNumber());
    }

    double radiusVdW(const Atom *atom)
    {
      return OpenBabel::etab.GetVdwRad(atom->atomicNumber());
    }
  } // End of anonymous namespace

  inline double QTAIMEngine::radius(const Atom *atom) const
  {
    if (atom->customRadius())
      return atom->customRadius()* m_atomRadiusPercentage;
    else {
      if (atom->atomicNumber())
        return pRadius(atom) * m_atomRadiusPercentage;
    }
    return m_atomRadiusPercentage;
  }

  void QTAIMEngine::setAtomRadiusPercentage( int percent )
  {
    m_atomRadiusPercentage = 0.02 * percent;
    emit changed();
  }

  void QTAIMEngine::setAtomRadiusType(int type)
  {
    m_atomRadiusType = type;
    if (type == 0)
      pRadius = radiusCovalent;
    else
      pRadius = radiusVdW;
    emit changed();
  }

  void QTAIMEngine::setBondRadius( int value )
  {
    m_bondRadius = value * 0.025;
    emit changed();
  }

  void QTAIMEngine::setOpacity(int value)
  {
    m_alpha = 0.05 * value;
    emit changed();
  }

  double QTAIMEngine::radius( const PainterDevice *pd, const Primitive *p ) const
  {
    // Atom radius
    if ( p->type() == Primitive::AtomType ) {
      if ( pd ) {
        if ( pd->isSelected( p ) )
          return radius( static_cast<const Atom *>( p ) ) + SEL_ATOM_EXTRA_RADIUS;
      }
      return radius( static_cast<const Atom *>( p ) );
    }
    // Bond radius
    else if ( p->type() == Primitive::BondType ) {
      if ( pd ) {
        if ( pd->isSelected( p ) )
          return m_bondRadius + SEL_BOND_EXTRA_RADIUS;
      }
      return m_bondRadius;
    }
    // Something else
    else
      return 0.;
  }

  double QTAIMEngine::transparencyDepth() const
  {
    return m_atomRadiusPercentage;
  }

  Engine::Layers QTAIMEngine::layers() const
  {
    return Engine::Opaque | Engine::Transparent;
  }

  QWidget *QTAIMEngine::settingsWidget()
  {
    if (!m_settingsWidget) {
      m_settingsWidget = new QTAIMSettingsWidget();
      connect(m_settingsWidget->atomRadiusSlider, SIGNAL(valueChanged(int)),
              this, SLOT(setAtomRadiusPercentage(int)));
      connect(m_settingsWidget->combo_radius, SIGNAL(currentIndexChanged(int)),
              this, SLOT(setAtomRadiusType(int)));
      connect(m_settingsWidget->bondRadiusSlider, SIGNAL(valueChanged(int)),
              this, SLOT(setBondRadius(int)));
      connect(m_settingsWidget->opacitySlider, SIGNAL(valueChanged(int)),
              this, SLOT(setOpacity(int)));
      connect(m_settingsWidget, SIGNAL(destroyed()),
              this, SLOT(settingsWidgetDestroyed()));
      m_settingsWidget->atomRadiusSlider->setValue(int(50*m_atomRadiusPercentage));
      m_settingsWidget->bondRadiusSlider->setValue(int(50*m_bondRadius));
      m_settingsWidget->opacitySlider->setValue(int(20*m_alpha));
      m_settingsWidget->combo_radius->setCurrentIndex(m_atomRadiusType);
    }
    return m_settingsWidget;
  }

  void QTAIMEngine::settingsWidgetDestroyed()
  {
    qDebug() << "Destroyed Settings Widget";
    m_settingsWidget = 0;
  }

  void QTAIMEngine::writeSettings(QSettings &settings) const
  {
    Engine::writeSettings(settings);
    settings.setValue("atomRadius", 50*m_atomRadiusPercentage);
    settings.setValue("radiusType", m_atomRadiusType);
    settings.setValue("bondRadius", 50*m_bondRadius);
    settings.setValue("opacity", 20*m_alpha);
  }

  void QTAIMEngine::readSettings(QSettings &settings)
  {
    Engine::readSettings(settings);
    setAtomRadiusPercentage(settings.value("atomRadius", 25).toDouble());
    setBondRadius(settings.value("bondRadius", 4).toDouble());
    setOpacity(settings.value("opacity", 100).toInt());
    setAtomRadiusType(settings.value("radiusType", 1).toInt());

    if (m_settingsWidget) {
      m_settingsWidget->atomRadiusSlider->setValue(int(50*m_atomRadiusPercentage));
      m_settingsWidget->combo_radius->setCurrentIndex(m_atomRadiusType);
      m_settingsWidget->bondRadiusSlider->setValue(int(50*m_bondRadius));
      m_settingsWidget->opacitySlider->setValue(int(20*m_alpha));
      m_settingsWidget->combo_radius->setCurrentIndex(m_atomRadiusType);
    }
  }

}

Q_EXPORT_PLUGIN2( qtaimengine, Avogadro::QTAIMEngineFactory )
