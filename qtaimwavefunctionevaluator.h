/**********************************************************************
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.
 **********************************************************************/

#ifndef QTAIMWAVEFUNCTIONEVALUATOR_H
#define QTAIMWAVEFUNCTIONEVALUATOR_H

#include "qtaimwavefunction.h"

#include <Eigen/Eigen>

using namespace Eigen;

namespace Avogadro
{

  class QTAIMWavefunction;

  class QTAIMWavefunctionEvaluator
  {
  public:
    EIGEN_MAKE_ALIGNED_OPERATOR_NEW

    explicit QTAIMWavefunctionEvaluator(QTAIMWavefunction &wfn);

    const qreal molecularOrbital(const qint64 mo, const Matrix<qreal,3,1> xyz);
    const qreal electronDensity(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,1> gradientOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,3> hessianOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,4> gradientAndHessianOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const qreal laplacianOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const qreal electronDensityLaplacian(const Matrix<qreal,3,1> xyz) {return laplacianOfElectronDensity(xyz);}
    const Matrix<qreal,3,1> gradientOfElectronDensityLaplacian(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,3> hessianOfElectronDensityLaplacian(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,4> gradientAndHessianOfElectronDensityLaplacian(const Matrix<qreal,3,1> xyz);
    const qreal kineticEnergyDensityG(const Matrix<qreal,3,1> xyz);
    const qreal kineticEnergyDensityK(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,3> quantumStressTensor(const Matrix<qreal,3,1> xyz);

  private:
    qint64 m_nmo;
    qint64 m_nprim;
    qint64 m_nnuc;
    //    qint64 m_noccmo; // number of (significantly) occupied molecular orbitals
    Matrix<qreal,Dynamic,1> m_nucxcoord;
    Matrix<qreal,Dynamic,1> m_nucycoord;
    Matrix<qreal,Dynamic,1> m_nuczcoord;
    Matrix<qint64,Dynamic,1> m_nucz;
    Matrix<qreal,Dynamic,1> m_X0;
    Matrix<qreal,Dynamic,1> m_Y0;
    Matrix<qreal,Dynamic,1> m_Z0;
    Matrix<qint64,Dynamic,1> m_xamom;
    Matrix<qint64,Dynamic,1> m_yamom;
    Matrix<qint64,Dynamic,1> m_zamom;
    Matrix<qreal,Dynamic,1> m_alpha;
    Matrix<qreal,Dynamic,1> m_occno;
    Matrix<qreal,Dynamic,1> m_orbe;
    Matrix<qreal,Dynamic,Dynamic,RowMajor> m_coef;
    qreal m_totalEnergy;
    qreal m_virialRatio;

    qreal m_cutoff;

    Matrix<qreal,Dynamic,1> m_cdg000;
    Matrix<qreal,Dynamic,1> m_cdg100;
    Matrix<qreal,Dynamic,1> m_cdg010;
    Matrix<qreal,Dynamic,1> m_cdg001;
    Matrix<qreal,Dynamic,1> m_cdg200;
    Matrix<qreal,Dynamic,1> m_cdg110;
    Matrix<qreal,Dynamic,1> m_cdg101;
    Matrix<qreal,Dynamic,1> m_cdg020;
    Matrix<qreal,Dynamic,1> m_cdg011;
    Matrix<qreal,Dynamic,1> m_cdg002;
    Matrix<qreal,Dynamic,1> m_cdg300;
    Matrix<qreal,Dynamic,1> m_cdg120;
    Matrix<qreal,Dynamic,1> m_cdg102;
    Matrix<qreal,Dynamic,1> m_cdg210;
    Matrix<qreal,Dynamic,1> m_cdg030;
    Matrix<qreal,Dynamic,1> m_cdg012;
    Matrix<qreal,Dynamic,1> m_cdg201;
    Matrix<qreal,Dynamic,1> m_cdg021;
    Matrix<qreal,Dynamic,1> m_cdg003;
    Matrix<qreal,Dynamic,1> m_cdg111;
    Matrix<qreal,Dynamic,1> m_cdg400;
    Matrix<qreal,Dynamic,1> m_cdg220;
    Matrix<qreal,Dynamic,1> m_cdg202;
    Matrix<qreal,Dynamic,1> m_cdg310;
    Matrix<qreal,Dynamic,1> m_cdg130;
    Matrix<qreal,Dynamic,1> m_cdg112;
    Matrix<qreal,Dynamic,1> m_cdg301;
    Matrix<qreal,Dynamic,1> m_cdg121;
    Matrix<qreal,Dynamic,1> m_cdg103;
    Matrix<qreal,Dynamic,1> m_cdg040;
    Matrix<qreal,Dynamic,1> m_cdg022;
    Matrix<qreal,Dynamic,1> m_cdg211;
    Matrix<qreal,Dynamic,1> m_cdg031;
    Matrix<qreal,Dynamic,1> m_cdg013;
    Matrix<qreal,Dynamic,1> m_cdg004;

    static inline qreal ipow(qreal a, qint64 n)
    {
      return (qreal) pow( a, (int) n );
    }

  };

} // namespace Avogadro

#endif // QTAIMWAVEFUNCTIONEVALUATOR_H
