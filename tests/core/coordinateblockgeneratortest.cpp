/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/coordinateblockgenerator.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <string>

using Avogadro::Core::CoordinateBlockGenerator;
using Avogadro::Core::Elements;
using Avogadro::Core::Molecule;
using Avogadro::Vector3;

namespace {

const std::string refCoordBlock(
    "1   0   0.0   Xx  Dummy            2.362158    4.724315    7.086473 0 1   0 1\n"
    "2   1   1.0   H   Hydrogen         4.940384    9.880769   14.821153 0 1   0 1\n"
    "3   2   2.0   He  Helium          10.667759   21.335518   32.003277 0 1   0 1\n"
    "4   3   3.0   Li  Lithium         14.840133   29.680266   44.520399 0 1   0 1\n"
    "5   4   4.0   Be  Beryllium        7.319117   14.638233   21.957350 0 1   0 1\n"
    "6   5   5.0   B   Boron            2.130417    4.260834    6.391252 0 1   0 1\n"
    "7   6   6.0   C   Carbon           2.067750    4.135500    6.203250 0 1   0 1\n"
    "8   7   7.0   N   Nitrogen         3.943171    7.886343   11.829514 0 1   0 1\n"
    "9   8   8.0   O   Oxygen           8.830173   17.660347   26.490520 0 1   0 1\n"
    "10  9   9.0   F   Fluorine        14.676794   29.353588   44.030383 0 1   0 1\n"
    "11  10  10.0  Ne  Neon            10.361507   20.723014   31.084521 0 1   0 1\n"
    "12  11  11.0  Na  Sodium           2.590478    5.180956    7.771435 0 1   0 1\n"
    "13  12  12.0  Mg  Magnesium        1.848117    3.696235    5.544352 0 1   0 1\n"
    "14  13  13.0  Al  Aluminium        3.086665    6.173329    9.259994 0 1   0 1\n"
    "15  14  14.0  Si  Silicon          6.916003   13.832007   20.748010 0 1   0 1\n"
    "16  15  15.0  P   Phosphorus      13.142397   26.284794   39.427191 0 1   0 1\n"
    "17  16  16.0  S   Sulfur          12.644257   25.288513   37.932770 0 1   0 1\n"
    "18  17  17.0  Cl  Chlorine         3.649164    7.298328   10.947493 0 1   0 1\n"
    "19  18  18.0  Ar  Argon            1.820979    3.641959    5.462938 0 1   0 1\n"
    "20  19  19.0  K   Potassium        2.549148    5.098295    7.647443 0 1   0 1\n"
    "21  20  20.0  Ca  Calcium          5.513667   11.027334   16.541001 0 1   0 1\n"
    "22  21  21.0  Sc  Scandium        11.505124   23.010248   34.515372 0 1   0 1\n"
    "23  22  22.0  Ti  Titanium        14.279570   28.559139   42.838709 0 1   0 1\n"
    "24  23  23.0  V   Vanadium         5.765799   11.531598   17.297396 0 1   0 1\n"
    "25  24  24.0  Cr  Chromium         1.985866    3.971732    5.957598 0 1   0 1\n"
    "26  25  25.0  Mn  Manganese        2.219500    4.438999    6.658499 0 1   0 1\n"
    "27  26  26.0  Fe  Iron             4.466873    8.933745   13.400618 0 1   0 1\n"
    "28  27  27.0  Co  Cobalt           9.855600   19.711200   29.566800 0 1   0 1\n"
    "29  28  28.0  Ni  Nickel          14.989439   29.978878   44.968317 0 1   0 1\n"
    "30  29  29.0  Cu  Copper           8.789299   17.578598   26.367898 0 1   0 1\n"
    "31  30  30.0  Zn  Zinc             2.302518    4.605037    6.907555 0 1   0 1\n"
    "32  31  31.0  Ga  Gallium          1.947844    3.895688    5.843532 0 1   0 1\n"
    "33  32  32.0  Ge  Germanium        3.508898    7.017796   10.526694 0 1   0 1\n"
    "34  33  33.0  As  Arsenic          7.894711   15.789422   23.684134 0 1   0 1\n"
    "35  34  34.0  Se  Selenium        14.045344   28.090688   42.136032 0 1   0 1\n"
    "36  35  35.0  Br  Bromine         11.542707   23.085414   34.628121 0 1   0 1\n"
    "37  36  36.0  Kr  Krypton          2.980571    5.961142    8.941713 0 1   0 1\n"
    "38  37  37.0  Rb  Rubidium         1.807603    3.615205    5.422808 0 1   0 1\n"
    "39  38  38.0  Sr  Strontium        2.795220    5.590440    8.385660 0 1   0 1\n"
    "40  39  39.0  Y   Yttrium          6.188045   12.376090   18.564136 0 1   0 1\n"
    "41  40  40.0  Zr  Zirconium       12.345850   24.691701   37.037551 0 1   0 1\n"
    "42  41  41.0  Nb  Niobium         13.473981   26.947962   40.421944 0 1   0 1\n"
    "43  42  42.0  Mo  Molybdenum       4.493282    8.986565   13.479847 0 1   0 1\n"
    "44  43  43.0  Tc  Technetium       1.879204    3.758408    5.637613 0 1   0 1\n"
    "45  44  44.0  Ru  Ruthenium        2.382271    4.764542    7.146812 0 1   0 1\n"
    "46  45  45.0  Rh  Rhodium          5.004921   10.009842   15.014763 0 1   0 1\n"
    "47  46  46.0  Pd  Palladium       10.769531   21.539062   32.308592 0 1   0 1\n"
    "48  47  47.0  Ag  Silver          14.792738   29.585476   44.378214 0 1   0 1\n"
    "49  48  48.0  Cd  Cadmium          7.126333   14.252665   21.378998 0 1   0 1\n"
    "50  49  49.0  In  Indium           2.111157    4.222314    6.333471 0 1   0 1\n"
    "51  50  50.0  Sn  Tin              2.085032    4.170064    6.255096 0 1   0 1\n"
    "52  51  51.0  Sb  Antimony         4.003739    8.007478   12.011217 0 1   0 1\n"
    "53  52  52.0  Te  Tellurium        8.954873   17.909746   26.864620 0 1   0 1\n"
    "54  53  53.0  I   Iodine          14.739051   29.478102   44.217153 0 1   0 1\n"
    "55  54  54.0  Xe  Xenon           10.187793   20.375587   30.563380 0 1   0 1\n"
    "56  55  55.0  Cs  Caesium          2.549443    5.098885    7.648328 0 1   0 1\n"
    "57  56  56.0  Ba  Barium           1.857139    3.714278    5.571417 0 1   0 1\n"
    "58  57  57.0  La  Lanthanum        3.131442    6.262884    9.394327 0 1   0 1\n"
    "59  58  58.0  Ce  Cerium           7.023426   14.046852   21.070278 0 1   0 1\n"
    "60  59  59.0  Pr  Praseodymium    13.251365   26.502730   39.754094 0 1   0 1\n"
    "61  60  60.0  Nd  Neodymium       12.525049   25.050099   37.575148 0 1   0 1\n"
    "62  61  61.0  Pm  Promethium       3.555639    7.111278   10.666917 0 1   0 1\n"
    "63  62  62.0  Sm  Samarium         1.816289    3.632578    5.448867 0 1   0 1\n"
    "64  63  63.0  Eu  Europium         2.574328    5.148655    7.722983 0 1   0 1\n"
    "65  64  64.0  Gd  Gadolinium       5.586358   11.172716   16.759073 0 1   0 1\n"
    "66  65  65.0  Tb  Terbium         11.601908   23.203816   34.805724 0 1   0 1\n"
    "67  66  66.0  Dy  Dysprosium      14.194341   28.388682   42.583023 0 1   0 1\n"
    "68  67  67.0  Ho  Holmium          5.599384   11.198768   16.798152 0 1   0 1\n"
    "69  68  68.0  Er  Erbium           1.971388    3.942776    5.914164 0 1   0 1\n"
    "70  69  69.0  Tm  Thulium          2.237950    4.475899    6.713849 0 1   0 1\n"
    "71  70  70.0  Yb  Ytterbium        4.529366    9.058731   13.588097 0 1   0 1\n"
    "72  71  71.0  Lu  Lutetium         9.969381   19.938762   29.908144 0 1   0 1\n"
    "73  72  72.0  Hf  Hafnium         14.992188   29.984377   44.976565 0 1   0 1\n"
    "74  73  73.0  Ta  Tantalum         8.593943   17.187886   25.781828 0 1   0 1\n"
    "75  74  74.0  W   Tungsten         2.276138    4.552276    6.828414 0 1   0 1\n"
    "76  75  75.0  Re  Rhenium          1.962528    3.925056    5.887584 0 1   0 1\n"
    "77  76  76.0  Os  Osmium           3.564162    7.128324   10.692486 0 1   0 1\n"
    "78  77  77.0  Ir  Iridium          8.017654   16.035308   24.052962 0 1   0 1\n"
    "79  78  78.0  Pt  Platinum        14.142969   28.285938   42.428907 0 1   0 1\n"
    "80  79  79.0  Au  Gold            11.397639   22.795279   34.192918 0 1   0 1\n"
    "81  80  80.0  Hg  Mercury          2.919065    5.838130    8.757194 0 1   0 1\n"
    "82  81  81.0  Tl  Thallium         1.810147    3.620294    5.430441 0 1   0 1\n"
    "83  82  82.0  Pb  Lead             2.829674    5.659348    8.489022 0 1   0 1\n"
    "84  83  83.0  Bi  Bismuth          6.277248   12.554497   18.831745 0 1   0 1\n"
    "85  84  84.0  Po  Polonium        12.448978   24.897957   37.346935 0 1   0 1\n"
    "86  85  85.0  At  Astatine        13.369261   26.738523   40.107784 0 1   0 1\n"
    "87  86  86.0  Rn  Radon            4.365619    8.731239   13.096858 0 1   0 1\n"
    "88  87  87.0  Fr  Francium         1.869280    3.738561    5.607841 0 1   0 1\n"
    "89  88  88.0  Ra  Radium           2.402770    4.805540    7.208309 0 1   0 1\n"
    "90  89  89.0  Ac  Actinium         5.070011   10.140022   15.210033 0 1   0 1\n"
    "91  90  90.0  Th  Thorium         10.870087   21.740173   32.610260 0 1   0 1\n"
    "92  91  91.0  Pa  Protactinium    14.739702   29.479403   44.219105 0 1   0 1\n"
    "93  92  92.0  U   Uranium          6.935530   13.871060   20.806589 0 1   0 1\n"
    "94  93  93.0  Np  Neptunium        2.092573    4.185146    6.277720 0 1   0 1\n"
    "95  94  94.0  Pu  Plutonium        2.102509    4.205018    6.307526 0 1   0 1\n"
    "96  95  95.0  Am  Americium        4.064700    8.129399   12.194099 0 1   0 1\n"
    "97  96  96.0  Cm  Curium           9.078863   18.157727   27.236590 0 1   0 1\n"
    "98  97  97.0  Bk  Berkelium       14.794986   29.589972   44.384958 0 1   0 1\n"
    "99  98  98.0  Cf  Californium     10.010556   20.021112   30.031667 0 1   0 1\n"
    "100 99  99.0  Es  Einsteinium      2.510579    5.021158    7.531737 0 1   0 1\n"
    "101 100 100.0 Fm  Fermium          1.866953    3.733906    5.600858 0 1   0 1\n"
    "102 101 101.0 Md  Mendelevium      3.177602    6.355204    9.532805 0 1   0 1\n"
    "103 102 102.0 No  Nobelium         7.133166   14.266331   21.399497 0 1   0 1\n"
    "104 103 103.0 Lr  Lawrencium      13.360338   26.720676   40.081014 0 1   0 1\n"
    "105 104 104.0 Rf  Rutherfordium   12.403439   24.806877   37.210316 0 1   0 1\n"
    "106 105 105.0 Db  Dubnium          3.466323    6.932647   10.398970 0 1   0 1\n"
    "107 106 106.0 Sg  Seaborgium       1.812393    3.624786    5.437180 0 1   0 1\n"
    "108 107 107.0 Bh  Bohrium          2.600389    5.200777    7.801166 0 1   0 1\n"
    "109 108 108.0 Hs  Hassium          5.660574   11.321149   16.981723 0 1   0 1\n"
    "110 109 109.0 Mt  Meitnerium      11.698950   23.397900   35.096850 0 1   0 1\n"
    "111 110 110.0 Ds  Darmstadtium    14.106095   28.212189   42.318284 0 1   0 1\n"
    "112 111 111.0 Rg  Roentgenium      5.437174   10.874347   16.311521 0 1   0 1\n"
    "113 112 112.0 Cn  Copernicium      1.957406    3.914813    5.872219 0 1   0 1\n"
    "114 113 113.0 Uut Ununtrium        2.256534    4.513067    6.769601 0 1   0 1\n"
    "115 114 114.0 Uuq Ununquadium      4.592002    9.184003   13.776005 0 1   0 1\n"
    "116 115 115.0 Uup Ununpentium     10.081442   20.162885   30.244327 0 1   0 1\n"
    "117 116 116.0 Uuh Ununhexium      14.987691   29.975383   44.963074 0 1   0 1\n"
    "118 117 117.0 Uus Ununseptium      8.397634   16.795269   25.192903 0 1   0 1\n"
    "119 118 118.0 Uuo Ununoctium       2.250968    4.501935    6.752903 0 1   0 1\n"
    );
} // end anon namespace

TEST(CoordinateBlockGeneratorTest, generateCoordinateBlock)
{
  Molecule molecule;
  Vector3 pos(1.f, 2.f, 3.f);
  for (unsigned char i = 0; i < Elements::elementCount(); ++i) {
    molecule.addAtom(i).setPosition3d(
          pos += pos * (std::sin(static_cast<float>(i)) + 0.25));
  }

  CoordinateBlockGenerator gen;
  gen.setMolecule(&molecule);
  gen.setDistanceUnit(CoordinateBlockGenerator::Bohr);
  gen.setSpecification("#ZGSNxyz01__01");

  EXPECT_EQ(refCoordBlock, gen.generateCoordinateBlock());
}
