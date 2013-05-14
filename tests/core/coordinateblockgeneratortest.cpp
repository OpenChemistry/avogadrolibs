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
    "1   0   0.0   Xx  Dummy           23.329953   33.128541   19.591491 0 1   0 1\n"
    "2   1   1.0   H   Hydrogen         9.130389    5.456937   33.084910 0 1   0 1\n"
    "3   2   2.0   He  Helium          35.806393   29.500411    5.205176 0 1   0 1\n"
    "4   3   3.0   Li  Lithium         29.668931   13.770287   10.759257 0 1   0 1\n"
    "5   4   4.0   Be  Beryllium       17.278416   34.922183   31.481970 0 1   0 1\n"
    "6   5   5.0   B   Boron           32.663425   21.023126   31.150952 0 1   0 1\n"
    "7   6   6.0   C   Carbon          25.970430   21.410472   24.437914 0 1   0 1\n"
    "8   7   7.0   N   Nitrogen        32.747713   22.764868   28.666556 0 1   0 1\n"
    "9   8   8.0   O   Oxygen          10.360607   15.368606   25.056726 0 1   0 1\n"
    "10  9   9.0   F   Fluorine        31.867986   23.266437   18.754464 0 1   0 1\n"
    "11  10  10.0  Ne  Neon            19.175580   30.376245   37.037410 0 1   0 1\n"
    "12  11  11.0  Na  Sodium           6.237490   21.090565   30.917755 0 1   0 1\n"
    "13  12  12.0  Mg  Magnesium       18.421127   18.365820   35.201548 0 1   0 1\n"
    "14  13  13.0  Al  Aluminium        9.158650   34.589532   18.963754 0 1   0 1\n"
    "15  14  14.0  Si  Silicon         33.087267   32.173677   15.763112 0 1   0 1\n"
    "16  15  15.0  P   Phosphorus      35.098598    8.721861   36.443611 0 1   0 1\n"
    "17  16  16.0  S   Sulfur          34.235112   17.632303   34.305679 0 1   0 1\n"
    "18  17  17.0  Cl  Chlorine        11.103761   14.657514   31.886868 0 1   0 1\n"
    "19  18  18.0  Ar  Argon           34.558497   28.841109   12.702446 0 1   0 1\n"
    "20  19  19.0  K   Potassium       29.194687   13.747565   27.502350 0 1   0 1\n"
    "21  20  20.0  Ca  Calcium         10.088504   16.398880   30.669813 0 1   0 1\n"
    "22  21  21.0  Sc  Scandium        18.881760   29.694517   31.807989 0 1   0 1\n"
    "23  22  22.0  Ti  Titanium        32.459836   28.784402    9.818556 0 1   0 1\n"
    "24  23  23.0  V   Vanadium        17.920360   10.580233    2.830732 0 1   0 1\n"
    "25  24  24.0  Cr  Chromium        12.974961    8.016182   12.649972 0 1   0 1\n"
    "26  25  25.0  Mn  Manganese        7.404699   24.542809    7.406677 0 1   0 1\n"
    "27  26  26.0  Fe  Iron            11.589155   25.171397   18.348445 0 1   0 1\n"
    "28  27  27.0  Co  Cobalt          37.702939   30.072894   36.201865 0 1   0 1\n"
    "29  28  28.0  Ni  Nickel           5.938605    0.991011   18.330480 0 1   0 1\n"
    "30  29  29.0  Cu  Copper           7.401088   26.151350   10.881428 0 1   0 1\n"
    "31  30  30.0  Zn  Zinc            35.720673   19.531393   32.319971 0 1   0 1\n"
    "32  31  31.0  Ga  Gallium         14.514109   10.391367    0.840566 0 1   0 1\n"
    "33  32  32.0  Ge  Germanium       17.210213    4.266262   25.679828 0 1   0 1\n"
    "34  33  33.0  As  Arsenic          5.286448    2.087475   34.767527 0 1   0 1\n"
    "35  34  34.0  Se  Selenium        16.596229   35.003431   16.219044 0 1   0 1\n"
    "36  35  35.0  Br  Bromine          6.170031   37.076038   12.554501 0 1   0 1\n"
    "37  36  36.0  Kr  Krypton         21.614701   32.175493   36.704828 0 1   0 1\n"
    "38  37  37.0  Rb  Rubidium        11.298250    3.907524   29.004462 0 1   0 1\n"
    "39  38  38.0  Sr  Strontium       35.281377    8.981934   25.486027 0 1   0 1\n"
    "40  39  39.0  Y   Yttrium         37.421734   32.921570   29.750545 0 1   0 1\n"
    "41  40  40.0  Zr  Zirconium        6.809819   10.757887   30.235610 0 1   0 1\n"
    "42  41  41.0  Nb  Niobium         16.126888   27.770802    4.308726 0 1   0 1\n"
    "43  42  42.0  Mo  Molybdenum      19.625341   21.287667   14.739786 0 1   0 1\n"
    "44  43  43.0  Tc  Technetium       2.623908   26.173342   18.754622 0 1   0 1\n"
    "45  44  44.0  Ru  Ruthenium       21.534579   32.218523    4.178802 0 1   0 1\n"
    "46  45  45.0  Rh  Rhodium         21.883468   35.120299   31.460709 0 1   0 1\n"
    "47  46  46.0  Pd  Palladium       36.649574   19.785412   29.789108 0 1   0 1\n"
    "48  47  47.0  Ag  Silver          24.210422   29.298445   18.835150 0 1   0 1\n"
    "49  48  48.0  Cd  Cadmium         19.330439   22.752137   28.741072 0 1   0 1\n"
    "50  49  49.0  In  Indium          27.094997   30.909284   10.637505 0 1   0 1\n"
    "51  50  50.0  Sn  Tin             14.483161   15.569654    6.286299 0 1   0 1\n"
    "52  51  51.0  Sb  Antimony         0.379489   27.253105    6.547557 0 1   0 1\n"
    "53  52  52.0  Te  Tellurium       21.540777   21.701448   16.043805 0 1   0 1\n"
    "54  53  53.0  I   Iodine          36.393783   14.226012   29.462354 0 1   0 1\n"
    "55  54  54.0  Xe  Xenon           32.004627   25.097768   30.898818 0 1   0 1\n"
    "56  55  55.0  Cs  Caesium         16.860112   30.861018   36.173606 0 1   0 1\n"
    "57  56  56.0  Ba  Barium          34.838001   32.475710    5.806705 0 1   0 1\n"
    "58  57  57.0  La  Lanthanum        1.344502    9.056735    1.916320 0 1   0 1\n"
    "59  58  58.0  Ce  Cerium          34.465390   13.896294   33.467660 0 1   0 1\n"
    "60  59  59.0  Pr  Praseodymium    18.615806   31.937809    9.867635 0 1   0 1\n"
    "61  60  60.0  Nd  Neodymium       35.337169    3.529544   16.586916 0 1   0 1\n"
    "62  61  61.0  Pm  Promethium      25.119652   32.337303    8.759124 0 1   0 1\n"
    "63  62  62.0  Sm  Samarium        35.533870   29.641548    5.986947 0 1   0 1\n"
    "64  63  63.0  Eu  Europium        32.608244   16.413286   27.730308 0 1   0 1\n"
    "65  64  64.0  Gd  Gadolinium      13.300124   35.910946   13.123329 0 1   0 1\n"
    "66  65  65.0  Tb  Terbium         27.904743   24.686711   16.641984 0 1   0 1\n"
    "67  66  66.0  Dy  Dysprosium      27.042248   11.053643   14.780629 0 1   0 1\n"
    "68  67  67.0  Ho  Holmium         25.420423    8.370619    8.039595 0 1   0 1\n"
    "69  68  68.0  Er  Erbium          35.967605   12.284441   19.910596 0 1   0 1\n"
    "70  69  69.0  Tm  Thulium         16.017950    5.176644    7.639937 0 1   0 1\n"
    "71  70  70.0  Yb  Ytterbium       18.657285   17.675357    1.899959 0 1   0 1\n"
    "72  71  71.0  Lu  Lutetium        30.252565   24.642900   20.707402 0 1   0 1\n"
    "73  72  72.0  Hf  Hafnium         14.806258    0.219398   13.368188 0 1   0 1\n"
    "74  73  73.0  Ta  Tantalum        34.060566   16.129479   15.748599 0 1   0 1\n"
    "75  74  74.0  W   Tungsten        16.929113    9.137406   28.699898 0 1   0 1\n"
    "76  75  75.0  Re  Rhenium         10.406304   27.688571   15.344056 0 1   0 1\n"
    "77  76  76.0  Os  Osmium          28.041668   16.587750   10.632263 0 1   0 1\n"
    "78  77  77.0  Ir  Iridium         17.798631    3.832001    4.182279 0 1   0 1\n"
    "79  78  78.0  Pt  Platinum        11.472459    3.606011   17.043104 0 1   0 1\n"
    "80  79  79.0  Au  Gold            30.261122   32.664389   25.850401 0 1   0 1\n"
    "81  80  80.0  Hg  Mercury         25.503891    3.781456    8.178813 0 1   0 1\n"
    "82  81  81.0  Tl  Thallium         5.095531   11.559876   27.261778 0 1   0 1\n"
    "83  82  82.0  Pb  Lead             5.702709   11.572400   34.731069 0 1   0 1\n"
    "84  83  83.0  Bi  Bismuth         17.974937    9.974251   23.750882 0 1   0 1\n"
    "85  84  84.0  Po  Polonium         3.121635   19.584152   16.512523 0 1   0 1\n"
    "86  85  85.0  At  Astatine        26.205073   10.705772   29.208301 0 1   0 1\n"
    "87  86  86.0  Rn  Radon           27.064582   36.266499    8.614377 0 1   0 1\n"
    "88  87  87.0  Fr  Francium        37.152269   36.603402    1.895645 0 1   0 1\n"
    "89  88  88.0  Ra  Radium           3.544985    3.657044   19.017626 0 1   0 1\n"
    "90  89  89.0  Ac  Actinium         8.241629    3.768251   29.769392 0 1   0 1\n"
    "91  90  90.0  Th  Thorium         37.251071    3.844494   18.856907 0 1   0 1\n"
    "92  91  91.0  Pa  Protactinium    17.787308   10.546269   27.256734 0 1   0 1\n"
    "93  92  92.0  U   Uranium         13.422182    2.071933   31.857070 0 1   0 1\n"
    "94  93  93.0  Np  Neptunium        5.015793   36.103036   21.136369 0 1   0 1\n"
    "95  94  94.0  Pu  Plutonium       24.569760   30.023070    3.931416 0 1   0 1\n"
    "96  95  95.0  Am  Americium       17.932836   32.638130    3.624067 0 1   0 1\n"
    "97  96  96.0  Cm  Curium           7.836359    7.260635    7.828104 0 1   0 1\n"
    "98  97  97.0  Bk  Berkelium       32.396159   15.760773   26.721724 0 1   0 1\n"
    "99  98  98.0  Cf  Californium     24.440372   17.065833   37.389408 0 1   0 1\n"
    "100 99  99.0  Es  Einsteinium     13.269919   25.658525    1.539070 0 1   0 1\n"
    "101 100 100.0 Fm  Fermium         30.235615    7.200123   21.524700 0 1   0 1\n"
    "102 101 101.0 Md  Mendelevium     15.394106    6.879604   35.285344 0 1   0 1\n"
    "103 102 102.0 No  Nobelium        35.452829   27.448297   35.750344 0 1   0 1\n"
    "104 103 103.0 Lr  Lawrencium      15.076674   28.725208   23.784981 0 1   0 1\n"
    "105 104 104.0 Rf  Rutherfordium    4.068378   32.409664   21.411629 0 1   0 1\n"
    "106 105 105.0 Db  Dubnium         32.817505   19.747545   11.123161 0 1   0 1\n"
    "107 106 106.0 Sg  Seaborgium       1.201841   26.543324   12.568310 0 1   0 1\n"
    "108 107 107.0 Bh  Bohrium         15.085248   10.017025   21.243288 0 1   0 1\n"
    "109 108 108.0 Hs  Hassium          4.242729    9.826522    9.115322 0 1   0 1\n"
    "110 109 109.0 Mt  Meitnerium      16.963015   25.547668   23.071722 0 1   0 1\n"
    "111 110 110.0 Ds  Darmstadtium     1.982236   20.725146    1.410857 0 1   0 1\n"
    "112 111 111.0 Rg  Roentgenium     19.663979   32.155635   16.285757 0 1   0 1\n"
    "113 112 112.0 Cn  Copernicium     31.435134   13.776480    6.632383 0 1   0 1\n"
    "114 113 113.0 Uut Ununtrium       22.448879    4.241395    3.204845 0 1   0 1\n"
    "115 114 114.0 Uuq Ununquadium     11.083228   23.644296   29.665245 0 1   0 1\n"
    "116 115 115.0 Uup Ununpentium     36.371994   14.390131   23.252290 0 1   0 1\n"
    "117 116 116.0 Uuh Ununhexium       2.938536   27.856641   29.609854 0 1   0 1\n"
    "118 117 117.0 Uus Ununseptium     10.049427   33.080602   35.633881 0 1   0 1\n"
    "119 118 118.0 Uuo Ununoctium      24.109773    6.923345   21.499079 0 1   0 1\n"
    );
} // end anon namespace

TEST(CoordinateBlockGeneratorTest, generateCoordinateBlock)
{
  Molecule molecule;
  Vector3 pos(1.23456789, 2.34567891, 3.456789123);
  Vector3 inc(0.23456789, 0.34567891, 0.456789123);
  for (unsigned char i = 0; i < Elements::elementCount(); ++i)
    molecule.addAtom(i).setPosition3d(pos += inc);

  CoordinateBlockGenerator gen;
  gen.setMolecule(&molecule);
  gen.setDistanceUnit(CoordinateBlockGenerator::Bohr);
  gen.setSpecification("#ZGSNxyz01__01");
std::cout << gen.generateCoordinateBlock() << std::endl;
  EXPECT_EQ(refCoordBlock, gen.generateCoordinateBlock());
}
