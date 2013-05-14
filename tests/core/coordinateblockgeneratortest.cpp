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
    "1   0   0.0   Xx  Dummy            2.776264    5.085929    7.395591 0 1   0 1\n"
    "2   1   1.0   H   Hydrogen         3.219533    5.739168    8.258798 0 1   0 1\n"
    "3   2   2.0   He  Helium           3.662802    6.392406    9.122004 0 1   0 1\n"
    "4   3   3.0   Li  Lithium          4.106072    7.045645    9.985210 0 1   0 1\n"
    "5   4   4.0   Be  Beryllium        4.549341    7.698883   10.848417 0 1   0 1\n"
    "6   5   5.0   B   Boron            4.992610    8.352122   11.711623 0 1   0 1\n"
    "7   6   6.0   C   Carbon           5.435879    9.005360   12.574829 0 1   0 1\n"
    "8   7   7.0   N   Nitrogen         5.879148    9.658599   13.438036 0 1   0 1\n"
    "9   8   8.0   O   Oxygen           6.322417   10.311837   14.301242 0 1   0 1\n"
    "10  9   9.0   F   Fluorine         6.765686   10.965076   15.164448 0 1   0 1\n"
    "11  10  10.0  Ne  Neon             7.208955   11.618314   16.027655 0 1   0 1\n"
    "12  11  11.0  Na  Sodium           7.652224   12.271553   16.890861 0 1   0 1\n"
    "13  12  12.0  Mg  Magnesium        8.095493   12.924791   17.754067 0 1   0 1\n"
    "14  13  13.0  Al  Aluminium        8.538762   13.578030   18.617274 0 1   0 1\n"
    "15  14  14.0  Si  Silicon          8.982031   14.231268   19.480480 0 1   0 1\n"
    "16  15  15.0  P   Phosphorus       9.425300   14.884506   20.343687 0 1   0 1\n"
    "17  16  16.0  S   Sulfur           9.868570   15.537745   21.206893 0 1   0 1\n"
    "18  17  17.0  Cl  Chlorine        10.311839   16.190983   22.070099 0 1   0 1\n"
    "19  18  18.0  Ar  Argon           10.755108   16.844222   22.933306 0 1   0 1\n"
    "20  19  19.0  K   Potassium       11.198377   17.497460   23.796512 0 1   0 1\n"
    "21  20  20.0  Ca  Calcium         11.641646   18.150699   24.659718 0 1   0 1\n"
    "22  21  21.0  Sc  Scandium        12.084915   18.803937   25.522925 0 1   0 1\n"
    "23  22  22.0  Ti  Titanium        12.528184   19.457176   26.386131 0 1   0 1\n"
    "24  23  23.0  V   Vanadium        12.971453   20.110414   27.249337 0 1   0 1\n"
    "25  24  24.0  Cr  Chromium        13.414722   20.763653   28.112544 0 1   0 1\n"
    "26  25  25.0  Mn  Manganese       13.857991   21.416891   28.975750 0 1   0 1\n"
    "27  26  26.0  Fe  Iron            14.301260   22.070130   29.838956 0 1   0 1\n"
    "28  27  27.0  Co  Cobalt          14.744529   22.723368   30.702163 0 1   0 1\n"
    "29  28  28.0  Ni  Nickel          15.187799   23.376607   31.565369 0 1   0 1\n"
    "30  29  29.0  Cu  Copper          15.631068   24.029845   32.428576 0 1   0 1\n"
    "31  30  30.0  Zn  Zinc            16.074337   24.683084   33.291782 0 1   0 1\n"
    "32  31  31.0  Ga  Gallium         16.517606   25.336322   34.154988 0 1   0 1\n"
    "33  32  32.0  Ge  Germanium       16.960875   25.989561   35.018195 0 1   0 1\n"
    "34  33  33.0  As  Arsenic         17.404144   26.642799   35.881401 0 1   0 1\n"
    "35  34  34.0  Se  Selenium        17.847413   27.296038   36.744607 0 1   0 1\n"
    "36  35  35.0  Br  Bromine         18.290682   27.949276   37.607814 0 1   0 1\n"
    "37  36  36.0  Kr  Krypton         18.733951   28.602515   38.471020 0 1   0 1\n"
    "38  37  37.0  Rb  Rubidium        19.177220   29.255753   39.334226 0 1   0 1\n"
    "39  38  38.0  Sr  Strontium       19.620489   29.908992   40.197433 0 1   0 1\n"
    "40  39  39.0  Y   Yttrium         20.063758   30.562230   41.060639 0 1   0 1\n"
    "41  40  40.0  Zr  Zirconium       20.507027   31.215468   41.923845 0 1   0 1\n"
    "42  41  41.0  Nb  Niobium         20.950297   31.868707   42.787052 0 1   0 1\n"
    "43  42  42.0  Mo  Molybdenum      21.393566   32.521945   43.650258 0 1   0 1\n"
    "44  43  43.0  Tc  Technetium      21.836835   33.175184   44.513465 0 1   0 1\n"
    "45  44  44.0  Ru  Ruthenium       22.280104   33.828422   45.376671 0 1   0 1\n"
    "46  45  45.0  Rh  Rhodium         22.723373   34.481661   46.239877 0 1   0 1\n"
    "47  46  46.0  Pd  Palladium       23.166642   35.134899   47.103084 0 1   0 1\n"
    "48  47  47.0  Ag  Silver          23.609911   35.788138   47.966290 0 1   0 1\n"
    "49  48  48.0  Cd  Cadmium         24.053180   36.441376   48.829496 0 1   0 1\n"
    "50  49  49.0  In  Indium          24.496449   37.094615   49.692703 0 1   0 1\n"
    "51  50  50.0  Sn  Tin             24.939718   37.747853   50.555909 0 1   0 1\n"
    "52  51  51.0  Sb  Antimony        25.382987   38.401092   51.419115 0 1   0 1\n"
    "53  52  52.0  Te  Tellurium       25.826256   39.054330   52.282322 0 1   0 1\n"
    "54  53  53.0  I   Iodine          26.269525   39.707569   53.145528 0 1   0 1\n"
    "55  54  54.0  Xe  Xenon           26.712795   40.360807   54.008734 0 1   0 1\n"
    "56  55  55.0  Cs  Caesium         27.156064   41.014046   54.871941 0 1   0 1\n"
    "57  56  56.0  Ba  Barium          27.599333   41.667284   55.735147 0 1   0 1\n"
    "58  57  57.0  La  Lanthanum       28.042602   42.320523   56.598354 0 1   0 1\n"
    "59  58  58.0  Ce  Cerium          28.485871   42.973761   57.461560 0 1   0 1\n"
    "60  59  59.0  Pr  Praseodymium    28.929140   43.627000   58.324766 0 1   0 1\n"
    "61  60  60.0  Nd  Neodymium       29.372409   44.280238   59.187973 0 1   0 1\n"
    "62  61  61.0  Pm  Promethium      29.815678   44.933477   60.051179 0 1   0 1\n"
    "63  62  62.0  Sm  Samarium        30.258947   45.586715   60.914385 0 1   0 1\n"
    "64  63  63.0  Eu  Europium        30.702216   46.239954   61.777592 0 1   0 1\n"
    "65  64  64.0  Gd  Gadolinium      31.145485   46.893192   62.640798 0 1   0 1\n"
    "66  65  65.0  Tb  Terbium         31.588754   47.546430   63.504004 0 1   0 1\n"
    "67  66  66.0  Dy  Dysprosium      32.032023   48.199669   64.367211 0 1   0 1\n"
    "68  67  67.0  Ho  Holmium         32.475293   48.852907   65.230417 0 1   0 1\n"
    "69  68  68.0  Er  Erbium          32.918562   49.506146   66.093623 0 1   0 1\n"
    "70  69  69.0  Tm  Thulium         33.361831   50.159384   66.956830 0 1   0 1\n"
    "71  70  70.0  Yb  Ytterbium       33.805100   50.812623   67.820036 0 1   0 1\n"
    "72  71  71.0  Lu  Lutetium        34.248369   51.465861   68.683242 0 1   0 1\n"
    "73  72  72.0  Hf  Hafnium         34.691638   52.119100   69.546449 0 1   0 1\n"
    "74  73  73.0  Ta  Tantalum        35.134907   52.772338   70.409655 0 1   0 1\n"
    "75  74  74.0  W   Tungsten        35.578176   53.425577   71.272862 0 1   0 1\n"
    "76  75  75.0  Re  Rhenium         36.021445   54.078815   72.136068 0 1   0 1\n"
    "77  76  76.0  Os  Osmium          36.464714   54.732054   72.999274 0 1   0 1\n"
    "78  77  77.0  Ir  Iridium         36.907983   55.385292   73.862481 0 1   0 1\n"
    "79  78  78.0  Pt  Platinum        37.351252   56.038531   74.725687 0 1   0 1\n"
    "80  79  79.0  Au  Gold            37.794522   56.691769   75.588893 0 1   0 1\n"
    "81  80  80.0  Hg  Mercury         38.237791   57.345008   76.452100 0 1   0 1\n"
    "82  81  81.0  Tl  Thallium        38.681060   57.998246   77.315306 0 1   0 1\n"
    "83  82  82.0  Pb  Lead            39.124329   58.651485   78.178512 0 1   0 1\n"
    "84  83  83.0  Bi  Bismuth         39.567598   59.304723   79.041719 0 1   0 1\n"
    "85  84  84.0  Po  Polonium        40.010867   59.957962   79.904925 0 1   0 1\n"
    "86  85  85.0  At  Astatine        40.454136   60.611200   80.768131 0 1   0 1\n"
    "87  86  86.0  Rn  Radon           40.897405   61.264439   81.631338 0 1   0 1\n"
    "88  87  87.0  Fr  Francium        41.340674   61.917677   82.494544 0 1   0 1\n"
    "89  88  88.0  Ra  Radium          41.783943   62.570916   83.357751 0 1   0 1\n"
    "90  89  89.0  Ac  Actinium        42.227212   63.224154   84.220957 0 1   0 1\n"
    "91  90  90.0  Th  Thorium         42.670481   63.877392   85.084163 0 1   0 1\n"
    "92  91  91.0  Pa  Protactinium    43.113750   64.530631   85.947370 0 1   0 1\n"
    "93  92  92.0  U   Uranium         43.557020   65.183869   86.810576 0 1   0 1\n"
    "94  93  93.0  Np  Neptunium       44.000289   65.837108   87.673782 0 1   0 1\n"
    "95  94  94.0  Pu  Plutonium       44.443558   66.490346   88.536989 0 1   0 1\n"
    "96  95  95.0  Am  Americium       44.886827   67.143585   89.400195 0 1   0 1\n"
    "97  96  96.0  Cm  Curium          45.330096   67.796823   90.263401 0 1   0 1\n"
    "98  97  97.0  Bk  Berkelium       45.773365   68.450062   91.126608 0 1   0 1\n"
    "99  98  98.0  Cf  Californium     46.216634   69.103300   91.989814 0 1   0 1\n"
    "100 99  99.0  Es  Einsteinium     46.659903   69.756539   92.853020 0 1   0 1\n"
    "101 100 100.0 Fm  Fermium         47.103172   70.409777   93.716227 0 1   0 1\n"
    "102 101 101.0 Md  Mendelevium     47.546441   71.063016   94.579433 0 1   0 1\n"
    "103 102 102.0 No  Nobelium        47.989710   71.716254   95.442640 0 1   0 1\n"
    "104 103 103.0 Lr  Lawrencium      48.432979   72.369493   96.305846 0 1   0 1\n"
    "105 104 104.0 Rf  Rutherfordium   48.876248   73.022731   97.169052 0 1   0 1\n"
    "106 105 105.0 Db  Dubnium         49.319518   73.675970   98.032259 0 1   0 1\n"
    "107 106 106.0 Sg  Seaborgium      49.762787   74.329208   98.895465 0 1   0 1\n"
    "108 107 107.0 Bh  Bohrium         50.206056   74.982447   99.758671 0 1   0 1\n"
    "109 108 108.0 Hs  Hassium         50.649325   75.635685  100.621878 0 1   0 1\n"
    "110 109 109.0 Mt  Meitnerium      51.092594   76.288924  101.485084 0 1   0 1\n"
    "111 110 110.0 Ds  Darmstadtium    51.535863   76.942162  102.348290 0 1   0 1\n"
    "112 111 111.0 Rg  Roentgenium     51.979132   77.595401  103.211497 0 1   0 1\n"
    "113 112 112.0 Cn  Copernicium     52.422401   78.248639  104.074703 0 1   0 1\n"
    "114 113 113.0 Uut Ununtrium       52.865670   78.901878  104.937909 0 1   0 1\n"
    "115 114 114.0 Uuq Ununquadium     53.308939   79.555116  105.801116 0 1   0 1\n"
    "116 115 115.0 Uup Ununpentium     53.752208   80.208354  106.664322 0 1   0 1\n"
    "117 116 116.0 Uuh Ununhexium      54.195477   80.861593  107.527529 0 1   0 1\n"
    "118 117 117.0 Uus Ununseptium     54.638747   81.514831  108.390735 0 1   0 1\n"
    "119 118 118.0 Uuo Ununoctium      55.082016   82.168070  109.253941 0 1   0 1\n"
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
