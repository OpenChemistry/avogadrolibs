#ifndef AVOGADRO_CORE_ELEMENTS_DATA
#define AVOGADRO_CORE_ELEMENTS_DATA

namespace Avogadro {
namespace Core {

unsigned char element_count = 119;

const char* element_symbols[] = {
  "Xx", "H",  "He", "Li", "Be", "B",  "C",  "N",  "O",  "F",  "Ne", "Na",
  "Mg", "Al", "Si", "P",  "S",  "Cl", "Ar", "K",  "Ca", "Sc", "Ti", "V",
  "Cr", "Mn", "Fe", "Co", "Ni", "Cu", "Zn", "Ga", "Ge", "As", "Se", "Br",
  "Kr", "Rb", "Sr", "Y",  "Zr", "Nb", "Mo", "Tc", "Ru", "Rh", "Pd", "Ag",
  "Cd", "In", "Sn", "Sb", "Te", "I",  "Xe", "Cs", "Ba", "La", "Ce", "Pr",
  "Nd", "Pm", "Sm", "Eu", "Gd", "Tb", "Dy", "Ho", "Er", "Tm", "Yb", "Lu",
  "Hf", "Ta", "W",  "Re", "Os", "Ir", "Pt", "Au", "Hg", "Tl", "Pb", "Bi",
  "Po", "At", "Rn", "Fr", "Ra", "Ac", "Th", "Pa", "U",  "Np", "Pu", "Am",
  "Cm", "Bk", "Cf", "Es", "Fm", "Md", "No", "Lr", "Rf", "Db", "Sg", "Bh",
  "Hs", "Mt", "Ds", "Rg", "Cn", "Nh", "Fl", "Mc", "Lv", "Ts", "Og"
};

const char* element_names[] = {
  "Dummy",        "Hydrogen",     "Helium",      "Lithium",     "Beryllium",
  "Boron",        "Carbon",       "Nitrogen",    "Oxygen",      "Fluorine",
  "Neon",         "Sodium",       "Magnesium",   "Aluminium",   "Silicon",
  "Phosphorus",   "Sulfur",       "Chlorine",    "Argon",       "Potassium",
  "Calcium",      "Scandium",     "Titanium",    "Vanadium",    "Chromium",
  "Manganese",    "Iron",         "Cobalt",      "Nickel",      "Copper",
  "Zinc",         "Gallium",      "Germanium",   "Arsenic",     "Selenium",
  "Bromine",      "Krypton",      "Rubidium",    "Strontium",   "Yttrium",
  "Zirconium",    "Niobium",      "Molybdenum",  "Technetium",  "Ruthenium",
  "Rhodium",      "Palladium",    "Silver",      "Cadmium",     "Indium",
  "Tin",          "Antimony",     "Tellurium",   "Iodine",      "Xenon",
  "Caesium",      "Barium",       "Lanthanum",   "Cerium",      "Praseodymium",
  "Neodymium",    "Promethium",   "Samarium",    "Europium",    "Gadolinium",
  "Terbium",      "Dysprosium",   "Holmium",     "Erbium",      "Thulium",
  "Ytterbium",    "Lutetium",     "Hafnium",     "Tantalum",    "Tungsten",
  "Rhenium",      "Osmium",       "Iridium",     "Platinum",    "Gold",
  "Mercury",      "Thallium",     "Lead",        "Bismuth",     "Polonium",
  "Astatine",     "Radon",        "Francium",    "Radium",      "Actinium",
  "Thorium",      "Protactinium", "Uranium",     "Neptunium",   "Plutonium",
  "Americium",    "Curium",       "Berkelium",   "Californium", "Einsteinium",
  "Fermium",      "Mendelevium",  "Nobelium",    "Lawrencium",  "Rutherfordium",
  "Dubnium",      "Seaborgium",   "Bohrium",     "Hassium",     "Meitnerium",
  "Darmstadtium", "Roentgenium",  "Copernicium", "Nihonium",    "Flerovium",
  "Moscovium",    "Livermorium",  "Tennessine",  "Oganesson"
};

double element_masses[] = {
  // from IUPAC http://www.chem.qmul.ac.uk/iupac/AtWt/
  // (2015 set, updated from 2013)
  0,       1.00784,  4.0026,   6.938,    9.01218,  10.806,   12.011,  14.006,
  15.9994, 18.9984,  20.1797,  22.9898,  24.305,   26.9815,  28.0855, 30.9738,
  32.065,  35.453,   39.948,   39.0983,  40.078,   44.9559,  47.867,  50.9415,
  51.9961, 54.938,   55.845,   58.9332,  58.6934,  63.546,   65.38,   69.723,
  72.64,   74.9216,  78.971,   79.904,   83.798,   85.4678,  87.62,   88.9058,
  91.224,  92.9064,  95.95,    97,       101.07,   102.9055, 106.42,  107.8682,
  112.414, 114.818,  118.71,   121.76,   127.6,    126.9045, 131.293, 132.9055,
  137.327, 138.9055, 140.116,  140.9077, 144.242,  145,      150.36,  151.964,
  157.25,  158.9253, 162.5,    164.9303, 167.259,  168.9342, 173.045, 174.9668,
  178.49,  180.9479, 183.84,   186.207,  190.23,   192.217,  195.084, 196.9666,
  200.592, 204.38,   207.2,    208.9804, 209,      210,      222,     223,
  226,     227,      232.0377, 231.0358, 238.0289, 237,      244,     243,
  247,     247,      251,      252,      257,      258,      259,     262,
  267,     270,      269,      270,      270,      278,      281,     281,
  285,     286,      289,      289,      293,      293,      294
};

double element_VDW[] = {
  // From Alvarez doi: 10.1039/C3DT50599E
  // Dalton Trans., 2013,42, 8617-8636
  // Dummy, 1st row
  0.69, 1.2, 1.43,
  // 2nd row (Li..Ne)
  2.12, 1.98, 1.91, 1.77, 1.66, 1.50, 1.46, 1.58,
  // 3rd row (Na .. Ar)
  2.50, 2.51, 2.25, 2.19, 1.90, 1.89, 1.82, 1.83,
  // 4th row (K, Ca)
  2.73, 2.62,
  // 1st row TM (Sc.. Zn)
  2.58, 2.46, 2.42, 2.45, 2.45, 2.44, 2.40, 2.40, 2.38, 2.39,
  // 4th row p-block (Ga .. Kr)
  2.32, 2.29, 1.88, 1.82, 1.86, 2.25,
  // 5th row Rb, Sr
  3.21, 2.84,
  // 2nd row TM (Y .. Cd)
  2.75, 2.52, 2.56, 2.45, 2.44, 2.46, 2.44, 2.15, 2.53, 2.49,
  // 5th row p-block (Sn .. Xe)
  2.43, 2.42, 2.47, 1.99, 2.04, 2.06,
  // 6th row Cs, Ba
  3.48, 3.03,
  // Lanthanides (La..Gd)
  2.98, 2.88, 2.92, 2.95, 2.90, 2.87, 2.83,
  // Lanthanides (Tb..Yb)
  2.79, 2.87, 2.81, 2.83, 2.79, 2.80,
  // 3rd row TM (Lu..Hg)
  2.74, 2.63, 2.53, 2.57, 2.49, 2.48, 2.41, 2.29, 2.32, 2.45,
  // 6th row p-block (Tl.. Bi)
  // 2.5 is a default here
  2.47, 2.60, 2.54, 2.5, 2.5, 2.5,
  // 7th row
  // 2.5 is a default here
  2.5, 2.5,
  // Actinides
  2.8, 2.93, 2.88, 2.71, 2.82, 2.81, 2.83, 3.05, 3.38, 3.05, 3., 3., 3., 3.,
  // Trans-actinides
  3., 3., 3., 3., 3., 3., 3., 3., 3., 3.,
  // 7th row p-block
  3., 3., 3., 3., 3., 3.,
};

double element_covalent[] = {
  // From Pyykko doi: 10.1002/chem.200800987
  // Dummy, 1st row
  0.18, 0.32, 0.46,
  // 2nd row
  1.33, 1.02, 0.85, 0.75, 0.71, 0.63, 0.64, 0.67,
  // 3rd row
  1.55, 1.39, 1.26, 1.16, 1.11, 1.03, 0.99, 0.96,
  // 4th row K, Ca
  1.96, 1.71,
  // 1st row TM (Sc.. Zn)
  1.48, 1.36, 1.34, 1.22, 1.19, 1.16, 1.11, 1.10, 1.12, 1.18,
  // 4th row p-block (Ga..Kr)
  1.24, 1.21, 1.21, 1.16, 1.14, 1.17,
  // 5th row Rb, Sr
  2.10, 1.85,
  // 2nd row TM (Y..Cd)
  1.63, 1.54, 1.47, 1.38, 1.28, 1.25, 1.25, 1.20, 1.28, 1.36,
  // 5th row p-block (In..Xe)
  1.42, 1.40, 1.40, 1.36, 1.33, 1.31,
  // 6th row Cs, Ba
  2.32, 1.96,
  // Lanthanides La..Gd
  1.80, 1.63, 1.76, 1.74, 1.73, 1.72, 1.68,
  // Lanthanides Tb..Yb
  1.69, 1.68, 1.67, 1.66, 1.65, 1.64, 1.70,
  // 3rd row TM (Lu..Hg)
  1.62, 1.52, 1.46, 1.37, 1.31, 1.29, 1.22, 1.23, 1.24, 1.33,
  // 6th row p-block (Tl..Rn)
  1.44, 1.44, 1.51, 1.45, 1.47, 1.42,
  // 7th row Fr, Ra
  2.23, 2.01,
  // Actinides (Ac.. Am)
  1.86, 1.75, 1.69, 1.70, 1.71, 1.72, 1.66,
  // Actinides (Cm..No)
  1.66, 1.68, 1.68, 1.65, 1.67, 1.73, 1.76,
  // Trans-actinides
  1.61, 1.57, 1.49, 1.43, 1.41, 1.34, 1.29, 1.28, 1.21, 1.22, 1.36, 1.43, 1.62,
  1.75, 1.65, 1.57
};

unsigned char element_color[][3] = {
  // See, for example http://jmol.sourceforge.net/jscolors/index.en.html
  // Changes - H is not completely white to add contrast on light backgrounds
  //         - C is slightly darker (i.e. 50% gray - consistent with Avo1)
  //         - F is bluer to add contrast with Cl (e.g. CFC compounds)
  // # Du             # H                 # He
  { 17, 127, 178 },  { 240, 240, 240 }, { 217, 255, 255 }, { 204, 128, 255 },
  // # Be, B, C, N
  { 194, 255, 0 },   { 255, 181, 181 }, { 127, 127, 127 }, { 48, 80, 255 },
  // # O, F, Ne, Na
  { 255, 13, 13 },   { 178, 255, 255 }, { 178, 227, 245 }, { 171, 91, 242 },
  // # Mg
  { 138, 255, 0 },   { 191, 166, 166 }, { 240, 200, 160 }, { 255, 128, 0 },
  // # S
  { 255, 255, 48 },  { 31, 240, 31 },   { 128, 209, 227 }, { 143, 64, 212 },
  // # Ca
  { 61, 255, 0 },    { 230, 230, 230 }, { 191, 194, 199 }, { 166, 166, 171 },
  // # Cr
  { 138, 153, 199 }, { 156, 122, 199 }, { 224, 102, 51 }, { 240, 144, 160 },
  // # Ni
  { 80, 208, 80 },  { 200, 128, 51 },  { 125, 128, 176 }, { 194, 143, 143 },
  // # Ge
  { 102, 143, 143 }, { 189, 128, 227 }, { 255, 161, 0 },   { 166, 41, 41 },
  // # Kr
  { 92, 184, 209 },  { 112, 46, 176 },  { 0, 255, 0 },     { 148, 255, 255 },
  // # Zr
  { 148, 224, 224 }, { 115, 194, 201 }, { 84, 181, 181 },  { 59, 158, 158 },
  // # Ru
  { 36, 143, 143 },  { 10, 125, 140 },  { 0, 105, 133 },   { 192, 192, 192 },
  // # Cd
  { 255, 217, 143 }, { 166, 117, 115 }, { 102, 128, 128 }, { 158, 99, 181 },
  // # Te
  { 211, 122, 0 },   { 148, 0, 148 },   { 66, 158, 176 },  { 87, 23, 143 },
  // # Ba
  { 0, 201, 0 },     { 112, 212, 255 }, { 255, 255, 199 }, { 217, 255, 199 },
  // # Nd
  { 199, 255, 199 }, { 163, 255, 199 }, { 143, 255, 199 }, { 97, 255, 199 },
  // # Gd
  { 69, 255, 199 },  { 48, 255, 199 },  { 31, 255, 199 },  { 0, 255, 156 },
  // # Er
  { 0, 230, 117 },   { 0, 212, 82 },    { 0, 191, 56 },    { 0, 171, 36 },
  // # Hf
  { 77, 194, 255 },  { 77, 166, 255 },  { 33, 148, 214 },  { 38, 102, 150 },
  // # Os
  { 38, 102, 150 },  { 23, 84, 135 },   { 208, 208, 224 }, { 255, 209, 35 },
  // # Hg
  { 184, 194, 208 }, { 166, 84, 77 },   { 87, 89, 97 },    { 158, 79, 181 },
  // # Po
  { 171, 92, 0 },    { 117, 79, 69 },   { 66, 130, 150 },  { 66, 0, 102 },
  { 0, 124, 0 },     { 112, 170, 249 }, { 0, 186, 255 },   { 0, 160, 255 },
  { 0, 142, 255 },   { 0, 127, 255 },   { 0, 107, 255 },   { 84, 91, 242 },
  { 119, 91, 226 },  { 137, 79, 226 },  { 160, 53, 211 },  { 178, 30, 211 },
  { 178, 30, 186 },  { 178, 12, 165 },  { 188, 12, 135 },  { 198, 0, 102 },
  { 204, 0, 89 },    { 209, 0, 79 },    { 216, 0, 68 },    { 224, 0, 56 },
  { 229, 0, 45 },    { 232, 0, 38 },    { 234, 0, 35 },    { 237, 0, 33 },
  { 239, 0, 30 },    { 242, 0, 28 },    { 244, 0, 25 },    { 247, 0, 22 },
  { 249, 0, 20 },    { 252, 0, 17 },    { 255, 0, 15 }
};
}
}

#endif
