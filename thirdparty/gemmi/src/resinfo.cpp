/// Copyright 2018-2022 Global Phasing Ltd.

#include <gemmi/resinfo.hpp>
#include <gemmi/atox.hpp>  // for is_space

namespace gemmi {

using RI = ResidueKind;



 size_t find_tabulated_residue_idx(const std::string& name) {
  if (name.size() == 3) {

#define ID(s) (((s)[0] << 16 | (s)[1] << 8 | (s)[2]) & ~0x202020)
    //printf(">>> %x %x %x\n", ID(name.c_str()), ID("ALA"), ID("GLX"));
    switch (ID(name.c_str())) {
      case ID("ALA"): return 0;
      case ID("ARG"): return 1;
      case ID("ASN"): return 2;
      case ID("ABA"): return 3;
      case ID("ASP"): return 4;
      case ID("ASX"): return 5;
      case ID("CYS"): return 6;
      case ID("CSH"): return 7;
      case ID("GLN"): return 8;
      case ID("GLU"): return 9;
      case ID("GLX"): return 10;
      case ID("GLY"): return 11;
      case ID("HIS"): return 12;
      case ID("ILE"): return 13;
      case ID("LEU"): return 14;
      case ID("LYS"): return 15;
      case ID("MET"): return 16;
      case ID("MSE"): return 17;
      case ID("ORN"): return 18;
      case ID("PHE"): return 19;
      case ID("PRO"): return 20;
      case ID("SER"): return 21;
      case ID("THR"): return 22;
      case ID("TRY"):
      case ID("TRP"): return 23;
      case ID("TYR"): return 24;
      case ID("UNK"): return 25;
      case ID("VAL"): return 26;
      case ID("SEC"): return 27;
      case ID("PYL"): return 28;
      case ID("SEP"): return 29;
      case ID("TPO"): return 30;
      case ID("PCA"): return 31;
      case ID("CSO"): return 32;
      case ID("PTR"): return 33;
      case ID("KCX"): return 34;
      case ID("CSD"): return 35;
      case ID("LLP"): return 36;
      case ID("CME"): return 37;
      case ID("MLY"): return 38;
      case ID("DAL"): return 39;
      case ID("TYS"): return 40;
      case ID("OCS"): return 41;
      case ID("M3L"): return 42;
      case ID("FME"): return 43;
      case ID("ALY"): return 44;
      case ID("HYP"): return 45;
      case ID("CAS"): return 46;
      case ID("CRO"): return 47;
      case ID("CSX"): return 48;
      case ID("DPR"): return 49;
      case ID("DGL"): return 50;
      case ID("DVA"): return 51;
      case ID("CSS"): return 52;
      case ID("DPN"): return 53;
      case ID("DSN"): return 54;
      case ID("DLE"): return 55;
      case ID("HIC"): return 56;
      case ID("NLE"): return 57;
      case ID("MVA"): return 58;
      case ID("MLZ"): return 59;
      case ID("CR2"): return 60;
      case ID("SAR"): return 61;
      case ID("DAR"): return 62;
      case ID("DLY"): return 63;
      case ID("YCM"): return 64;
      case ID("NRQ"): return 65;
      case ID("CGU"): return 66;
      case ID("0TD"): return 67;
      case ID("MLE"): return 68;
      case ID("DAS"): return 69;
      case ID("DTR"): return 70;
      case ID("CXM"): return 71;
      case ID("TPQ"): return 72;
      case ID("DCY"): return 73;
      case ID("DSG"): return 74;
      case ID("DTY"): return 75;
      case ID("DHI"): return 76;
      case ID("MEN"): return 77;
      case ID("DTH"): return 78;
      case ID("SAC"): return 79;
      case ID("DGN"): return 80;
      case ID("AIB"): return 81;
      case ID("SMC"): return 82;
      case ID("IAS"): return 83;
      case ID("CIR"): return 84;
      case ID("BMT"): return 85;
      case ID("DIL"): return 86;
      case ID("FGA"): return 87;
      case ID("PHI"): return 88;
      case ID("CRQ"): return 89;
      case ID("SME"): return 90;
      case ID("GHP"): return 91;
      case ID("MHO"): return 92;
      case ID("NEP"): return 93;
      case ID("TRQ"): return 94;
      case ID("TOX"): return 95;
      case ID("ALC"): return 96;
      case ID("3FG"): return 97;
      case ID("SCH"): return 98;
      case ID("MDO"): return 99;
      case ID("MAA"): return 100;
      case ID("GYS"): return 101;
      case ID("MK8"): return 102;
      case ID("CR8"): return 103;
      case ID("KPI"): return 104;
      case ID("SCY"): return 105;
      case ID("DHA"): return 106;
      case ID("OMY"): return 107;
      case ID("CAF"): return 108;
      case ID("0AF"): return 109;
      case ID("SNN"): return 110;
      case ID("MHS"): return 111;
      case ID("MLU"): return 112;
      case ID("SNC"): return 113;
      case ID("PHD"): return 114;
      case ID("B3E"): return 115;
      case ID("MEA"): return 116;
      case ID("MED"): return 117;
      case ID("OAS"): return 118;
      case ID("GL3"): return 119;
      case ID("FVA"): return 120;
      case ID("PHL"): return 121;
      case ID("CRF"): return 122;
      case ID("OMZ"): return 123;
      case ID("BFD"): return 124;
      case ID("MEQ"): return 125;
      case ID("DAB"): return 126;
      case ID("AGM"): return 127;
      case ID("PSU"): return 128;
      case ID("5MU"): return 129;
      case ID("7MG"): return 130;
      case ID("OMG"): return 131;
      case ID("UR3"): return 132;
      case ID("OMC"): return 133;
      case ID("2MG"): return 134;
      case ID("H2U"): return 135;
      case ID("4SU"): return 136;
      case ID("OMU"): return 137;
      case ID("4OC"): return 138;
      case ID("MA6"): return 139;
      case ID("M2G"): return 140;
      case ID("1MA"): return 141;
      case ID("6MZ"): return 142;
      case ID("CCC"): return 143;
      case ID("2MA"): return 144;
      case ID("1MG"): return 145;
      case ID("5BU"): return 146;
      case ID("MIA"): return 147;
      case ID("DOC"): return 148;
      case ID("8OG"): return 149;
      case ID("5CM"): return 150;
      case ID("3DR"): return 151;
      case ID("BRU"): return 152;
      case ID("CBR"): return 153;
      case ID("WAT"):
      case ID("H2O"):
      case ID("HOH"): return 154;
      case ID("DOD"): return 155;
      case ID("HEM"): return 156;
      case ID("SO4"): return 157;
      case ID("GOL"): return 158;
      case ID("EDO"): return 159;
      case ID("NAG"): return 160;
      case ID("PO4"): return 161;
      case ID("ACT"): return 162;
      case ID("PEG"): return 163;
      case ID("MAN"): return 164;
      case ID("FAD"): return 165;
      case ID("BMA"): return 166;
      case ID("ADP"): return 167;
      case ID("DMS"): return 168;
      case ID("ACE"): return 169;
      case ID("NH2"): return 170;
      case ID("MPD"): return 171;
      case ID("MES"): return 172;
      case ID("NAD"): return 173;
      case ID("NAP"): return 174;
      case ID("TRS"): return 175;
      case ID("ATP"): return 176;
      case ID("PG4"): return 177;
      case ID("GDP"): return 178;
      case ID("FUC"): return 179;
      case ID("FMT"): return 180;
      case ID("GAL"): return 181;
      case ID("PGE"): return 182;
      case ID("FMN"): return 183;
      case ID("PLP"): return 184;
      case ID("EPE"): return 185;
      case ID("SF4"): return 186;
      case ID("BME"): return 187;
      case ID("CIT"): return 188;
      case ID("BE7"): return 189;
      case ID("MRD"): return 190;
      case ID("MHA"): return 191;
      case ID("BU3"): return 192;
      case ID("PGO"): return 193;
      case ID("BU2"): return 194;
      case ID("PDO"): return 195;
      case ID("BU1"): return 196;
      case ID("PG6"): return 197;
      case ID("1BO"): return 198;
      case ID("PE7"): return 199;
      case ID("PG5"): return 200;
      case ID("TFP"): return 201;
      case ID("DHD"): return 202;
      case ID("PEU"): return 203;
      case ID("TAU"): return 204;
      case ID("SBT"): return 205;
      case ID("SAL"): return 206;
      case ID("IOH"): return 207;
      case ID("IPA"): return 208;
      case ID("PIG"): return 209;
      case ID("B3P"): return 210;
      case ID("BTB"): return 211;
      case ID("NHE"): return 212;
      case ID("C8E"): return 213;
      case ID("OTE"): return 214;
      case ID("PE4"): return 215;
      case ID("XPE"): return 216;
      case ID("PE8"): return 217;
      case ID("P33"): return 218;
      case ID("N8E"): return 219;
      case ID("2OS"): return 220;
      case ID("1PS"): return 221;
      case ID("CPS"): return 222;
      case ID("DMX"): return 223;
      case ID("MPO"): return 224;
      case ID("GCD"): return 225;
      case ID("DXG"): return 226;
      case ID("CM5"): return 227;
      case ID("ACA"): return 228;
      case ID("ACN"): return 229;
      case ID("CCN"): return 230;
      case ID("GLC"): return 231;
      case ID("DR6"): return 232;
      case ID("NH4"): return 233;
      case ID("AZI"): return 234;
      case ID("BNG"): return 235;
      case ID("BOG"): return 236;
      case ID("BGC"): return 237;
      case ID("BCN"): return 238;
      case ID("BRO"): return 239;
      case ID("CAC"): return 240;
      case ID("CBX"): return 241;
      case ID("ACY"): return 242;
      case ID("CBM"): return 243;
      case ID("CLO"): return 244;
      case ID("3CO"): return 245;
      case ID("NCO"): return 246;
      case ID("CU1"): return 247;
      case ID("CYN"): return 248;
      case ID("MA4"): return 249;
      case ID("TAR"): return 250;
      case ID("GLO"): return 251;
      case ID("MTL"): return 252;
      case ID("SOR"): return 253;
      case ID("DMU"): return 254;
      case ID("DDQ"): return 255;
      case ID("DMF"): return 256;
      case ID("DIO"): return 257;
      case ID("DOX"): return 258;
      case ID("12P"): return 259;
      case ID("SDS"): return 260;
      case ID("LMT"): return 261;
      case ID("EOH"): return 262;
      case ID("EEE"): return 263;
      case ID("EGL"): return 264;
      case ID("FLO"): return 265;
      case ID("TRT"): return 266;
      case ID("FCY"): return 267;
      case ID("FRU"): return 268;
      case ID("GBL"): return 269;
      case ID("GPX"): return 270;
      case ID("HTO"): return 271;
      case ID("HTG"): return 272;
      case ID("B7G"): return 273;
      case ID("C10"): return 274;
      case ID("16D"): return 275;
      case ID("HEZ"): return 276;
      case ID("IOD"): return 277;
      case ID("IDO"): return 278;
      case ID("ICI"): return 279;
      case ID("ICT"): return 280;
      case ID("TLA"): return 281;
      case ID("LAT"): return 282;
      case ID("LBT"): return 283;
      case ID("LDA"): return 284;
      case ID("MN3"): return 285;
      case ID("MRY"): return 286;
      case ID("MOH"): return 287;
      case ID("BEQ"): return 288;
      case ID("C15"): return 289;
      case ID("MG8"): return 290;
      case ID("POL"): return 291;
      case ID("NO3"): return 292;
      case ID("JEF"): return 293;
      case ID("P4C"): return 294;
      case ID("CE1"): return 295;
      case ID("DIA"): return 296;
      case ID("CXE"): return 297;
      case ID("IPH"): return 298;
      case ID("PIN"): return 299;
      case ID("15P"): return 300;
      case ID("CRY"): return 301;
      case ID("PGR"): return 302;
      case ID("PGQ"): return 303;
      case ID("SPD"): return 304;
      case ID("SPK"): return 305;
      case ID("SPM"): return 306;
      case ID("SUC"): return 307;
      case ID("TBU"): return 308;
      case ID("TMA"): return 309;
      case ID("TEP"): return 310;
      case ID("SCN"): return 311;
      case ID("TRE"): return 312;
      case ID("ETF"): return 313;
      case ID("144"): return 314;
      case ID("UMQ"): return 315;
      case ID("URE"): return 316;
      case ID("YT3"): return 317;
      case ID("ZN2"): return 318;
      case ID("FE2"): return 319;
      case ID("3NI"): return 320;
      case ID("SIA"): return 321;
      case ID("XYP"): return 322;
      case ID("A2G"): return 323;
      case ID("GLA"): return 324;
      case ID("NDG"): return 325;
      case ID("NGA"): return 326;
#undef ID
    }} else if (name.size() == 1) {
    switch (name[0]& ~0x20) {
      case 'A': return 327;
      case 'C': return 328;
      case 'G': return 329;
      case 'I': return 330;
      case 'U': return 331;
      case 'N': return 332;
      case 'F': return 333;
      case 'K': return 334;
    }
  } else if (name.size() == 2) {
    if (name[0] == 'D' || name[0] == '+')
      switch (name[1]) {
        case 'A': return 335;
        case 'C': return 336;
        case 'G': return 337;
        case 'I': return 338;
        case 'T': return 339;
        case 'U': return 340;
        case 'N': return 341;
      }
#define ID(s) ((s)[0] << 8 | (s)[1])
    switch (ID(name.c_str())) {
        case ID("AG"): return 342;
        case ID("AL"): return 343;
        case ID("BA"): return 344;
        case ID("BR"): return 345;
        case ID("CA"): return 346;
        case ID("CD"): return 347;
        case ID("CL"): return 348;
        case ID("CM"): return 349;
        case ID("CN"): return 350;
        case ID("CO"): return 351;
        case ID("CS"): return 352;
        case ID("CU"): return 353;
        case ID("FE"): return 354;
        case ID("HG"): return 355;
        case ID("LI"): return 356;
        case ID("MG"): return 357;
        case ID("MN"): return 358;
        case ID("NA"): return 359;
        case ID("NI"): return 360;
        case ID("NO"): return 361;
        case ID("PB"): return 362;
        case ID("RB"): return 363;
        case ID("SR"): return 364;
        case ID("Y1"): return 365;
        case ID("ZN"): return 366;
      }
#undef ID
    }
    return 367;
 }

ResidueInfo& get_residue_info(size_t idx) {
  static ResidueInfo array[368] = {
    // hydrogen_count needs to be verified
    {"ALA", RI::AA,  1, 'A',   7, 89.0932f },
    {"ARG", RI::AA,  1, 'R',  15, 175.209f },
    {"ASN", RI::AA,  1, 'N',   8, 132.118f },
    {"ABA", RI::AA,  1, 'a',   9, 103.120f },
    {"ASP", RI::AA,  1, 'D',   7, 133.103f },
    {"ASX", RI::AA,  1, 'B',   6, 100.096f },
    {"CYS", RI::AA,  1, 'C',   7, 121.158f },  // also BUF
    {"CSH", RI::AA,  1, 's',  17, 283.284f },
    {"GLN", RI::AA,  1, 'Q',  10, 146.144f },
    {"GLU", RI::AA,  1, 'E',   9, 147.129f },

    {"GLX", RI::AA,  1, 'Z',   8, 114.123f },
    {"GLY", RI::AA,  1, 'G',   5, 75.0666f },  // also BUF
    {"HIS", RI::AA,  1, 'H',  10, 156.162f },
    {"ILE", RI::AA,  1, 'I',  13, 131.173f },
    {"LEU", RI::AA,  1, 'L',  13, 131.173f },
    {"LYS", RI::AA,  1, 'K',  15, 147.196f },
    {"MET", RI::AA,  1, 'M',  11, 149.211f },
    {"MSE", RI::AA,  1, 'm',  11, 196.106f },
    {"ORN", RI::AA,  1, 'a',  12, 132.161f },
    {"PHE", RI::AA,  1, 'F',  11, 165.189f },
    //20

    {"PRO", RI::AA,  1, 'P',   9, 115.130f },
    {"SER", RI::AA,  1, 'S',   7, 105.093f },
    {"THR", RI::AA,  1, 'T',   9, 119.119f },
    {"TRP", RI::AA,  1, 'W',  12, 204.225f },
    {"TYR", RI::AA,  1, 'Y',  11, 181.189f },
    {"UNK", RI::AA,  1, 'X',   9, 103.120f },
    {"VAL", RI::AA,  1, 'V',  11, 117.146f },
    {"SEC", RI::AA,  1, 'U',   7, 168.053f },
    {"PYL", RI::AA,  1, 'O',  21, 255.313f },
    {"SEP", RI::AA,  1, 's',   8, 185.072f },
    // 30

    {"TPO", RI::AA,  1, 't',  10, 199.099f },
    {"PCA", RI::AA,  1, 'e',   7, 129.114f },
    {"CSO", RI::AA,  1, 'c',   7, 137.158f },
    {"PTR", RI::AA,  1, 'y',  12, 261.168f },
    {"KCX", RI::AA,  1, 'k',  14, 190.197f },
    {"CSD", RI::AA,  1, 'c',   7, 153.157f },
    {"LLP", RI::AA,  1, 'k',  22, 375.314f },
    {"CME", RI::AA,  1, 'c',  11, 197.276f },
    {"MLY", RI::AA,  1, 'k',  18, 174.241f },
    {"DAL", RI::AAD, 1, 'a',   7, 89.0932f },
    {"TYS", RI::AA,  1, 'y',  11, 261.252f },
    {"OCS", RI::AA,  1, 'c',   7, 169.156f },
    // 40

    {"M3L", RI::AA,  1, 'k',  21, 189.275f },
    {"FME", RI::AA,  1, 'm',  11, 177.221f },
    {"ALY", RI::AA,  1, 'k',  16, 188.224f },
    {"HYP", RI::AA,  1, 'p',   9, 131.130f },
    {"CAS", RI::AA,  1, 'c',  12, 225.141f },
    {"CRO", RI::AA,  1, 't',  17, 319.313f },
    {"CSX", RI::AA,  1, 'c',   7, 137.158f },
    {"DPR", RI::AAD, 1, 'p',   9, 115.130f },  // also BUF
    {"DGL", RI::AAD, 1, 'e',   9, 147.129f },
    {"DVA", RI::AAD, 1, 'v',  11, 117.146f },
    {"CSS", RI::AA,  1, 'c',   7, 153.223f },
    {"DPN", RI::AAD, 1, 'f',  11, 165.189f },
    {"DSN", RI::AAD, 1, 's',   7, 105.093f },
    // 50

    {"DLE", RI::AAD, 1, 'l',  13, 131.173f },
    {"HIC", RI::AA,  1, 'h',  11, 169.181f },
    {"NLE", RI::AA,  1, 'l',  13, 131.173f },
    {"MVA", RI::AA,  1, 'v',  13, 131.173f },
    {"MLZ", RI::AA,  1, 'k',  16, 160.214f },
    {"CR2", RI::AA,  1, 'g',  13, 275.260f },
    {"SAR", RI::AA,  1, 'g',   7, 89.0932f },
    {"DAR", RI::AAD, 1, 'r',  15, 175.209f },
    {"DLY", RI::AAD, 1, 'k',  14, 146.188f },
    {"YCM", RI::AA,  1, 'c',  10, 178.209f },
    // 60

    {"NRQ", RI::AA,  1, 'm',  17, 347.389f },
    {"CGU", RI::AA,  1, 'e',   9, 191.139f },
    {"0TD", RI::AA,  1, 'd',   9, 179.194f },
    {"MLE", RI::AA,  1, 'l',  15, 145.200f },
    {"DAS", RI::AAD, 1, 'd',   7, 133.103f },
    {"DTR", RI::AAD, 1, 'w',  12, 204.225f },
    {"CXM", RI::AA,  1, 'm',  11, 193.221f },
    {"TPQ", RI::AA,  1, 'y',   9, 211.171f },
    {"DCY", RI::AAD, 1, 'c',   7, 121.158f },
    {"DSG", RI::AAD, 1, 'n',   8, 132.118f },
    {"DTY", RI::AAD, 1, 'y',  11, 181.189f },
    // 70

    {"DHI", RI::AAD, 1, 'h',  10, 156.162f },
    {"MEN", RI::AA,  1, 'n',  10, 146.144f },
    {"DTH", RI::AAD, 1, 't',   9, 119.119f },
    {"SAC", RI::AA,  1, 's',   9, 147.129f },
    {"DGN", RI::AAD, 1, 'q',  10, 146.144f },
    {"AIB", RI::AA,  1, 'a',   9, 103.120f },
    {"SMC", RI::AA,  1, 'c',   9, 135.185f },
    {"IAS", RI::AA,  1, 'd',   7, 133.103f },
    {"CIR", RI::AA,  1, 'r',  13, 175.186f },
    {"BMT", RI::AA,  1, 't',  19, 201.263f },
    {"DIL", RI::AAD, 1, 'i',  13, 131.173f },
    {"FGA", RI::AA,  1, 'e',   9, 147.129f },
    //80

    {"PHI", RI::AA,  1, 'f',  10, 291.086f },
    {"CRQ", RI::AA,  1, 'q',  16, 344.322f },
    {"SME", RI::AA,  1, 'm',  11, 165.211f },
    {"GHP", RI::AA,  1, 'g',   9, 167.162f },  // d-peptide in CCD
    {"MHO", RI::AA,  1, 'm',  11, 165.211f },
    {"NEP", RI::AA,  1, 'h',  10, 235.134f },
    {"TRQ", RI::AA,  1, 'w',  10, 234.208f },
    {"TOX", RI::AA,  1, 'w',  12, 236.224f },
    {"ALC", RI::AA,  1, 'a',  17, 171.237f },
    {"3FG", RI::AA,  1, ' ',   9, 183.161f },
    {"SCH", RI::AA,  1, 'c',   9, 167.250f },
    {"MDO", RI::AA,  1, 'a',  11, 197.191f },
    {"MAA", RI::AA,  1, 'a',   9, 103.120f },
    //90

    {"GYS", RI::AA,  1, 's',  15, 305.286f },
    {"MK8", RI::AA,  1, 'l',  15, 145.200f },
    {"CR8", RI::AA,  1, 'h',  16, 354.340f },
    {"KPI", RI::AA,  1, 'k',  16, 216.234f },
    {"SCY", RI::AA,  1, 'c',   9, 163.195f },
    {"DHA", RI::AA,  1, 's',   5, 87.0773f },
    {"OMY", RI::AA,  1, 'y',  10, 231.633f },
    {"CAF", RI::AA,  1, 'c',  12, 241.140f },
    {"0AF", RI::AA,  1, 'w',  12, 220.225f },
    {"SNN", RI::AA,  1, 'n',   6, 114.103f },
    // 100

    {"MHS", RI::AA,  1, 'h',  11, 169.181f },
    {"MLU", RI::AAD, 1, ' ',  15, 145.200f },
    {"SNC", RI::AA,  1, 'c',   6, 150.156f },
    {"PHD", RI::AA,  1, 'd',   8, 213.083f },
    {"B3E", RI::AA,  1, 'e',  11, 161.156f },
    {"MEA", RI::AA,  1, 'f',  13, 179.216f },
    {"MED", RI::AAD, 1, 'm',  11, 149.211f },
    {"OAS", RI::AA,  1, 's',   9, 147.129f },
    {"GL3", RI::AA,  1, 'g',   5, 91.1322f },
    {"FVA", RI::AA,  1, 'v',  11, 145.156f },
    // 110

    {"PHL", RI::AA,  1, 'f',  13, 151.206f },
    {"CRF", RI::AA,  1, 't',  18, 342.349f },
    {"OMZ", RI::AA,  1, ' ',  10, 231.633f },  // d-peptide in CCD
    {"BFD", RI::AA,  1, 'd',   6, 198.102f },
    {"MEQ", RI::AA,  1, 'q',  12, 160.171f },
    {"DAB", RI::AA,  1, 'a',  10, 118.134f },
    {"AGM", RI::AA,  1, 'r',  17, 189.235f },
    {"PSU", RI::RNA, 2, 'u',  13, 324.181f },
    {"5MU", RI::RNA, 2, 'u',  15, 338.208f },
    {"7MG", RI::RNA, 2, 'g',  18, 379.263f },
    // 120

    {"OMG", RI::RNA, 2, 'g',  16, 377.247f },
    {"UR3", RI::RNA, 2, 'u',  15, 338.208f },
    {"OMC", RI::RNA, 2, 'c',  16, 337.223f },
    {"2MG", RI::RNA, 2, 'g',  16, 377.247f },
    {"H2U", RI::RNA, 2, 'u',  15, 326.197f },
    {"4SU", RI::RNA, 2, 'u',  13, 340.247f },
    {"OMU", RI::RNA, 2, 'u',  15, 338.208f },
    {"4OC", RI::RNA, 2, 'c',  18, 351.250f },
    {"MA6", RI::RNA, 2, 'a',  18, 375.274f },
    {"M2G", RI::RNA, 2, 'g',  18, 391.274f },
    // 130

    {"1MA", RI::RNA, 2, 'a',  16, 361.248f },
    {"6MZ", RI::RNA, 2, 'a',  16, 361.248f },
    {"CCC", RI::RNA, 2, 'c',  13, 385.161f },
    {"2MA", RI::RNA, 2, 'a',  16, 361.248f },
    {"1MG", RI::RNA, 2, 'g',  16, 377.247f },
    {"5BU", RI::RNA, 2, 'u',  12, 403.077f },
    {"MIA", RI::RNA, 2, 'a',  24, 461.430f },
    {"DOC", RI::DNA, 2, 'c',  14, 291.198f },
    {"8OG", RI::DNA, 2, 'g',  14, 363.221f },
    {"5CM", RI::DNA, 2, 'c',  16, 321.224f },
    // 140

    {"3DR", RI::DNA, 2, ' ',  11, 198.111f },
    {"BRU", RI::DNA, 2, 'u',  12, 387.078f },
    {"CBR", RI::DNA, 2, 'c',  13, 386.093f },
    {"HOH", RI::HOH, 0, ' ',   2, 18.0153f },
    {"DOD", RI::HOH, 0, ' ',   2, 20.0276f },
    {"HEM", RI::ELS, 0, ' ',  32, 616.487f },
    {"SO4", RI::BUF, 0, ' ',   0, 96.0626f },
    {"GOL", RI::BUF, 0, ' ',   8, 92.0938f },
    {"EDO", RI::BUF, 0, ' ',   6, 62.0678f },
    {"NAG", RI::PYR, 0, ' ',  15, 221.208f },
    // 150

    {"PO4", RI::ELS, 0, ' ',   0, 94.9714f },
    {"ACT", RI::BUF, 0, ' ',   3, 59.0440f },
    {"PEG", RI::ELS, 0, ' ',  10, 106.120f },
    {"MAN", RI::PYR, 0, ' ',  12, 180.156f },  // also BUF
    {"FAD", RI::ELS, 0, ' ',  33, 785.550f },
    {"BMA", RI::PYR, 0, ' ',  12, 180.156f },  // also BUF
    {"ADP", RI::ELS, 0, ' ',  15, 427.201f },
    {"DMS", RI::BUF, 0, ' ',   6, 78.1334f },
    {"ACE", RI::ELS, 1, ' ',   4, 44.0526f },
    {"NH2", RI::ELS, 1, ' ',   2, 16.0226f },  // ?
    {"MPD", RI::BUF, 0, ' ',  14, 118.174f },
    {"MES", RI::ELS, 0, ' ',  13, 195.237f },
    // 160

    {"NAD", RI::ELS, 0, ' ',  27, 663.425f },
    {"NAP", RI::ELS, 0, ' ',  28, 743.405f },
    {"TRS", RI::BUF, 0, ' ',  12, 122.143f },
    {"ATP", RI::ELS, 0, ' ',  16, 507.181f },
    {"PG4", RI::ELS, 0, ' ',  18, 194.226f },
    {"GDP", RI::ELS, 2, 'g',  15, 443.201f },  // RNA in CCD
    {"FUC", RI::PYR, 0, ' ',  12, 164.156f },
    {"FMT", RI::BUF, 0, ' ',   2, 46.0254f },
    {"GAL", RI::PYR, 0, ' ',  12, 180.156f },
    {"PGE", RI::BUF, 0, ' ',  14, 150.173f },
    {"FMN", RI::ELS, 0, ' ',  21, 456.344f },
    // 170

    {"PLP", RI::ELS, 0, ' ',  10, 247.142f },
    {"EPE", RI::ELS, 0, ' ',  18, 238.305f },
    {"SF4", RI::ELS, 0, ' ',   0, 351.640f },
    {"BME", RI::ELS, 0, ' ',   6, 78.1334f },
    {"CIT", RI::BUF, 0, ' ',   8, 192.124f },
    {"BE7", RI::BUF, 0, ' ',   5, 357.156f },
    {"MRD", RI::BUF, 0, ' ',  14, 118.174f },
    {"MHA", RI::BUF, 0, ' ',  10, 190.154f },
    {"BU3", RI::BUF, 0, ' ',  10, 90.1210f },
    {"PGO", RI::BUF, 0, ' ',   8, 76.0944f },
    {"BU2", RI::BUF, 0, ' ',  10, 90.1210f },
    // 180

    {"PDO", RI::BUF, 0, ' ',   8, 76.0944f },
    {"BU1", RI::BUF, 0, ' ',  10, 90.1210f },
    {"PG6", RI::BUF, 0, ' ',  26, 266.331f },
    {"1BO", RI::BUF, 0, ' ',  10, 74.1216f },
    {"PE7", RI::BUF, 0, ' ',  30, 342.449f },
    {"PG5", RI::BUF, 0, ' ',  18, 178.226f },
    {"TFP", RI::BUF, 0, ' ',  24, 407.496f },
    {"DHD", RI::BUF, 0, ' ',   4, 160.082f },
    {"PEU", RI::BUF, 0, ' ', 112, 1221.46f },
    {"TAU", RI::BUF, 0, ' ',   7, 125.147f },
    {"SBT", RI::BUF, 0, ' ',  10, 74.1216f },
    // 180

    {"SAL", RI::BUF, 0, ' ',   6, 138.121f },
    {"IOH", RI::BUF, 0, ' ',   8, 60.0950f },
    {"IPA", RI::BUF, 0, ' ',   8, 60.0950f },
    {"PIG", RI::BUF, 0, ' ',  14, 150.173f },
    {"B3P", RI::BUF, 0, ' ',  26, 282.334f },
    {"BTB", RI::BUF, 0, ' ',  19, 209.240f },
    {"NHE", RI::BUF, 0, ' ',  17, 207.290f },
    {"C8E", RI::BUF, 0, ' ',  34, 306.438f },
    {"OTE", RI::BUF, 0, ' ',  34, 306.438f },
    {"PE4", RI::BUF, 0, ' ',  34, 354.436f },
    {"XPE", RI::BUF, 0, ' ',  42, 458.541f },
    // 200

    {"PE8", RI::BUF, 0, ' ',  34, 370.436f },
    {"P33", RI::BUF, 0, ' ',  30, 326.383f },
    {"N8E", RI::BUF, 0, ' ',  38, 350.491f },
    {"2OS", RI::BUF, 0, ' ',  36, 468.493f },
    {"1PS", RI::BUF, 0, ' ',  11, 201.243f },
    {"CPS", RI::BUF, 0, ' ',  58, 614.877f },
    {"DMX", RI::BUF, 0, ' ',  19, 257.349f },
    {"MPO", RI::BUF, 0, ' ',  15, 209.263f },
    {"GCD", RI::PYR, 0, ' ',   8, 176.124f },
    {"DXG", RI::BUF, 0, ' ',   8, 192.124f },
    {"CM5", RI::BUF, 0, ' ',  42, 494.573f },
    // 210

    {"ACA", RI::BUF, 1, ' ',  13, 131.173f }, // peptide linking
    {"ACN", RI::BUF, 0, ' ',   6, 58.0791f },
    {"CCN", RI::BUF, 0, ' ',   3, 41.0519f },
    {"GLC", RI::PYR, 0, ' ',  12, 180.156f },
    {"DR6", RI::BUF, 0, ' ', 142, 1527.90f },
    {"NH4", RI::BUF, 0, ' ',   4, 18.0385f },
    {"AZI", RI::BUF, 0, ' ',   0, 42.0201f },
    {"BNG", RI::PYR, 0, ' ',  30, 306.395f },
    {"BOG", RI::PYR, 0, ' ',  28, 292.369f },
    {"BGC", RI::PYR, 0, ' ',  12, 180.156f },
    {"BCN", RI::BUF, 0, ' ',  13, 163.172f },
    // 220

    {"BRO", RI::BUF, 0, ' ',   0, 79.9040f },
    {"CAC", RI::BUF, 0, ' ',   6, 136.989f },
    {"CBX", RI::BUF, 0, ' ',   2, 46.0254f },
    {"ACY", RI::BUF, 0, ' ',   4, 60.0520f },
    {"CBM", RI::BUF, 0, ' ',   4, 60.0520f },
    {"CLO", RI::BUF, 0, ' ',   0, 35.4530f },
    {"3CO", RI::BUF, 0, ' ',   0, 58.9332f },
    {"NCO", RI::BUF, 0, ' ',  18, 161.116f },
    {"CU1", RI::BUF, 0, ' ',   0, 63.5460f },
    {"CYN", RI::BUF, 0, ' ',   0, 26.0174f },
    {"MA4", RI::BUF, 0, ' ',  44, 508.600f },
    // 230

    {"TAR", RI::BUF, 0, ' ',   6, 150.087f },
    {"GLO", RI::BUF, 0, ' ',  12, 180.156f },  // d-saccharide
    {"MTL", RI::BUF, 0, ' ',  14, 182.172f },
    {"SOR", RI::BUF, 0, ' ',  14, 182.172f },
    {"DMU", RI::BUF, 0, ' ',  42, 482.562f },  // d-saccharide
    {"DDQ", RI::BUF, 0, ' ',  27, 201.349f },
    {"DMF", RI::BUF, 0, ' ',   7, 73.0938f },
    {"DIO", RI::BUF, 0, ' ',   8, 88.1051f },
    {"DOX", RI::BUF, 0, ' ',   8, 88.1051f },
    {"12P", RI::BUF, 0, ' ',  50, 546.646f },
    {"SDS", RI::BUF, 0, ' ',  26, 266.397f },
    // 240

    {"LMT", RI::BUF, 0, ' ',  46, 510.615f },  // d-saccharide
    {"EOH", RI::BUF, 0, ' ',   6, 46.0684f },
    {"EEE", RI::BUF, 0, ' ',   8, 88.1051f },
    {"EGL", RI::BUF, 0, ' ',   6, 62.0678f },
    {"FLO", RI::BUF, 0, ' ',   0, 18.9984f },
    {"TRT", RI::BUF, 0, ' ',  36, 352.508f },
    {"FCY", RI::BUF, 0, ' ',   7, 121.158f },
    {"FRU", RI::BUF, 0, ' ',  12, 180.156f },  // saccharide
    {"GBL", RI::BUF, 0, ' ',   6, 86.0892f },
    {"GPX", RI::BUF, 0, ' ',  14, 505.165f },
    {"HTO", RI::BUF, 0, ' ',  16, 148.200f },
    // 250

    {"HTG", RI::BUF, 0, ' ',  26, 294.408f },
    {"B7G", RI::BUF, 0, ' ',  26, 278.342f },
    {"C10", RI::BUF, 0, ' ',  46, 422.596f },
    {"16D", RI::BUF, 0, ' ',  16, 116.205f },
    {"HEZ", RI::BUF, 0, ' ',  14, 118.174f },
    {"IOD", RI::BUF, 0, ' ',   0, 126.904f },
    {"IDO", RI::BUF, 0, ' ',   0, 126.904f },
    {"ICI", RI::BUF, 0, ' ',   8, 192.124f },
    {"ICT", RI::BUF, 0, ' ',   8, 192.124f },
    {"TLA", RI::BUF, 0, ' ',   6, 150.087f },
    {"LAT", RI::BUF, 0, ' ',  22, 342.296f },  // saccharide
    // 260

    {"LBT", RI::BUF, 0, ' ',  22, 342.296f },  // saccharide
    {"LDA", RI::BUF, 0, ' ',  31, 229.402f },
    {"MN3", RI::BUF, 0, ' ',   0, 54.9380f },
    {"MRY", RI::BUF, 0, ' ',  10, 122.120f },
    {"MOH", RI::BUF, 0, ' ',   4, 32.0419f },
    {"BEQ", RI::BUF, 0, ' ',  38, 342.517f },
    {"C15", RI::BUF, 0, ' ',  38, 336.554f },
    {"MG8", RI::BUF, 0, ' ',  31, 321.410f },
    {"POL", RI::BUF, 0, ' ',   8, 60.0950f },
    {"NO3", RI::BUF, 0, ' ',   0, 62.0049f },
    {"JEF", RI::BUF, 0, ' ',  63, 597.822f },
    // 270

    {"P4C", RI::BUF, 0, ' ',  28, 324.367f },
    {"CE1", RI::BUF, 0, ' ',  58, 538.755f },
    {"DIA", RI::BUF, 0, ' ',  20, 144.258f },
    {"CXE", RI::BUF, 0, ' ',  42, 378.544f },
    {"IPH", RI::BUF, 0, ' ',   6, 94.1112f },
    {"PIN", RI::BUF, 0, ' ',  18, 302.368f },
    {"15P", RI::BUF, 0, ' ', 140, 1529.83f },
    {"CRY", RI::BUF, 0, ' ',   8, 92.0938f },
    {"PGR", RI::BUF, 0, ' ',   8, 76.0944f },
    {"PGQ", RI::BUF, 0, ' ',   8, 76.0944f },
    {"SPD", RI::BUF, 0, ' ',  19, 145.246f },
    // 270

    {"SPK", RI::BUF, 0, ' ',  30, 206.372f },
    {"SPM", RI::BUF, 0, ' ',  26, 202.340f },
    {"SUC", RI::PYR, 0, ' ',  22, 342.296f },
    {"TBU", RI::BUF, 0, ' ',  10, 74.1216f },
    {"TMA", RI::BUF, 0, ' ',  12, 74.1448f },
    {"TEP", RI::BUF, 0, ' ',   8, 180.164f },
    {"SCN", RI::BUF, 0, ' ',   0, 58.0824f },
    {"TRE", RI::PYR, 0, ' ',  22, 342.296f },
    {"ETF", RI::BUF, 0, ' ',   3, 100.040f },
    {"144", RI::BUF, 0, ' ',  12, 122.143f },
    {"UMQ", RI::BUF, 0, ' ',  44, 496.589f },
    // 280

    {"URE", RI::BUF, 0, ' ',   4, 60.0553f },
    {"YT3", RI::BUF, 0, ' ',   0, 88.9059f },
    {"ZN2", RI::BUF, 0, ' ',   0, 65.3800f },
    {"FE2", RI::BUF, 0, ' ',   0, 55.8450f },
    {"3NI", RI::BUF, 0, ' ',   0, 58.6934f },
    {"SIA", RI::PYR, 0, ' ',   0, 0.0f },
    {"XYP", RI::PYR, 0, ' ',   0, 0.0f },
    {"A2G", RI::PYR, 0, ' ',   0, 0.0f },
    {"GLA", RI::PYR, 0, ' ',   0, 0.0f },
    {"NDG", RI::PYR, 0, ' ',   0, 0.0f },
    // 290
    {"NGA", RI::PYR, 0, ' ',   0, 0.0f },
    {"A",   RI::RNA, 2, 'A',  14, 347.221f },
    {"C",   RI::RNA, 2, 'C',  14, 323.197f },
    {"G",   RI::RNA, 2, 'G',  14, 363.221f },
    {"I",   RI::RNA, 2, 'I',  13, 348.206f },
    {"U",   RI::RNA, 2, 'U',  13, 324.181f },
    {"N",   RI::RNA, 2, 'N',  11, 214.11f },

    {"F",   RI::BUF, 0, ' ',   0, 18.9984f },
    {"K",   RI::BUF, 0, ' ',   0, 39.0983f },
    {"DA", RI::DNA, 2, 'A',  14, 331.222f },
    // 300
    {"DC", RI::DNA, 2, 'C',  14, 307.197f },
    {"DG", RI::DNA, 2, 'G',  14, 347.221f },
    {"DI", RI::DNA, 2, 'I',  13, 332.207f },
    {"DT", RI::DNA, 2, 'T',  15, 322.208f },
    {"DU", RI::DNA, 2, 'U',  13, 308.182f },
    {"DN", RI::DNA, 2, 'N',  14, 198.111f },  // unknown DNA
    {"AG",  RI::BUF, 0, ' ',   0, 107.868f },
    {"AL",  RI::BUF, 0, ' ',   0, 26.9815f },
    // 308

    {"BA",  RI::BUF, 0, ' ',   0, 137.327f },
    {"BR",  RI::BUF, 0, ' ',   0, 79.9040f },
    {"CA",  RI::BUF, 0, ' ',   0, 40.0780f },
    {"CD",  RI::BUF, 0, ' ',   0, 112.411f },
    {"CL",  RI::BUF, 0, ' ',   0, 35.4530f },
    {"CM",  RI::BUF, 0, ' ',   4, 60.0520f },
    {"CN",  RI::BUF, 0, ' ',   0, 27.0253f },
    {"CO",  RI::BUF, 0, ' ',   0, 58.9332f },
    {"CS",  RI::BUF, 0, ' ',   0, 132.905f },
    {"CU",  RI::BUF, 0, ' ',   0, 63.5460f },
    {"FE",  RI::BUF, 0, ' ',   0, 55.8450f },
    // 318

    {"HG",  RI::BUF, 0, ' ',   0, 200.590f },
    {"LI",  RI::BUF, 0, ' ',   0, 6.94100f },
    {"MG",  RI::BUF, 0, ' ',   0, 24.3050f },
    {"MN",  RI::BUF, 0, ' ',   0, 54.9380f },
    {"NA",  RI::BUF, 0, ' ',   0, 22.9898f },
    {"NI",  RI::BUF, 0, ' ',   0, 58.6934f },
    {"NO",  RI::ELS, 0, ' ',   0, 30.0061f },
    {"PB",  RI::BUF, 0, ' ',   0, 207.200f },
    {"RB",  RI::BUF, 0, ' ',   0, 85.4678f },
    {"SR",  RI::BUF, 0, ' ',   0, 87.6200f },
    {"Y1",  RI::BUF, 0, ' ',   0, 88.9059f },
    // 328

    {"ZN",  RI::BUF, 0, ' ',   0, 65.3800f },
    {"",    RI::UNKNOWN, 0, ' ', 0, 0.0f }
  };
  return array[idx];
}

ResidueInfo& find_tabulated_residue(const std::string& name) {
  size_t idx = find_tabulated_residue_idx(name);
  return get_residue_info(idx);
}


std::vector<std::string> expand_one_letter_sequence(const std::string& seq,
                                                    ResidueKind kind) {

 std::vector<std::string> r;
  r.reserve(seq.size());
  auto kind_str = [&]() {
    switch (kind) {
      case ResidueKind::AA: return "peptide";
      case ResidueKind::RNA: return "RNA";
      case ResidueKind::DNA: return "DNA";
      default: return "unknown";
    }
  };
  for (size_t i = 0; i != seq.size(); ++i) {
    char c = seq[i];
    if (is_space(c))
      continue;
    if (c == '(') { // special case, e.g. (MSE)
      size_t start = i + 1;
      i = seq.find(')', start);
      if (i == std::string::npos)
        gemmi::fail("unmatched '(' in sequence");
      r.emplace_back(seq, start, i - start);
    } else {
      const char* str = gemmi::expand_one_letter(c, kind);
      if (str == nullptr)
        gemmi::fail("unexpected letter in ", kind_str(), " sequence: ", c,
             " (", std::to_string(int(c)), ')');
      r.emplace_back(str);
    }
  }
  return r;
}
}
