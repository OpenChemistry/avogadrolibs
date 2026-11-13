// Copyright Global Phasing Ltd.

#include <gemmi/symmetry.hpp>
#include <cmath>      // for fabs
#include <cstring>    // for memchr, strchr

static const char* skip_space(const char* p) {
  if (p)
    while (*p == ' ' || *p == '\t' || *p == '_') // '_' can be used as space
      ++p;
  return p;
}

namespace gemmi {

// TRIPLET -> OP

// param only can be set to 'h', 'x', 'a' or ' ' (any), to limit accepted characters.
// decimal_fract is useful only for non-crystallographic ops (such as x+0.12)
std::array<int, 4> parse_triplet_part(const std::string& s, char& notation, double* decimal_fract) {
  constexpr char a_ = 'a' & ~3;
  constexpr char h_ = 'h' & ~3;
  constexpr char x_ = 'x' & ~3;
  static const signed char letter2index[] =
    // a     b     c    d  e  f  g   h    i  j   k     l
    { a_+0, a_+1, a_+2, 0, 0, 0, 0, h_+0, 0, 0, h_+1, h_+2,
    // m  n  o  p  q  r  s  t  u  v  w   x     y     z
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x_+0, x_+1, x_+2 };
  auto interpret_letter = [&](char c) {
    size_t idx = size_t((c | 0x20) - 'a');  // "|0x20" = to lower
    if (idx >= sizeof(letter2index) || letter2index[idx] == 0)
      fail("unexpected character '", c, "' in: ", s);
    auto value = letter2index[idx];
    int detected_notation = value & ~3;
    if ((notation | 0x20) == ' ')
      notation = detected_notation;
    else if (((notation | 0x20) & ~3) != detected_notation)
      fail("Unexpected notation (letter set) in: ", s);
    return value & 3;
  };

  std::array<int, 4> r = { 0, 0, 0, 0 };
  int num = Op::DEN;
  const char* c = s.c_str();
  while (*(c = skip_space(c))) {
    if (*c == '+' || *c == '-') {
      num = (*c == '+' ? Op::DEN : -Op::DEN);
      c = skip_space(++c);
    }
    if (num == 0)
      fail("wrong or unsupported triplet format: " + s);
    int r_idx;
    int den = 1;
    double fract = 0;
    if ((*c >= '0' && *c <= '9') || *c == '.') {
      // syntax examples in this branch: "1", "-1/2", "+2*x", "1/2 * b"
      char* endptr;
      int n = std::strtol(c, &endptr, 10);
      // some COD CIFs have decimal fractions ("-x+0.25", ".5+Y", "1.25000-y")
      if (*endptr == '.') {
        // avoiding strtod() etc which is locale-dependent
        fract = n;
        for (double denom = 0.1; *++endptr >= '0' && *endptr <= '9'; denom *= 0.1)
          fract += int(*endptr - '0') * denom;
        double rounded = std::round(fract * num);
        if (!decimal_fract) {
          if (std::fabs(rounded - fract * num) > 0.05)
            fail("unexpected number in a symmetry triplet part: " + s);
          num = int(rounded);
        }
      } else {
        num *= n;
      }
      if (*endptr == '/')
        den = std::strtol(endptr + 1, &endptr, 10);
      if (*endptr == '*') {
        c = skip_space(endptr + 1);
        r_idx = interpret_letter(*c);
        ++c;
      } else {
        c = endptr;
        r_idx = 3;
      }
    } else {
      // syntax examples in this branch: "x", "+a", "-k/3"
      r_idx = interpret_letter(*c);
      c = skip_space(++c);
      if (*c == '/') {
        char* endptr;
        den = std::strtol(c + 1, &endptr, 10);
        c = endptr;
      }
    }
    if (den != 1) {
      if (den <= 0 || Op::DEN % den != 0 || fract != 0)
        fail("Wrong denominator " + std::to_string(den) + " in: " + s);
      num /= den;
    }
    r[r_idx] += num;
    if (decimal_fract)
      decimal_fract[r_idx] = num > 0 ? fract : -fract;
    num = 0;
  }
  if (num != 0)
    fail("trailing sign in: " + s);
  return r;
}

Op parse_triplet(const std::string& s, char notation) {
  if (std::count(s.begin(), s.end(), ',') != 2)
    fail("expected exactly two commas in triplet");
  size_t comma1 = s.find(',');
  size_t comma2 = s.find(',', comma1 + 1);
  char save_notation = notation;
  notation = (notation | 0x20) & ~3;
  if (notation != 'x' && notation != 'h' && notation != '`' && notation != ' ')  // '`' == a' & ~3
    fail("parse_triplet(): unexpected notation='", save_notation, "'");
  auto a = parse_triplet_part(s.substr(0, comma1), notation);
  auto b = parse_triplet_part(s.substr(comma1 + 1, comma2 - (comma1 + 1)), notation);
  auto c = parse_triplet_part(s.substr(comma2 + 1), notation);
  Op::Rot rot = {{{a[0], a[1], a[2]}, {b[0], b[1], b[2]}, {c[0], c[1], c[2]}}};
  Op::Tran tran = {a[3], b[3], c[3]};
  if (notation == 'h') {
    if (tran != Op::Tran{0, 0, 0})
      fail("parse_triplet(): reciprocal-space Op cannot have translation: ", s);
    rot = Op::transpose(rot);
  }
  return { rot, tran, notation };
}


// OP -> TRIPLET

namespace {

// much faster than s += std::to_string(n) for n in 0 ... 99
void append_small_number(std::string& s, int n) {
  if (n < 0 || n >= 100) {
    s += std::to_string(n);
  } else if (n < 10) {
    s += char('0' + n);
  } else { // 10 ... 99
    int tens = n / 10;
    s += char('0' + tens);
    s += char('0' + n - 10 * tens);
  }
}

void append_sign_of(std::string& s, int n) {
  if (n < 0)
    s += '-';
  else if (!s.empty())
    s += '+';
}

// append w/DEN fraction reduced to the lowest terms
std::pair<int,int> get_op_fraction(int w) {
  // Op::DEN == 24 == 2 * 2 * 2 * 3
  int denom = 1;
  for (int i = 0; i != 3; ++i)
    if (w % 2 == 0)  // 2, 2, 2
      w /= 2;
    else
      denom *= 2;
  if (w % 3 == 0)    // 3
    w /= 3;
  else
    denom *= 3;
  return {w, denom};
}

void append_fraction(std::string& s, std::pair<int,int> frac) {
  append_small_number(s, frac.first);
  if (frac.second != 1) {
    s += '/';
    append_small_number(s, frac.second);
  }
}

std::string make_triplet_part(const std::array<int, 3>& xyz, int w, char style) {
  std::string s;
  const char* letters = "xyz hkl abc XYZ HKL ABC";
  switch((style | 0x20) & ~3) {  // |0x20 converts to lower case
    case 'h': letters += 4; break;
    case '`': letters += 8; break;  // 'a', because 'a'&~3 == 0x60 == '`'
  }
  if (!(style & 0x20))  // not lower
    letters += 12;
  for (int i = 0; i != 3; ++i)
    if (xyz[i] != 0) {
      append_sign_of(s, xyz[i]);
      int a = std::abs(xyz[i]);
      if (a != Op::DEN) {
        std::pair<int,int> frac = get_op_fraction(a);
        if (frac.first == 1) {  // e.g. "x/3"
          s += letters[i];
          s += '/';
          append_small_number(s, frac.second);
        } else {  // e.g. "2/3*x"
          append_fraction(s, frac);
          s += '*';
          s += letters[i];
        }
      } else {
        s += letters[i];
      }
    }
  if (w != 0) {
    append_sign_of(s, w);
    std::pair<int,int> frac = get_op_fraction(std::abs(w));
    append_fraction(s, frac);
  }
  return s;
}

}  // anonymous namespace

Op seitz_to_op(const std::array<std::array<double,4>, 4>& t) {
  static_assert(Op::DEN == 24, "");
  auto check_round = [](double d) {
    double r = std::round(d * Op::DEN);
    if (std::fabs(r - d * Op::DEN) > 0.05)
      fail("all numbers in Seitz matrix must be equal Z/24");
    return static_cast<int>(r);
  };
  Op op;
  if (std::fabs(t[3][0]) + std::fabs(t[3][1]) + std::fabs(t[3][2]) +
      std::fabs(t[3][3] - 1) > 1e-3)
    fail("the last row in Seitz matrix must be [0 0 0 1]");
  for (int i = 0; i < 3; ++i) {
    for (int j = 0; j < 3; ++j)
      op.rot[i][j] = check_round(t[i][j]);
    op.tran[i] = check_round(t[i][3]);
  }
  op.notation = 'x';
  return op;
}

void append_op_fraction(std::string& s, int w) {
  append_fraction(s, get_op_fraction(w));
}

std::string Op::triplet(char style) const {
  if (style == ' ')
    style = (notation & ~0x20) ? notation : 'x';
  char lower_style = (style | 0x20) & ~3;
  if (lower_style == 'h' && !is_hkl())
    fail("triplet(): can't write real-space triplet as hkl");
  if (lower_style != 'h' && is_hkl())
    fail("triplet(): can't write reciprocal-space triplet as xyz");
  // 'x'==0x78, 'h'==0x68, 'a'==0x61, so 'a'&~3 == 0x60 == '`'
  if (lower_style != 'x' && lower_style != 'h' && lower_style != '`')
    fail("unexpected triplet style: '", style, "'");
  // parse_triplet() transposes hkl ops such as l,h,k
  auto r = !is_hkl()? rot : transposed_rot();
  return make_triplet_part(r[0], tran[0], style) +
   "," + make_triplet_part(r[1], tran[1], style) +
   "," + make_triplet_part(r[2], tran[2], style);
}


// INTERPRETING HALL SYMBOLS
// based on both ITfC vol.B ch.1.4 (2010)
// and http://cci.lbl.gov/sginfo/hall_symbols.html

// matrices for Nz from Table 3 and 4 from hall_symbols.html
namespace {
Op::Rot hall_rotation_z(int N) {
  constexpr int d = Op::DEN;
  switch (N) {
    case 1: return {{{d,0,0},  {0,d,0},  {0,0,d}}};
    case 2: return {{{-d,0,0}, {0,-d,0}, {0,0,d}}};
    case 3: return {{{0,-d,0}, {d,-d,0}, {0,0,d}}};
    case 4: return {{{0,-d,0}, {d,0,0},  {0,0,d}}};
    case 6: return {{{d,-d,0}, {d,0,0},  {0,0,d}}};
    case '\'': return {{{0,-d,0},{-d,0,0}, {0,0,-d}}};
    case '"':  return {{{0,d,0}, { d,0,0}, {0,0,-d}}};
    case '*':  return {{{0,0,d}, { d,0,0}, {0,d,0}}};
    default: fail("incorrect axis definition");
  }
}
Op::Tran hall_translation_from_symbol(char symbol) {
  constexpr int h = Op::DEN / 2;
  constexpr int q = Op::DEN / 4;
  switch (symbol) {
    case 'a': return {h, 0, 0};
    case 'b': return {0, h, 0};
    case 'c': return {0, 0, h};
    case 'n': return {h, h, h};
    case 'u': return {q, 0, 0};
    case 'v': return {0, q, 0};
    case 'w': return {0, 0, q};
    case 'd': return {q, q, q};
    default: fail(std::string("unknown symbol: ") + symbol);
  }
}

Op hall_matrix_symbol(const char* start, const char* end, int pos, int& prev) {
  Op op = Op::identity();
  bool neg = (*start == '-');
  const char* p = (neg ? start + 1 : start);
  if (*p < '1' || *p == '5' || *p > '6')
    fail("wrong n-fold order notation: " + std::string(start, end));
  int N = *p++ - '0';
  int fractional_tran = 0;
  char principal_axis = '\0';
  char diagonal_axis = '\0';
  for (; p < end; ++p) {
    if (*p >= '1' && *p <= '5') {
      if (fractional_tran != '\0')
        fail("two numeric subscripts");
      fractional_tran = *p - '0';
    } else if (*p == '\'' || *p == '"' || *p == '*') {
      if (N != (*p == '*' ? 3 : 2))
        fail("wrong symbol: " + std::string(start, end));
      diagonal_axis = *p;
    } else if (*p == 'x' || *p == 'y' || *p == 'z') {
      principal_axis = *p;
    } else {
      op.translate(hall_translation_from_symbol(*p));
    }
  }
  // fill in implicit values
  if (!principal_axis && !diagonal_axis) {
    if (pos == 1) {
      principal_axis = 'z';
    } else if (pos == 2 && N == 2) {
      if (prev == 2 || prev == 4)
        principal_axis = 'x';
      else if (prev == 3 || prev == 6)
        diagonal_axis = '\'';
    } else if (pos == 3 && N == 3) {
      diagonal_axis = '*';
    } else if (N != 1) {
      fail("missing axis");
    }
  }
  // get the operation
  op.rot = hall_rotation_z(diagonal_axis ? diagonal_axis : N);
  if (neg)
    op.rot = op.negated_rot();
  auto alter_order = [](const Op::Rot& r, int i, int j, int k) {
    return Op::Rot{{ {r[i][i], r[i][j], r[i][k]},
                     {r[j][i], r[j][j], r[j][k]},
                     {r[k][i], r[k][j], r[k][k]} }};
  };
  if (principal_axis == 'x')
    op.rot = alter_order(op.rot, 2, 0, 1);
  else if (principal_axis == 'y')
    op.rot = alter_order(op.rot, 1, 2, 0);
  if (fractional_tran)
    op.tran[principal_axis - 'x'] += Op::DEN / N * fractional_tran;
  prev = N;
  return op;
}

// Parses either short (0 0 1) or long notation (x,y,z+1/12)
// but without multipliers (such as 1/2x) to keep things simple for now.
Op parse_hall_change_of_basis(const char* start, const char* end) {
  if (std::memchr(start, ',', end - start) != nullptr) // long symbol
    return parse_triplet(std::string(start, end));
  // short symbol (0 0 1)
  Op cob = Op::identity();
  char* endptr;
  for (int i = 0; i != 3; ++i) {
    cob.tran[i] = std::strtol(start, &endptr, 10) % 12 * (Op::DEN / 12);
    start = endptr;
  }
  if (endptr != end)
    fail("unexpected change-of-basis format: " + std::string(start, end));
  return cob;
}
}  // anonymous namespace

GroupOps generators_from_hall(const char* hall) {
  auto find_blank = [](const char* p) {
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '_') // '_' == ' '
      ++p;
    return p;
  };
  if (hall == nullptr)
    fail("null");
  hall = skip_space(hall);
  GroupOps ops;
  ops.sym_ops.emplace_back(Op::identity());
  bool centrosym = (hall[0] == '-');
  const char* lat = skip_space(centrosym ? hall + 1 : hall);
  if (!lat)
    fail("not a hall symbol: " + std::string(hall));
  ops.cen_ops = centring_vectors(*lat);
  int counter = 0;
  int prev = 0;
  const char* part = skip_space(lat + 1);
  while (*part != '\0' && *part != '(') {
    const char* space = find_blank(part);
    ++counter;
    if (part[0] != '1' || (part[1] != ' ' && part[1] != '\0')) {
      Op op = hall_matrix_symbol(part, space, counter, prev);
      ops.sym_ops.emplace_back(op);
    }
    part = skip_space(space);
  }
  if (centrosym)
    ops.sym_ops.push_back({Op::identity().negated_rot(), {0,0,0}, 'x'});
  if (*part == '(') {
    const char* rb = std::strchr(part, ')');
    if (!rb)
      fail("missing ')': " + std::string(hall));
    if (ops.sym_ops.empty())
      fail("misplaced translation: " + std::string(hall));
    ops.change_basis_forward(parse_hall_change_of_basis(part + 1, rb));

    if (*skip_space(find_blank(rb + 1)) != '\0')
      fail("unexpected characters after ')': " + std::string(hall));
  }
  return ops;
}


const SpaceGroup spacegroup_tables::main[564] = {
  // This table was generated by tools/gen_sg_table.py.
  // First 530 entries in the same order as in SgInfo, sgtbx and ITB.
  // Note: spacegroup 68 has three duplicates with different H-M names.
  {  1,    1, "P 1"       ,   0,     "", "P 1"           , 0 }, //   0
  {  2,    2, "P -1"      ,   0,     "", "-P 1"          , 0 }, //   1
  {  3,    3, "P 1 2 1"   ,   0,    "b", "P 2y"          , 0 }, //   2
  {  3, 1003, "P 1 1 2"   ,   0,    "c", "P 2"           , 1 }, //   3
  {  3,    0, "P 2 1 1"   ,   0,    "a", "P 2x"          , 2 }, //   4
  {  4,    4, "P 1 21 1"  ,   0,    "b", "P 2yb"         , 0 }, //   5
  {  4, 1004, "P 1 1 21"  ,   0,    "c", "P 2c"          , 1 }, //   6
  {  4,    0, "P 21 1 1"  ,   0,    "a", "P 2xa"         , 2 }, //   7
  {  5,    5, "C 1 2 1"   ,   0,   "b1", "C 2y"          , 0 }, //   8
  {  5, 2005, "A 1 2 1"   ,   0,   "b2", "A 2y"          , 3 }, //   9
  {  5, 4005, "I 1 2 1"   ,   0,   "b3", "I 2y"          , 4 }, //  10
  {  5,    0, "A 1 1 2"   ,   0,   "c1", "A 2"           , 1 }, //  11
  {  5, 1005, "B 1 1 2"   ,   0,   "c2", "B 2"           , 5 }, //  12
  {  5,    0, "I 1 1 2"   ,   0,   "c3", "I 2"           , 6 }, //  13
  {  5,    0, "B 2 1 1"   ,   0,   "a1", "B 2x"          , 2 }, //  14
  {  5,    0, "C 2 1 1"   ,   0,   "a2", "C 2x"          , 7 }, //  15
  {  5,    0, "I 2 1 1"   ,   0,   "a3", "I 2x"          , 8 }, //  16
  {  6,    6, "P 1 m 1"   ,   0,    "b", "P -2y"         , 0 }, //  17
  {  6, 1006, "P 1 1 m"   ,   0,    "c", "P -2"          , 1 }, //  18
  {  6,    0, "P m 1 1"   ,   0,    "a", "P -2x"         , 2 }, //  19
  {  7,    7, "P 1 c 1"   ,   0,   "b1", "P -2yc"        , 0 }, //  20
  {  7,    0, "P 1 n 1"   ,   0,   "b2", "P -2yac"       , 9 }, //  21
  {  7,    0, "P 1 a 1"   ,   0,   "b3", "P -2ya"        , 3 }, //  22
  {  7,    0, "P 1 1 a"   ,   0,   "c1", "P -2a"         , 1 }, //  23
  {  7,    0, "P 1 1 n"   ,   0,   "c2", "P -2ab"        , 10}, //  24
  {  7, 1007, "P 1 1 b"   ,   0,   "c3", "P -2b"         , 5 }, //  25
  {  7,    0, "P b 1 1"   ,   0,   "a1", "P -2xb"        , 2 }, //  26
  {  7,    0, "P n 1 1"   ,   0,   "a2", "P -2xbc"       , 11}, //  27
  {  7,    0, "P c 1 1"   ,   0,   "a3", "P -2xc"        , 7 }, //  28
  {  8,    8, "C 1 m 1"   ,   0,   "b1", "C -2y"         , 0 }, //  29
  {  8,    0, "A 1 m 1"   ,   0,   "b2", "A -2y"         , 3 }, //  30
  {  8,    0, "I 1 m 1"   ,   0,   "b3", "I -2y"         , 4 }, //  31
  {  8,    0, "A 1 1 m"   ,   0,   "c1", "A -2"          , 1 }, //  32
  {  8, 1008, "B 1 1 m"   ,   0,   "c2", "B -2"          , 5 }, //  33
  {  8,    0, "I 1 1 m"   ,   0,   "c3", "I -2"          , 6 }, //  34
  {  8,    0, "B m 1 1"   ,   0,   "a1", "B -2x"         , 2 }, //  35
  {  8,    0, "C m 1 1"   ,   0,   "a2", "C -2x"         , 7 }, //  36
  {  8,    0, "I m 1 1"   ,   0,   "a3", "I -2x"         , 8 }, //  37
  {  9,    9, "C 1 c 1"   ,   0,   "b1", "C -2yc"        , 0 }, //  38
  {  9,    0, "A 1 n 1"   ,   0,   "b2", "A -2yab"       , 12}, //  39
  {  9,    0, "I 1 a 1"   ,   0,   "b3", "I -2ya"        , 13}, //  40
  {  9,    0, "A 1 a 1"   ,   0,  "-b1", "A -2ya"        , 3 }, //  41
  {  9,    0, "C 1 n 1"   ,   0,  "-b2", "C -2yac"       , 14}, //  42
  {  9,    0, "I 1 c 1"   ,   0,  "-b3", "I -2yc"        , 4 }, //  43
  {  9,    0, "A 1 1 a"   ,   0,   "c1", "A -2a"         , 1 }, //  44
  {  9,    0, "B 1 1 n"   ,   0,   "c2", "B -2ab"        , 15}, //  45
  {  9,    0, "I 1 1 b"   ,   0,   "c3", "I -2b"         , 16}, //  46
  {  9, 1009, "B 1 1 b"   ,   0,  "-c1", "B -2b"         , 5 }, //  47
  {  9,    0, "A 1 1 n"   ,   0,  "-c2", "A -2ab"        , 10}, //  48
  {  9,    0, "I 1 1 a"   ,   0,  "-c3", "I -2a"         , 6 }, //  49
  {  9,    0, "B b 1 1"   ,   0,   "a1", "B -2xb"        , 2 }, //  50
  {  9,    0, "C n 1 1"   ,   0,   "a2", "C -2xac"       , 17}, //  51
  {  9,    0, "I c 1 1"   ,   0,   "a3", "I -2xc"        , 18}, //  52
  {  9,    0, "C c 1 1"   ,   0,  "-a1", "C -2xc"        , 7 }, //  53
  {  9,    0, "B n 1 1"   ,   0,  "-a2", "B -2xab"       , 11}, //  54
  {  9,    0, "I b 1 1"   ,   0,  "-a3", "I -2xb"        , 8 }, //  55
  { 10,   10, "P 1 2/m 1" ,   0,    "b", "-P 2y"         , 0 }, //  56
  { 10, 1010, "P 1 1 2/m" ,   0,    "c", "-P 2"          , 1 }, //  57
  { 10,    0, "P 2/m 1 1" ,   0,    "a", "-P 2x"         , 2 }, //  58
  { 11,   11, "P 1 21/m 1",   0,    "b", "-P 2yb"        , 0 }, //  59
  { 11, 1011, "P 1 1 21/m",   0,    "c", "-P 2c"         , 1 }, //  60
  { 11,    0, "P 21/m 1 1",   0,    "a", "-P 2xa"        , 2 }, //  61
  { 12,   12, "C 1 2/m 1" ,   0,   "b1", "-C 2y"         , 0 }, //  62
  { 12,    0, "A 1 2/m 1" ,   0,   "b2", "-A 2y"         , 3 }, //  63
  { 12,    0, "I 1 2/m 1" ,   0,   "b3", "-I 2y"         , 4 }, //  64
  { 12,    0, "A 1 1 2/m" ,   0,   "c1", "-A 2"          , 1 }, //  65
  { 12, 1012, "B 1 1 2/m" ,   0,   "c2", "-B 2"          , 5 }, //  66
  { 12,    0, "I 1 1 2/m" ,   0,   "c3", "-I 2"          , 6 }, //  67
  { 12,    0, "B 2/m 1 1" ,   0,   "a1", "-B 2x"         , 2 }, //  68
  { 12,    0, "C 2/m 1 1" ,   0,   "a2", "-C 2x"         , 7 }, //  69
  { 12,    0, "I 2/m 1 1" ,   0,   "a3", "-I 2x"         , 8 }, //  70
  { 13,   13, "P 1 2/c 1" ,   0,   "b1", "-P 2yc"        , 0 }, //  71
  { 13,    0, "P 1 2/n 1" ,   0,   "b2", "-P 2yac"       , 9 }, //  72
  { 13,    0, "P 1 2/a 1" ,   0,   "b3", "-P 2ya"        , 3 }, //  73
  { 13,    0, "P 1 1 2/a" ,   0,   "c1", "-P 2a"         , 1 }, //  74
  { 13,    0, "P 1 1 2/n" ,   0,   "c2", "-P 2ab"        , 10}, //  75
  { 13, 1013, "P 1 1 2/b" ,   0,   "c3", "-P 2b"         , 5 }, //  76
  { 13,    0, "P 2/b 1 1" ,   0,   "a1", "-P 2xb"        , 2 }, //  77
  { 13,    0, "P 2/n 1 1" ,   0,   "a2", "-P 2xbc"       , 11}, //  78
  { 13,    0, "P 2/c 1 1" ,   0,   "a3", "-P 2xc"        , 7 }, //  79
  { 14,   14, "P 1 21/c 1",   0,   "b1", "-P 2ybc"       , 0 }, //  80
  { 14, 2014, "P 1 21/n 1",   0,   "b2", "-P 2yn"        , 9 }, //  81
  { 14, 3014, "P 1 21/a 1",   0,   "b3", "-P 2yab"       , 3 }, //  82
  { 14,    0, "P 1 1 21/a",   0,   "c1", "-P 2ac"        , 1 }, //  83
  { 14,    0, "P 1 1 21/n",   0,   "c2", "-P 2n"         , 10}, //  84
  { 14, 1014, "P 1 1 21/b",   0,   "c3", "-P 2bc"        , 5 }, //  85
  { 14,    0, "P 21/b 1 1",   0,   "a1", "-P 2xab"       , 2 }, //  86
  { 14,    0, "P 21/n 1 1",   0,   "a2", "-P 2xn"        , 11}, //  87
  { 14,    0, "P 21/c 1 1",   0,   "a3", "-P 2xac"       , 7 }, //  88
  { 15,   15, "C 1 2/c 1" ,   0,   "b1", "-C 2yc"        , 0 }, //  89
  { 15,    0, "A 1 2/n 1" ,   0,   "b2", "-A 2yab"       , 12}, //  90
  { 15,    0, "I 1 2/a 1" ,   0,   "b3", "-I 2ya"        , 13}, //  91
  { 15,    0, "A 1 2/a 1" ,   0,  "-b1", "-A 2ya"        , 3 }, //  92
  { 15,    0, "C 1 2/n 1" ,   0,  "-b2", "-C 2yac"       , 19}, //  93
  { 15,    0, "I 1 2/c 1" ,   0,  "-b3", "-I 2yc"        , 4 }, //  94
  { 15,    0, "A 1 1 2/a" ,   0,   "c1", "-A 2a"         , 1 }, //  95
  { 15,    0, "B 1 1 2/n" ,   0,   "c2", "-B 2ab"        , 15}, //  96
  { 15,    0, "I 1 1 2/b" ,   0,   "c3", "-I 2b"         , 16}, //  97
  { 15, 1015, "B 1 1 2/b" ,   0,  "-c1", "-B 2b"         , 5 }, //  98
  { 15,    0, "A 1 1 2/n" ,   0,  "-c2", "-A 2ab"        , 10}, //  99
  { 15,    0, "I 1 1 2/a" ,   0,  "-c3", "-I 2a"         , 6 }, // 100
  { 15,    0, "B 2/b 1 1" ,   0,   "a1", "-B 2xb"        , 2 }, // 101
  { 15,    0, "C 2/n 1 1" ,   0,   "a2", "-C 2xac"       , 17}, // 102
  { 15,    0, "I 2/c 1 1" ,   0,   "a3", "-I 2xc"        , 18}, // 103
  { 15,    0, "C 2/c 1 1" ,   0,  "-a1", "-C 2xc"        , 7 }, // 104
  { 15,    0, "B 2/n 1 1" ,   0,  "-a2", "-B 2xab"       , 11}, // 105
  { 15,    0, "I 2/b 1 1" ,   0,  "-a3", "-I 2xb"        , 8 }, // 106
  { 16,   16, "P 2 2 2"   ,   0,     "", "P 2 2"         , 0 }, // 107
  { 17,   17, "P 2 2 21"  ,   0,     "", "P 2c 2"        , 0 }, // 108
  { 17, 1017, "P 21 2 2"  ,   0,  "cab", "P 2a 2a"       , 1 }, // 109
  { 17, 2017, "P 2 21 2"  ,   0,  "bca", "P 2 2b"        , 2 }, // 110
  { 18,   18, "P 21 21 2" ,   0,     "", "P 2 2ab"       , 0 }, // 111
  { 18, 3018, "P 2 21 21" ,   0,  "cab", "P 2bc 2"       , 1 }, // 112
  { 18, 2018, "P 21 2 21" ,   0,  "bca", "P 2ac 2ac"     , 2 }, // 113
  { 19,   19, "P 21 21 21",   0,     "", "P 2ac 2ab"     , 0 }, // 114
  { 20,   20, "C 2 2 21"  ,   0,     "", "C 2c 2"        , 0 }, // 115
  { 20,    0, "A 21 2 2"  ,   0,  "cab", "A 2a 2a"       , 1 }, // 116
  { 20,    0, "B 2 21 2"  ,   0,  "bca", "B 2 2b"        , 2 }, // 117
  { 21,   21, "C 2 2 2"   ,   0,     "", "C 2 2"         , 0 }, // 118
  { 21,    0, "A 2 2 2"   ,   0,  "cab", "A 2 2"         , 1 }, // 119
  { 21,    0, "B 2 2 2"   ,   0,  "bca", "B 2 2"         , 2 }, // 120
  { 22,   22, "F 2 2 2"   ,   0,     "", "F 2 2"         , 0 }, // 121
  { 23,   23, "I 2 2 2"   ,   0,     "", "I 2 2"         , 0 }, // 122
  { 24,   24, "I 21 21 21",   0,     "", "I 2b 2c"       , 0 }, // 123
  { 25,   25, "P m m 2"   ,   0,     "", "P 2 -2"        , 0 }, // 124
  { 25,    0, "P 2 m m"   ,   0,  "cab", "P -2 2"        , 1 }, // 125
  { 25,    0, "P m 2 m"   ,   0,  "bca", "P -2 -2"       , 2 }, // 126
  { 26,   26, "P m c 21"  ,   0,     "", "P 2c -2"       , 0 }, // 127
  { 26,    0, "P c m 21"  ,   0, "ba-c", "P 2c -2c"      , 7 }, // 128
  { 26,    0, "P 21 m a"  ,   0,  "cab", "P -2a 2a"      , 1 }, // 129
  { 26,    0, "P 21 a m"  ,   0, "-cba", "P -2 2a"       , 3 }, // 130
  { 26,    0, "P b 21 m"  ,   0,  "bca", "P -2 -2b"      , 2 }, // 131
  { 26,    0, "P m 21 b"  ,   0, "a-cb", "P -2b -2"      , 5 }, // 132
  { 27,   27, "P c c 2"   ,   0,     "", "P 2 -2c"       , 0 }, // 133
  { 27,    0, "P 2 a a"   ,   0,  "cab", "P -2a 2"       , 1 }, // 134
  { 27,    0, "P b 2 b"   ,   0,  "bca", "P -2b -2b"     , 2 }, // 135
  { 28,   28, "P m a 2"   ,   0,     "", "P 2 -2a"       , 0 }, // 136
  { 28,    0, "P b m 2"   ,   0, "ba-c", "P 2 -2b"       , 7 }, // 137
  { 28,    0, "P 2 m b"   ,   0,  "cab", "P -2b 2"       , 1 }, // 138
  { 28,    0, "P 2 c m"   ,   0, "-cba", "P -2c 2"       , 3 }, // 139
  { 28,    0, "P c 2 m"   ,   0,  "bca", "P -2c -2c"     , 2 }, // 140
  { 28,    0, "P m 2 a"   ,   0, "a-cb", "P -2a -2a"     , 5 }, // 141
  { 29,   29, "P c a 21"  ,   0,     "", "P 2c -2ac"     , 0 }, // 142
  { 29,    0, "P b c 21"  ,   0, "ba-c", "P 2c -2b"      , 7 }, // 143
  { 29,    0, "P 21 a b"  ,   0,  "cab", "P -2b 2a"      , 1 }, // 144
  { 29,    0, "P 21 c a"  ,   0, "-cba", "P -2ac 2a"     , 3 }, // 145
  { 29,    0, "P c 21 b"  ,   0,  "bca", "P -2bc -2c"    , 2 }, // 146
  { 29,    0, "P b 21 a"  ,   0, "a-cb", "P -2a -2ab"    , 5 }, // 147
  { 30,   30, "P n c 2"   ,   0,     "", "P 2 -2bc"      , 0 }, // 148
  { 30,    0, "P c n 2"   ,   0, "ba-c", "P 2 -2ac"      , 7 }, // 149
  { 30,    0, "P 2 n a"   ,   0,  "cab", "P -2ac 2"      , 1 }, // 150
  { 30,    0, "P 2 a n"   ,   0, "-cba", "P -2ab 2"      , 3 }, // 151
  { 30,    0, "P b 2 n"   ,   0,  "bca", "P -2ab -2ab"   , 2 }, // 152
  { 30,    0, "P n 2 b"   ,   0, "a-cb", "P -2bc -2bc"   , 5 }, // 153
  { 31,   31, "P m n 21"  ,   0,     "", "P 2ac -2"      , 0 }, // 154
  { 31,    0, "P n m 21"  ,   0, "ba-c", "P 2bc -2bc"    , 7 }, // 155
  { 31,    0, "P 21 m n"  ,   0,  "cab", "P -2ab 2ab"    , 1 }, // 156
  { 31,    0, "P 21 n m"  ,   0, "-cba", "P -2 2ac"      , 3 }, // 157
  { 31,    0, "P n 21 m"  ,   0,  "bca", "P -2 -2bc"     , 2 }, // 158
  { 31,    0, "P m 21 n"  ,   0, "a-cb", "P -2ab -2"     , 5 }, // 159
  { 32,   32, "P b a 2"   ,   0,     "", "P 2 -2ab"      , 0 }, // 160
  { 32,    0, "P 2 c b"   ,   0,  "cab", "P -2bc 2"      , 1 }, // 161
  { 32,    0, "P c 2 a"   ,   0,  "bca", "P -2ac -2ac"   , 2 }, // 162
  { 33,   33, "P n a 21"  ,   0,     "", "P 2c -2n"      , 0 }, // 163
  { 33,    0, "P b n 21"  ,   0, "ba-c", "P 2c -2ab"     , 7 }, // 164
  { 33,    0, "P 21 n b"  ,   0,  "cab", "P -2bc 2a"     , 1 }, // 165
  { 33,    0, "P 21 c n"  ,   0, "-cba", "P -2n 2a"      , 3 }, // 166
  { 33,    0, "P c 21 n"  ,   0,  "bca", "P -2n -2ac"    , 2 }, // 167
  { 33,    0, "P n 21 a"  ,   0, "a-cb", "P -2ac -2n"    , 5 }, // 168
  { 34,   34, "P n n 2"   ,   0,     "", "P 2 -2n"       , 0 }, // 169
  { 34,    0, "P 2 n n"   ,   0,  "cab", "P -2n 2"       , 1 }, // 170
  { 34,    0, "P n 2 n"   ,   0,  "bca", "P -2n -2n"     , 2 }, // 171
  { 35,   35, "C m m 2"   ,   0,     "", "C 2 -2"        , 0 }, // 172
  { 35,    0, "A 2 m m"   ,   0,  "cab", "A -2 2"        , 1 }, // 173
  { 35,    0, "B m 2 m"   ,   0,  "bca", "B -2 -2"       , 2 }, // 174
  { 36,   36, "C m c 21"  ,   0,     "", "C 2c -2"       , 0 }, // 175
  { 36,    0, "C c m 21"  ,   0, "ba-c", "C 2c -2c"      , 7 }, // 176
  { 36,    0, "A 21 m a"  ,   0,  "cab", "A -2a 2a"      , 1 }, // 177
  { 36,    0, "A 21 a m"  ,   0, "-cba", "A -2 2a"       , 3 }, // 178
  { 36,    0, "B b 21 m"  ,   0,  "bca", "B -2 -2b"      , 2 }, // 179
  { 36,    0, "B m 21 b"  ,   0, "a-cb", "B -2b -2"      , 5 }, // 180
  { 37,   37, "C c c 2"   ,   0,     "", "C 2 -2c"       , 0 }, // 181
  { 37,    0, "A 2 a a"   ,   0,  "cab", "A -2a 2"       , 1 }, // 182
  { 37,    0, "B b 2 b"   ,   0,  "bca", "B -2b -2b"     , 2 }, // 183
  { 38,   38, "A m m 2"   ,   0,     "", "A 2 -2"        , 0 }, // 184
  { 38,    0, "B m m 2"   ,   0, "ba-c", "B 2 -2"        , 7 }, // 185
  { 38,    0, "B 2 m m"   ,   0,  "cab", "B -2 2"        , 1 }, // 186
  { 38,    0, "C 2 m m"   ,   0, "-cba", "C -2 2"        , 3 }, // 187
  { 38,    0, "C m 2 m"   ,   0,  "bca", "C -2 -2"       , 2 }, // 188
  { 38,    0, "A m 2 m"   ,   0, "a-cb", "A -2 -2"       , 5 }, // 189
  { 39,   39, "A b m 2"   ,   0,     "", "A 2 -2b"       , 0 }, // 190
  { 39,    0, "B m a 2"   ,   0, "ba-c", "B 2 -2a"       , 7 }, // 191
  { 39,    0, "B 2 c m"   ,   0,  "cab", "B -2a 2"       , 1 }, // 192
  { 39,    0, "C 2 m b"   ,   0, "-cba", "C -2a 2"       , 3 }, // 193
  { 39,    0, "C m 2 a"   ,   0,  "bca", "C -2a -2a"     , 2 }, // 194
  { 39,    0, "A c 2 m"   ,   0, "a-cb", "A -2b -2b"     , 5 }, // 195
  { 40,   40, "A m a 2"   ,   0,     "", "A 2 -2a"       , 0 }, // 196
  { 40,    0, "B b m 2"   ,   0, "ba-c", "B 2 -2b"       , 7 }, // 197
  { 40,    0, "B 2 m b"   ,   0,  "cab", "B -2b 2"       , 1 }, // 198
  { 40,    0, "C 2 c m"   ,   0, "-cba", "C -2c 2"       , 3 }, // 199
  { 40,    0, "C c 2 m"   ,   0,  "bca", "C -2c -2c"     , 2 }, // 200
  { 40,    0, "A m 2 a"   ,   0, "a-cb", "A -2a -2a"     , 5 }, // 201
  { 41,   41, "A b a 2"   ,   0,     "", "A 2 -2ab"      , 0 }, // 202
  { 41,    0, "B b a 2"   ,   0, "ba-c", "B 2 -2ab"      , 7 }, // 203
  { 41,    0, "B 2 c b"   ,   0,  "cab", "B -2ab 2"      , 1 }, // 204
  { 41,    0, "C 2 c b"   ,   0, "-cba", "C -2ac 2"      , 3 }, // 205
  { 41,    0, "C c 2 a"   ,   0,  "bca", "C -2ac -2ac"   , 2 }, // 206
  { 41,    0, "A c 2 a"   ,   0, "a-cb", "A -2ab -2ab"   , 5 }, // 207
  { 42,   42, "F m m 2"   ,   0,     "", "F 2 -2"        , 0 }, // 208
  { 42,    0, "F 2 m m"   ,   0,  "cab", "F -2 2"        , 1 }, // 209
  { 42,    0, "F m 2 m"   ,   0,  "bca", "F -2 -2"       , 2 }, // 210
  { 43,   43, "F d d 2"   ,   0,     "", "F 2 -2d"       , 0 }, // 211
  { 43,    0, "F 2 d d"   ,   0,  "cab", "F -2d 2"       , 1 }, // 212
  { 43,    0, "F d 2 d"   ,   0,  "bca", "F -2d -2d"     , 2 }, // 213
  { 44,   44, "I m m 2"   ,   0,     "", "I 2 -2"        , 0 }, // 214
  { 44,    0, "I 2 m m"   ,   0,  "cab", "I -2 2"        , 1 }, // 215
  { 44,    0, "I m 2 m"   ,   0,  "bca", "I -2 -2"       , 2 }, // 216
  { 45,   45, "I b a 2"   ,   0,     "", "I 2 -2c"       , 0 }, // 217
  { 45,    0, "I 2 c b"   ,   0,  "cab", "I -2a 2"       , 1 }, // 218
  { 45,    0, "I c 2 a"   ,   0,  "bca", "I -2b -2b"     , 2 }, // 219
  { 46,   46, "I m a 2"   ,   0,     "", "I 2 -2a"       , 0 }, // 220
  { 46,    0, "I b m 2"   ,   0, "ba-c", "I 2 -2b"       , 7 }, // 221
  { 46,    0, "I 2 m b"   ,   0,  "cab", "I -2b 2"       , 1 }, // 222
  { 46,    0, "I 2 c m"   ,   0, "-cba", "I -2c 2"       , 3 }, // 223
  { 46,    0, "I c 2 m"   ,   0,  "bca", "I -2c -2c"     , 2 }, // 224
  { 46,    0, "I m 2 a"   ,   0, "a-cb", "I -2a -2a"     , 5 }, // 225
  { 47,   47, "P m m m"   ,   0,     "", "-P 2 2"        , 0 }, // 226
  { 48,   48, "P n n n"   , '1',     "", "P 2 2 -1n"     , 20}, // 227
  { 48,    0, "P n n n"   , '2',     "", "-P 2ab 2bc"    , 0 }, // 228
  { 49,   49, "P c c m"   ,   0,     "", "-P 2 2c"       , 0 }, // 229
  { 49,    0, "P m a a"   ,   0,  "cab", "-P 2a 2"       , 1 }, // 230
  { 49,    0, "P b m b"   ,   0,  "bca", "-P 2b 2b"      , 2 }, // 231
  { 50,   50, "P b a n"   , '1',     "", "P 2 2 -1ab"    , 21}, // 232
  { 50,    0, "P b a n"   , '2',     "", "-P 2ab 2b"     , 0 }, // 233
  { 50,    0, "P n c b"   , '1',  "cab", "P 2 2 -1bc"    , 22}, // 234
  { 50,    0, "P n c b"   , '2',  "cab", "-P 2b 2bc"     , 1 }, // 235
  { 50,    0, "P c n a"   , '1',  "bca", "P 2 2 -1ac"    , 23}, // 236
  { 50,    0, "P c n a"   , '2',  "bca", "-P 2a 2c"      , 2 }, // 237
  { 51,   51, "P m m a"   ,   0,     "", "-P 2a 2a"      , 0 }, // 238
  { 51,    0, "P m m b"   ,   0, "ba-c", "-P 2b 2"       , 7 }, // 239
  { 51,    0, "P b m m"   ,   0,  "cab", "-P 2 2b"       , 1 }, // 240
  { 51,    0, "P c m m"   ,   0, "-cba", "-P 2c 2c"      , 3 }, // 241
  { 51,    0, "P m c m"   ,   0,  "bca", "-P 2c 2"       , 2 }, // 242
  { 51,    0, "P m a m"   ,   0, "a-cb", "-P 2 2a"       , 5 }, // 243
  { 52,   52, "P n n a"   ,   0,     "", "-P 2a 2bc"     , 0 }, // 244
  { 52,    0, "P n n b"   ,   0, "ba-c", "-P 2b 2n"      , 7 }, // 245
  { 52,    0, "P b n n"   ,   0,  "cab", "-P 2n 2b"      , 1 }, // 246
  { 52,    0, "P c n n"   ,   0, "-cba", "-P 2ab 2c"     , 3 }, // 247
  { 52,    0, "P n c n"   ,   0,  "bca", "-P 2ab 2n"     , 2 }, // 248
  { 52,    0, "P n a n"   ,   0, "a-cb", "-P 2n 2bc"     , 5 }, // 249
  { 53,   53, "P m n a"   ,   0,     "", "-P 2ac 2"      , 0 }, // 250
  { 53,    0, "P n m b"   ,   0, "ba-c", "-P 2bc 2bc"    , 7 }, // 251
  { 53,    0, "P b m n"   ,   0,  "cab", "-P 2ab 2ab"    , 1 }, // 252
  { 53,    0, "P c n m"   ,   0, "-cba", "-P 2 2ac"      , 3 }, // 253
  { 53,    0, "P n c m"   ,   0,  "bca", "-P 2 2bc"      , 2 }, // 254
  { 53,    0, "P m a n"   ,   0, "a-cb", "-P 2ab 2"      , 5 }, // 255
  { 54,   54, "P c c a"   ,   0,     "", "-P 2a 2ac"     , 0 }, // 256
  { 54,    0, "P c c b"   ,   0, "ba-c", "-P 2b 2c"      , 7 }, // 257
  { 54,    0, "P b a a"   ,   0,  "cab", "-P 2a 2b"      , 1 }, // 258
  { 54,    0, "P c a a"   ,   0, "-cba", "-P 2ac 2c"     , 3 }, // 259
  { 54,    0, "P b c b"   ,   0,  "bca", "-P 2bc 2b"     , 2 }, // 260
  { 54,    0, "P b a b"   ,   0, "a-cb", "-P 2b 2ab"     , 5 }, // 261
  { 55,   55, "P b a m"   ,   0,     "", "-P 2 2ab"      , 0 }, // 262
  { 55,    0, "P m c b"   ,   0,  "cab", "-P 2bc 2"      , 1 }, // 263
  { 55,    0, "P c m a"   ,   0,  "bca", "-P 2ac 2ac"    , 2 }, // 264
  { 56,   56, "P c c n"   ,   0,     "", "-P 2ab 2ac"    , 0 }, // 265
  { 56,    0, "P n a a"   ,   0,  "cab", "-P 2ac 2bc"    , 1 }, // 266
  { 56,    0, "P b n b"   ,   0,  "bca", "-P 2bc 2ab"    , 2 }, // 267
  { 57,   57, "P b c m"   ,   0,     "", "-P 2c 2b"      , 0 }, // 268
  { 57,    0, "P c a m"   ,   0, "ba-c", "-P 2c 2ac"     , 7 }, // 269
  { 57,    0, "P m c a"   ,   0,  "cab", "-P 2ac 2a"     , 1 }, // 270
  { 57,    0, "P m a b"   ,   0, "-cba", "-P 2b 2a"      , 3 }, // 271
  { 57,    0, "P b m a"   ,   0,  "bca", "-P 2a 2ab"     , 2 }, // 272
  { 57,    0, "P c m b"   ,   0, "a-cb", "-P 2bc 2c"     , 5 }, // 273
  { 58,   58, "P n n m"   ,   0,     "", "-P 2 2n"       , 0 }, // 274
  { 58,    0, "P m n n"   ,   0,  "cab", "-P 2n 2"       , 1 }, // 275
  { 58,    0, "P n m n"   ,   0,  "bca", "-P 2n 2n"      , 2 }, // 276
  { 59,   59, "P m m n"   , '1',     "", "P 2 2ab -1ab"  , 21}, // 277
  { 59, 1059, "P m m n"   , '2',     "", "-P 2ab 2a"     , 0 }, // 278
  { 59,    0, "P n m m"   , '1',  "cab", "P 2bc 2 -1bc"  , 22}, // 279
  { 59,    0, "P n m m"   , '2',  "cab", "-P 2c 2bc"     , 1 }, // 280
  { 59,    0, "P m n m"   , '1',  "bca", "P 2ac 2ac -1ac", 23}, // 281
  { 59,    0, "P m n m"   , '2',  "bca", "-P 2c 2a"      , 2 }, // 282
  { 60,   60, "P b c n"   ,   0,     "", "-P 2n 2ab"     , 0 }, // 283
  { 60,    0, "P c a n"   ,   0, "ba-c", "-P 2n 2c"      , 7 }, // 284
  { 60,    0, "P n c a"   ,   0,  "cab", "-P 2a 2n"      , 1 }, // 285
  { 60,    0, "P n a b"   ,   0, "-cba", "-P 2bc 2n"     , 3 }, // 286
  { 60,    0, "P b n a"   ,   0,  "bca", "-P 2ac 2b"     , 2 }, // 287
  { 60,    0, "P c n b"   ,   0, "a-cb", "-P 2b 2ac"     , 5 }, // 288
  { 61,   61, "P b c a"   ,   0,     "", "-P 2ac 2ab"    , 0 }, // 289
  { 61,    0, "P c a b"   ,   0, "ba-c", "-P 2bc 2ac"    , 3 }, // 290
  { 62,   62, "P n m a"   ,   0,     "", "-P 2ac 2n"     , 0 }, // 291
  { 62,    0, "P m n b"   ,   0, "ba-c", "-P 2bc 2a"     , 7 }, // 292
  { 62,    0, "P b n m"   ,   0,  "cab", "-P 2c 2ab"     , 1 }, // 293
  { 62,    0, "P c m n"   ,   0, "-cba", "-P 2n 2ac"     , 3 }, // 294
  { 62,    0, "P m c n"   ,   0,  "bca", "-P 2n 2a"      , 2 }, // 295
  { 62,    0, "P n a m"   ,   0, "a-cb", "-P 2c 2n"      , 5 }, // 296
  { 63,   63, "C m c m"   ,   0,     "", "-C 2c 2"       , 0 }, // 297
  { 63,    0, "C c m m"   ,   0, "ba-c", "-C 2c 2c"      , 7 }, // 298
  { 63,    0, "A m m a"   ,   0,  "cab", "-A 2a 2a"      , 1 }, // 299
  { 63,    0, "A m a m"   ,   0, "-cba", "-A 2 2a"       , 3 }, // 300
  { 63,    0, "B b m m"   ,   0,  "bca", "-B 2 2b"       , 2 }, // 301
  { 63,    0, "B m m b"   ,   0, "a-cb", "-B 2b 2"       , 5 }, // 302
  { 64,   64, "C m c a"   ,   0,     "", "-C 2ac 2"      , 0 }, // 303
  { 64,    0, "C c m b"   ,   0, "ba-c", "-C 2ac 2ac"    , 7 }, // 304
  { 64,    0, "A b m a"   ,   0,  "cab", "-A 2ab 2ab"    , 1 }, // 305
  { 64,    0, "A c a m"   ,   0, "-cba", "-A 2 2ab"      , 3 }, // 306
  { 64,    0, "B b c m"   ,   0,  "bca", "-B 2 2ab"      , 2 }, // 307
  { 64,    0, "B m a b"   ,   0, "a-cb", "-B 2ab 2"      , 5 }, // 308
  { 65,   65, "C m m m"   ,   0,     "", "-C 2 2"        , 0 }, // 309
  { 65,    0, "A m m m"   ,   0,  "cab", "-A 2 2"        , 1 }, // 310
  { 65,    0, "B m m m"   ,   0,  "bca", "-B 2 2"        , 2 }, // 311
  { 66,   66, "C c c m"   ,   0,     "", "-C 2 2c"       , 0 }, // 312
  { 66,    0, "A m a a"   ,   0,  "cab", "-A 2a 2"       , 1 }, // 313
  { 66,    0, "B b m b"   ,   0,  "bca", "-B 2b 2b"      , 2 }, // 314
  { 67,   67, "C m m a"   ,   0,     "", "-C 2a 2"       , 0 }, // 315
  { 67,    0, "C m m b"   ,   0, "ba-c", "-C 2a 2a"      , 14}, // 316
  { 67,    0, "A b m m"   ,   0,  "cab", "-A 2b 2b"      , 1 }, // 317
  { 67,    0, "A c m m"   ,   0, "-cba", "-A 2 2b"       , 3 }, // 318
  { 67,    0, "B m c m"   ,   0,  "bca", "-B 2 2a"       , 2 }, // 319
  { 67,    0, "B m a m"   ,   0, "a-cb", "-B 2a 2"       , 5 }, // 320
  { 68,   68, "C c c a"   , '1',     "", "C 2 2 -1ac"    , 24}, // 321
  { 68,    0, "C c c a"   , '2',     "", "-C 2a 2ac"     , 0 }, // 322
  { 68,    0, "C c c b"   , '1', "ba-c", "C 2 2 -1ac"    , 24}, // 323 (==321)
  { 68,    0, "C c c b"   , '2', "ba-c", "-C 2a 2c"      , 21}, // 324
  { 68,    0, "A b a a"   , '1',  "cab", "A 2 2 -1ab"    , 25}, // 325
  { 68,    0, "A b a a"   , '2',  "cab", "-A 2a 2b"      , 1 }, // 326
  { 68,    0, "A c a a"   , '1', "-cba", "A 2 2 -1ab"    , 25}, // 327 (==325)
  { 68,    0, "A c a a"   , '2', "-cba", "-A 2ab 2b"     , 3 }, // 328
  { 68,    0, "B b c b"   , '1',  "bca", "B 2 2 -1ab"    , 26}, // 329
  { 68,    0, "B b c b"   , '2',  "bca", "-B 2ab 2b"     , 2 }, // 330
  { 68,    0, "B b a b"   , '1', "a-cb", "B 2 2 -1ab"    , 26}, // 331 (==329)
  { 68,    0, "B b a b"   , '2', "a-cb", "-B 2b 2ab"     , 5 }, // 332
  { 69,   69, "F m m m"   ,   0,     "", "-F 2 2"        , 0 }, // 333
  { 70,   70, "F d d d"   , '1',     "", "F 2 2 -1d"     , 27}, // 334
  { 70,    0, "F d d d"   , '2',     "", "-F 2uv 2vw"    , 0 }, // 335
  { 71,   71, "I m m m"   ,   0,     "", "-I 2 2"        , 0 }, // 336
  { 72,   72, "I b a m"   ,   0,     "", "-I 2 2c"       , 0 }, // 337
  { 72,    0, "I m c b"   ,   0,  "cab", "-I 2a 2"       , 1 }, // 338
  { 72,    0, "I c m a"   ,   0,  "bca", "-I 2b 2b"      , 2 }, // 339
  { 73,   73, "I b c a"   ,   0,     "", "-I 2b 2c"      , 0 }, // 340
  { 73,    0, "I c a b"   ,   0, "ba-c", "-I 2a 2b"      , 28}, // 341
  { 74,   74, "I m m a"   ,   0,     "", "-I 2b 2"       , 0 }, // 342
  { 74,    0, "I m m b"   ,   0, "ba-c", "-I 2a 2a"      , 28}, // 343
  { 74,    0, "I b m m"   ,   0,  "cab", "-I 2c 2c"      , 1 }, // 344
  { 74,    0, "I c m m"   ,   0, "-cba", "-I 2 2b"       , 3 }, // 345
  { 74,    0, "I m c m"   ,   0,  "bca", "-I 2 2a"       , 2 }, // 346
  { 74,    0, "I m a m"   ,   0, "a-cb", "-I 2c 2"       , 5 }, // 347
  { 75,   75, "P 4"       ,   0,     "", "P 4"           , 0 }, // 348
  { 76,   76, "P 41"      ,   0,     "", "P 4w"          , 0 }, // 349
  { 77,   77, "P 42"      ,   0,     "", "P 4c"          , 0 }, // 350
  { 78,   78, "P 43"      ,   0,     "", "P 4cw"         , 0 }, // 351
  { 79,   79, "I 4"       ,   0,     "", "I 4"           , 0 }, // 352
  { 80,   80, "I 41"      ,   0,     "", "I 4bw"         , 0 }, // 353
  { 81,   81, "P -4"      ,   0,     "", "P -4"          , 0 }, // 354
  { 82,   82, "I -4"      ,   0,     "", "I -4"          , 0 }, // 355
  { 83,   83, "P 4/m"     ,   0,     "", "-P 4"          , 0 }, // 356
  { 84,   84, "P 42/m"    ,   0,     "", "-P 4c"         , 0 }, // 357
  { 85,   85, "P 4/n"     , '1',     "", "P 4ab -1ab"    , 29}, // 358
  { 85,    0, "P 4/n"     , '2',     "", "-P 4a"         , 0 }, // 359
  { 86,   86, "P 42/n"    , '1',     "", "P 4n -1n"      , 30}, // 360
  { 86,    0, "P 42/n"    , '2',     "", "-P 4bc"        , 0 }, // 361
  { 87,   87, "I 4/m"     ,   0,     "", "-I 4"          , 0 }, // 362
  { 88,   88, "I 41/a"    , '1',     "", "I 4bw -1bw"    , 31}, // 363
  { 88,    0, "I 41/a"    , '2',     "", "-I 4ad"        , 0 }, // 364
  { 89,   89, "P 4 2 2"   ,   0,     "", "P 4 2"         , 0 }, // 365
  { 90,   90, "P 4 21 2"  ,   0,     "", "P 4ab 2ab"     , 0 }, // 366
  { 91,   91, "P 41 2 2"  ,   0,     "", "P 4w 2c"       , 0 }, // 367
  { 92,   92, "P 41 21 2" ,   0,     "", "P 4abw 2nw"    , 0 }, // 368
  { 93,   93, "P 42 2 2"  ,   0,     "", "P 4c 2"        , 0 }, // 369
  { 94,   94, "P 42 21 2" ,   0,     "", "P 4n 2n"       , 0 }, // 370
  { 95,   95, "P 43 2 2"  ,   0,     "", "P 4cw 2c"      , 0 }, // 371
  { 96,   96, "P 43 21 2" ,   0,     "", "P 4nw 2abw"    , 0 }, // 372
  { 97,   97, "I 4 2 2"   ,   0,     "", "I 4 2"         , 0 }, // 373
  { 98,   98, "I 41 2 2"  ,   0,     "", "I 4bw 2bw"     , 0 }, // 374
  { 99,   99, "P 4 m m"   ,   0,     "", "P 4 -2"        , 0 }, // 375
  {100,  100, "P 4 b m"   ,   0,     "", "P 4 -2ab"      , 0 }, // 376
  {101,  101, "P 42 c m"  ,   0,     "", "P 4c -2c"      , 0 }, // 377
  {102,  102, "P 42 n m"  ,   0,     "", "P 4n -2n"      , 0 }, // 378
  {103,  103, "P 4 c c"   ,   0,     "", "P 4 -2c"       , 0 }, // 379
  {104,  104, "P 4 n c"   ,   0,     "", "P 4 -2n"       , 0 }, // 380
  {105,  105, "P 42 m c"  ,   0,     "", "P 4c -2"       , 0 }, // 381
  {106,  106, "P 42 b c"  ,   0,     "", "P 4c -2ab"     , 0 }, // 382
  {107,  107, "I 4 m m"   ,   0,     "", "I 4 -2"        , 0 }, // 383
  {108,  108, "I 4 c m"   ,   0,     "", "I 4 -2c"       , 0 }, // 384
  {109,  109, "I 41 m d"  ,   0,     "", "I 4bw -2"      , 0 }, // 385
  {110,  110, "I 41 c d"  ,   0,     "", "I 4bw -2c"     , 0 }, // 386
  {111,  111, "P -4 2 m"  ,   0,     "", "P -4 2"        , 0 }, // 387
  {112,  112, "P -4 2 c"  ,   0,     "", "P -4 2c"       , 0 }, // 388
  {113,  113, "P -4 21 m" ,   0,     "", "P -4 2ab"      , 0 }, // 389
  {114,  114, "P -4 21 c" ,   0,     "", "P -4 2n"       , 0 }, // 390
  {115,  115, "P -4 m 2"  ,   0,     "", "P -4 -2"       , 0 }, // 391
  {116,  116, "P -4 c 2"  ,   0,     "", "P -4 -2c"      , 0 }, // 392
  {117,  117, "P -4 b 2"  ,   0,     "", "P -4 -2ab"     , 0 }, // 393
  {118,  118, "P -4 n 2"  ,   0,     "", "P -4 -2n"      , 0 }, // 394
  {119,  119, "I -4 m 2"  ,   0,     "", "I -4 -2"       , 0 }, // 395
  {120,  120, "I -4 c 2"  ,   0,     "", "I -4 -2c"      , 0 }, // 396
  {121,  121, "I -4 2 m"  ,   0,     "", "I -4 2"        , 0 }, // 397
  {122,  122, "I -4 2 d"  ,   0,     "", "I -4 2bw"      , 0 }, // 398
  {123,  123, "P 4/m m m" ,   0,     "", "-P 4 2"        , 0 }, // 399
  {124,  124, "P 4/m c c" ,   0,     "", "-P 4 2c"       , 0 }, // 400
  {125,  125, "P 4/n b m" , '1',     "", "P 4 2 -1ab"    , 21}, // 401
  {125,    0, "P 4/n b m" , '2',     "", "-P 4a 2b"      , 0 }, // 402
  {126,  126, "P 4/n n c" , '1',     "", "P 4 2 -1n"     , 20}, // 403
  {126,    0, "P 4/n n c" , '2',     "", "-P 4a 2bc"     , 0 }, // 404
  {127,  127, "P 4/m b m" ,   0,     "", "-P 4 2ab"      , 0 }, // 405
  {128,  128, "P 4/m n c" ,   0,     "", "-P 4 2n"       , 0 }, // 406
  {129,  129, "P 4/n m m" , '1',     "", "P 4ab 2ab -1ab", 29}, // 407
  {129,    0, "P 4/n m m" , '2',     "", "-P 4a 2a"      , 0 }, // 408
  {130,  130, "P 4/n c c" , '1',     "", "P 4ab 2n -1ab" , 29}, // 409
  {130,    0, "P 4/n c c" , '2',     "", "-P 4a 2ac"     , 0 }, // 410
  {131,  131, "P 42/m m c",   0,     "", "-P 4c 2"       , 0 }, // 411
  {132,  132, "P 42/m c m",   0,     "", "-P 4c 2c"      , 0 }, // 412
  {133,  133, "P 42/n b c", '1',     "", "P 4n 2c -1n"   , 32}, // 413
  {133,    0, "P 42/n b c", '2',     "", "-P 4ac 2b"     , 0 }, // 414
  {134,  134, "P 42/n n m", '1',     "", "P 4n 2 -1n"    , 33}, // 415
  {134,    0, "P 42/n n m", '2',     "", "-P 4ac 2bc"    , 0 }, // 416
  {135,  135, "P 42/m b c",   0,     "", "-P 4c 2ab"     , 0 }, // 417
  {136,  136, "P 42/m n m",   0,     "", "-P 4n 2n"      , 0 }, // 418
  {137,  137, "P 42/n m c", '1',     "", "P 4n 2n -1n"   , 32}, // 419
  {137,    0, "P 42/n m c", '2',     "", "-P 4ac 2a"     , 0 }, // 420
  {138,  138, "P 42/n c m", '1',     "", "P 4n 2ab -1n"  , 33}, // 421
  {138,    0, "P 42/n c m", '2',     "", "-P 4ac 2ac"    , 0 }, // 422
  {139,  139, "I 4/m m m" ,   0,     "", "-I 4 2"        , 0 }, // 423
  {140,  140, "I 4/m c m" ,   0,     "", "-I 4 2c"       , 0 }, // 424
  {141,  141, "I 41/a m d", '1',     "", "I 4bw 2bw -1bw", 34}, // 425
  {141,    0, "I 41/a m d", '2',     "", "-I 4bd 2"      , 0 }, // 426
  {142,  142, "I 41/a c d", '1',     "", "I 4bw 2aw -1bw", 35}, // 427
  {142,    0, "I 41/a c d", '2',     "", "-I 4bd 2c"     , 0 }, // 428
  {143,  143, "P 3"       ,   0,     "", "P 3"           , 0 }, // 429
  {144,  144, "P 31"      ,   0,     "", "P 31"          , 0 }, // 430
  {145,  145, "P 32"      ,   0,     "", "P 32"          , 0 }, // 431
  {146,  146, "R 3"       , 'H',     "", "R 3"           , 0 }, // 432
  {146, 1146, "R 3"       , 'R',     "", "P 3*"          , 36}, // 433
  {147,  147, "P -3"      ,   0,     "", "-P 3"          , 0 }, // 434
  {148,  148, "R -3"      , 'H',     "", "-R 3"          , 0 }, // 435
  {148, 1148, "R -3"      , 'R',     "", "-P 3*"         , 36}, // 436
  {149,  149, "P 3 1 2"   ,   0,     "", "P 3 2"         , 0 }, // 437
  {150,  150, "P 3 2 1"   ,   0,     "", "P 3 2\""       , 0 }, // 438
  {151,  151, "P 31 1 2"  ,   0,     "", "P 31 2 (0 0 4)", 0 }, // 439
  {152,  152, "P 31 2 1"  ,   0,     "", "P 31 2\""      , 0 }, // 440
  {153,  153, "P 32 1 2"  ,   0,     "", "P 32 2 (0 0 2)", 0 }, // 441
  {154,  154, "P 32 2 1"  ,   0,     "", "P 32 2\""      , 0 }, // 442
  {155,  155, "R 3 2"     , 'H',     "", "R 3 2\""       , 0 }, // 443
  {155, 1155, "R 3 2"     , 'R',     "", "P 3* 2"        , 36}, // 444
  {156,  156, "P 3 m 1"   ,   0,     "", "P 3 -2\""      , 0 }, // 445
  {157,  157, "P 3 1 m"   ,   0,     "", "P 3 -2"        , 0 }, // 446
  {158,  158, "P 3 c 1"   ,   0,     "", "P 3 -2\"c"     , 0 }, // 447
  {159,  159, "P 3 1 c"   ,   0,     "", "P 3 -2c"       , 0 }, // 448
  {160,  160, "R 3 m"     , 'H',     "", "R 3 -2\""      , 0 }, // 449
  {160, 1160, "R 3 m"     , 'R',     "", "P 3* -2"       , 36}, // 450
  {161,  161, "R 3 c"     , 'H',     "", "R 3 -2\"c"     , 0 }, // 451
  {161, 1161, "R 3 c"     , 'R',     "", "P 3* -2n"      , 36}, // 452
  {162,  162, "P -3 1 m"  ,   0,     "", "-P 3 2"        , 0 }, // 453
  {163,  163, "P -3 1 c"  ,   0,     "", "-P 3 2c"       , 0 }, // 454
  {164,  164, "P -3 m 1"  ,   0,     "", "-P 3 2\""      , 0 }, // 455
  {165,  165, "P -3 c 1"  ,   0,     "", "-P 3 2\"c"     , 0 }, // 456
  {166,  166, "R -3 m"    , 'H',     "", "-R 3 2\""      , 0 }, // 457
  {166, 1166, "R -3 m"    , 'R',     "", "-P 3* 2"       , 36}, // 458
  {167,  167, "R -3 c"    , 'H',     "", "-R 3 2\"c"     , 0 }, // 459
  {167, 1167, "R -3 c"    , 'R',     "", "-P 3* 2n"      , 36}, // 460
  {168,  168, "P 6"       ,   0,     "", "P 6"           , 0 }, // 461
  {169,  169, "P 61"      ,   0,     "", "P 61"          , 0 }, // 462
  {170,  170, "P 65"      ,   0,     "", "P 65"          , 0 }, // 463
  {171,  171, "P 62"      ,   0,     "", "P 62"          , 0 }, // 464
  {172,  172, "P 64"      ,   0,     "", "P 64"          , 0 }, // 465
  {173,  173, "P 63"      ,   0,     "", "P 6c"          , 0 }, // 466
  {174,  174, "P -6"      ,   0,     "", "P -6"          , 0 }, // 467
  {175,  175, "P 6/m"     ,   0,     "", "-P 6"          , 0 }, // 468
  {176,  176, "P 63/m"    ,   0,     "", "-P 6c"         , 0 }, // 469
  {177,  177, "P 6 2 2"   ,   0,     "", "P 6 2"         , 0 }, // 470
  {178,  178, "P 61 2 2"  ,   0,     "", "P 61 2 (0 0 5)", 0 }, // 471
  {179,  179, "P 65 2 2"  ,   0,     "", "P 65 2 (0 0 1)", 0 }, // 472
  {180,  180, "P 62 2 2"  ,   0,     "", "P 62 2 (0 0 4)", 0 }, // 473
  {181,  181, "P 64 2 2"  ,   0,     "", "P 64 2 (0 0 2)", 0 }, // 474
  {182,  182, "P 63 2 2"  ,   0,     "", "P 6c 2c"       , 0 }, // 475
  {183,  183, "P 6 m m"   ,   0,     "", "P 6 -2"        , 0 }, // 476
  {184,  184, "P 6 c c"   ,   0,     "", "P 6 -2c"       , 0 }, // 477
  {185,  185, "P 63 c m"  ,   0,     "", "P 6c -2"       , 0 }, // 478
  {186,  186, "P 63 m c"  ,   0,     "", "P 6c -2c"      , 0 }, // 479
  {187,  187, "P -6 m 2"  ,   0,     "", "P -6 2"        , 0 }, // 480
  {188,  188, "P -6 c 2"  ,   0,     "", "P -6c 2"       , 0 }, // 481
  {189,  189, "P -6 2 m"  ,   0,     "", "P -6 -2"       , 0 }, // 482
  {190,  190, "P -6 2 c"  ,   0,     "", "P -6c -2c"     , 0 }, // 483
  {191,  191, "P 6/m m m" ,   0,     "", "-P 6 2"        , 0 }, // 484
  {192,  192, "P 6/m c c" ,   0,     "", "-P 6 2c"       , 0 }, // 485
  {193,  193, "P 63/m c m",   0,     "", "-P 6c 2"       , 0 }, // 486
  {194,  194, "P 63/m m c",   0,     "", "-P 6c 2c"      , 0 }, // 487
  {195,  195, "P 2 3"     ,   0,     "", "P 2 2 3"       , 0 }, // 488
  {196,  196, "F 2 3"     ,   0,     "", "F 2 2 3"       , 0 }, // 489
  {197,  197, "I 2 3"     ,   0,     "", "I 2 2 3"       , 0 }, // 490
  {198,  198, "P 21 3"    ,   0,     "", "P 2ac 2ab 3"   , 0 }, // 491
  {199,  199, "I 21 3"    ,   0,     "", "I 2b 2c 3"     , 0 }, // 492
  {200,  200, "P m -3"    ,   0,     "", "-P 2 2 3"      , 0 }, // 493
  {201,  201, "P n -3"    , '1',     "", "P 2 2 3 -1n"   , 20}, // 494
  {201,    0, "P n -3"    , '2',     "", "-P 2ab 2bc 3"  , 0 }, // 495
  {202,  202, "F m -3"    ,   0,     "", "-F 2 2 3"      , 0 }, // 496
  {203,  203, "F d -3"    , '1',     "", "F 2 2 3 -1d"   , 27}, // 497
  {203,    0, "F d -3"    , '2',     "", "-F 2uv 2vw 3"  , 0 }, // 498
  {204,  204, "I m -3"    ,   0,     "", "-I 2 2 3"      , 0 }, // 499
  {205,  205, "P a -3"    ,   0,     "", "-P 2ac 2ab 3"  , 0 }, // 500
  {206,  206, "I a -3"    ,   0,     "", "-I 2b 2c 3"    , 0 }, // 501
  {207,  207, "P 4 3 2"   ,   0,     "", "P 4 2 3"       , 0 }, // 502
  {208,  208, "P 42 3 2"  ,   0,     "", "P 4n 2 3"      , 0 }, // 503
  {209,  209, "F 4 3 2"   ,   0,     "", "F 4 2 3"       , 0 }, // 504
  {210,  210, "F 41 3 2"  ,   0,     "", "F 4d 2 3"      , 0 }, // 505
  {211,  211, "I 4 3 2"   ,   0,     "", "I 4 2 3"       , 0 }, // 506
  {212,  212, "P 43 3 2"  ,   0,     "", "P 4acd 2ab 3"  , 0 }, // 507
  {213,  213, "P 41 3 2"  ,   0,     "", "P 4bd 2ab 3"   , 0 }, // 508
  {214,  214, "I 41 3 2"  ,   0,     "", "I 4bd 2c 3"    , 0 }, // 509
  {215,  215, "P -4 3 m"  ,   0,     "", "P -4 2 3"      , 0 }, // 510
  {216,  216, "F -4 3 m"  ,   0,     "", "F -4 2 3"      , 0 }, // 511
  {217,  217, "I -4 3 m"  ,   0,     "", "I -4 2 3"      , 0 }, // 512
  {218,  218, "P -4 3 n"  ,   0,     "", "P -4n 2 3"     , 0 }, // 513
  {219,  219, "F -4 3 c"  ,   0,     "", "F -4a 2 3"     , 0 }, // 514
  {220,  220, "I -4 3 d"  ,   0,     "", "I -4bd 2c 3"   , 0 }, // 515
  {221,  221, "P m -3 m"  ,   0,     "", "-P 4 2 3"      , 0 }, // 516
  {222,  222, "P n -3 n"  , '1',     "", "P 4 2 3 -1n"   , 20}, // 517
  {222,    0, "P n -3 n"  , '2',     "", "-P 4a 2bc 3"   , 0 }, // 518
  {223,  223, "P m -3 n"  ,   0,     "", "-P 4n 2 3"     , 0 }, // 519
  {224,  224, "P n -3 m"  , '1',     "", "P 4n 2 3 -1n"  , 30}, // 520
  {224,    0, "P n -3 m"  , '2',     "", "-P 4bc 2bc 3"  , 0 }, // 521
  {225,  225, "F m -3 m"  ,   0,     "", "-F 4 2 3"      , 0 }, // 522
  {226,  226, "F m -3 c"  ,   0,     "", "-F 4a 2 3"     , 0 }, // 523
  {227,  227, "F d -3 m"  , '1',     "", "F 4d 2 3 -1d"  , 27}, // 524
  {227,    0, "F d -3 m"  , '2',     "", "-F 4vw 2vw 3"  , 0 }, // 525
  {228,  228, "F d -3 c"  , '1',     "", "F 4d 2 3 -1ad" , 37}, // 526
  {228,    0, "F d -3 c"  , '2',     "", "-F 4ud 2vw 3"  , 0 }, // 527
  {229,  229, "I m -3 m"  ,   0,     "", "-I 4 2 3"      , 0 }, // 528
  {230,  230, "I a -3 d"  ,   0,     "", "-I 4bd 2c 3"   , 0 }, // 529
  // And extra entries from syminfo.lib
  {  5, 5005, "I 1 21 1"  ,   0,   "b4", "I 2yb"         , 38}, // 530
  {  5, 3005, "C 1 21 1"  ,   0,   "b5", "C 2yb"         , 14}, // 531
  { 18, 1018, "P 21212(a)",   0,     "", "P 2ab 2a"      , 14}, // 532
  { 20, 1020, "C 2 2 21a)",   0,     "", "C 2ac 2"       , 39}, // 533
  { 21, 1021, "C 2 2 2a"  ,   0,     "", "C 2ab 2b"      , 14}, // 534
  { 22, 1022, "F 2 2 2a"  ,   0,     "", "F 2 2c"        , 40}, // 535
  { 23, 1023, "I 2 2 2a"  ,   0,     "", "I 2ab 2bc"     , 33}, // 536
  { 94, 1094, "P 42 21 2a",   0,     "", "P 4bc 2a"      , 20}, // 537
  {197, 1197, "I 2 3a"    ,   0,     "", "I 2ab 2bc 3"   , 30}, // 538
  // And extra entries from Crystallographic Space Group Diagrams and Tables
  // http://img.chem.ucl.ac.uk/sgp/
  // We want to have all entries from Open Babel and PDB.
  // If available, Hall symbols are taken from
  // https://cci.lbl.gov/cctbx/multiple_cell.html
  // triclinic - enlarged unit cells
  {  1,    0, "A 1"       ,   0,     "", "A 1"           , 41}, // 539
  {  1,    0, "B 1"       ,   0,     "", "B 1"           , 42}, // 540
  {  1,    0, "C 1"       ,   0,     "", "C 1"           , 43}, // 541
  {  1,    0, "F 1"       ,   0,     "", "F 1"           , 44}, // 542
  {  1,    0, "I 1"       ,   0,     "", "I 1"           , 45}, // 543
  {  2,    0, "A -1"      ,   0,     "", "-A 1"          , 41}, // 544
  {  2,    0, "B -1"      ,   0,     "", "-B 1"          , 42}, // 545
  {  2,    0, "C -1"      ,   0,     "", "-C 1"          , 43}, // 546
  {  2,    0, "F -1"      ,   0,     "", "-F 1"          , 44}, // 547
  {  2,    0, "I -1"      ,   0,     "", "-I 1"          , 45}, // 548
  // monoclinic (qualifiers such as "b1" are assigned arbitrary unique numbers)
  {  3,    0, "B 1 2 1"  ,    0,   "b1", "B 2y"          , 46}, // 549
  {  3,    0, "C 1 1 2"  ,    0,   "c1", "C 2"           , 47}, // 550
  {  4,    0, "B 1 21 1"  ,   0,   "b1", "B 2yb"         , 46}, // 551
  {  4,    0, "C 1 1 21"  ,   0,   "c2", "C 2c"          , 47}, // 552
  {  5,    0, "F 1 2 1"   ,   0,   "b6", "F 2y"          , 48}, // 553
  {  8,    0, "F 1 m 1"   ,   0,   "b4", "F -2y"         , 48}, // 554
  {  9,    0, "F 1 d 1"   ,   0,   "b4", "F -2yuw"       , 49}, // 555
  { 12,    0, "F 1 2/m 1" ,   0,   "b4", "-F 2y"         , 48}, // 556
  // orthorhombic
  { 64,    0, "A b a m"   ,   0,     "", "-A 2 2ab"      , 3 }, // 557 (==306)
  // tetragonal - enlarged C- and F-centred unit cells
  { 89,    0, "C 4 2 2" ,     0,     "", "C 4 2"         , 50}, // 558
  { 90,    0, "C 4 2 21" ,    0,     "", "C 4a 2"        , 50}, // 559
  { 97,    0, "F 4 2 2" ,     0,     "", "F 4 2"         , 50}, // 560
  {115,    0, "C -4 2 m"  ,   0,     "", "C -4 2"        , 50}, // 561
  {117,    0, "C -4 2 b"  ,   0,     "", "C -4 2ya"      , 50}, // 562
  {139,    0, "F 4/m m m" ,   0,     "", "-F 4 2"        , 50}, // 563
};

const SpaceGroupAltName spacegroup_tables::alt_names[28] = {
  // In 1990's ITfC vol.A changed some of the standard names, introducing
  // symbol 'e'. sgtbx interprets these new symbols with option ad_hoc_1992.
  // spglib uses only the new symbols.
  {"A e m 2",   0, 190}, // A b m 2
  {"B m e 2",   0, 191}, // B m a 2
  {"B 2 e m",   0, 192}, // B 2 c m
  {"C 2 m e",   0, 193}, // C 2 m b
  {"C m 2 e",   0, 194}, // C m 2 a
  {"A e 2 m",   0, 195}, // A c 2 m
  {"A e a 2",   0, 202}, // A b a 2
  {"B b e 2",   0, 203}, // B b a 2
  {"B 2 e b",   0, 204}, // B 2 c b
  {"C 2 c e",   0, 205}, // C 2 c b
  {"C c 2 e",   0, 206}, // C c 2 a
  {"A e 2 a",   0, 207}, // A c 2 a
  {"C m c e",   0, 303}, // C m c a
  {"C c m e",   0, 304}, // C c m b
  {"A e m a",   0, 305}, // A b m a
  {"A e a m",   0, 306}, // A c a m
  {"B b e m",   0, 307}, // B b c m
  {"B m e b",   0, 308}, // B m a b
  {"C m m e",   0, 315}, // C m m a
  {"A e m m",   0, 317}, // A b m m
  {"B m e m",   0, 319}, // B m c m
  {"C c c e", '1', 321}, // C c c a
  {"C c c e", '2', 322}, // C c c a
  {"A e a a", '1', 325}, // A b a a
  {"A e a a", '2', 326}, // A b a a
  {"B b e b", '1', 329}, // B b c b
  {"B b e b", '2', 330}, // B b c b
  // help with  parsing of unusual setting names that are present in the PDB
  {"P 21 21 2a", 0, 532}, // P 21212(a)
};

// This table was generated by tools/gen_reciprocal_asu.py.
const unsigned char spacegroup_tables::ccp4_hkl_asu[230] = {
  0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 6, 7, 6, 7, 6, 7, 7, 7,
  6, 7, 6, 7, 7, 6, 6, 7, 7, 7, 7, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9,
  9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9
};

// Generated by tools/gen_sg_table.py.
const char* get_basisop(int basisop_idx) {
  static const char* basisops[51] = {
    "x,y,z",  // 0
    "z,x,y",  // 1
    "y,z,x",  // 2
    "z,y,-x",  // 3
    "x,y,-x+z",  // 4
    "-x,z,y",  // 5
    "-x+z,x,y",  // 6
    "y,-x,z",  // 7
    "y,-x+z,x",  // 8
    "x-z,y,z",  // 9
    "z,x-z,y",  // 10
    "y,z,x-z",  // 11
    "z,y,-x+z",  // 12
    "x+z,y,-x",  // 13
    "x+1/4,y+1/4,z",  // 14
    "-x+z,z,y",  // 15
    "-x,x+z,y",  // 16
    "y,-x+z,z",  // 17
    "y,-x,x+z",  // 18
    "x+1/4,y-1/4,z",  // 19
    "x-1/4,y-1/4,z-1/4",  // 20
    "x-1/4,y-1/4,z",  // 21
    "z,x-1/4,y-1/4",  // 22
    "y-1/4,z,x-1/4",  // 23
    "x-1/2,y-1/4,z+1/4",  // 24
    "z+1/4,x-1/2,y-1/4",  // 25
    "y-1/4,z+1/4,x-1/2",  // 26
    "x+1/8,y+1/8,z+1/8",  // 27
    "x+1/4,y-1/4,z+1/4",  // 28
    "x-1/4,y+1/4,z",  // 29
    "x+1/4,y+1/4,z+1/4",  // 30
    "x,y+1/4,z+1/8",  // 31
    "x-1/4,y+1/4,z+1/4",  // 32
    "x-1/4,y+1/4,z-1/4",  // 33
    "x-1/2,y+1/4,z+1/8",  // 34
    "x-1/2,y+1/4,z-3/8",  // 35
    "-y+z,x+z,-x+y+z",  // 36
    "x-1/8,y-1/8,z-1/8",  // 37
    "x+1/4,y+1/4,-x+z-1/4",  // 38
    "x+1/4,y,z",  // 39
    "x,y,z+1/4",  // 40
    "-x,-y/2+z/2,y/2+z/2",  // 41
    "-x/2+z/2,-y,x/2+z/2",  // 42
    "x/2+y/2,x/2-y/2,-z",  // 43
    "y/2+z/2,x/2+z/2,x/2+y/2",  // 44
    "-x/2+y/2+z/2,x/2-y/2+z/2,x/2+y/2-z/2",  // 45
    "x/2,y,-x/2+z",  // 46
    "-x/2+z,x/2,y",  // 47
    "x-z/2,y,z/2",  // 48
    "x+z/2,y,z/2",  // 49
    "x/2+y/2,-x/2+y/2,z",  // 50
  };
  return basisops[basisop_idx];
}

const SpaceGroup* find_spacegroup_by_name(std::string name, double alpha, double gamma,
                                          const char* prefer) {
  bool prefer_2 = false;
  bool prefer_R = false;
  if (prefer)
    for (const char* p = prefer; *p != '\0'; ++p) {
      if (*p == '2')
        prefer_2 = true;
      else if (*p == 'R')
        prefer_R = true;
      else if (*p != '1' && *p != 'H')
        throw std::invalid_argument("find_spacegroup_by_name(): invalid arg 'prefer'");
    }
  const char* p = skip_space(name.c_str());
  if (*p >= '0' && *p <= '9') { // handle numbers
    char *endptr;
    long n = std::strtol(p, &endptr, 10);
    return *endptr == '\0' ? find_spacegroup_by_number(n) : nullptr;
  }
  char first = *p & ~0x20; // to uppercase
  if (first == '\0')
    return nullptr;
  if (first == 'H')
    first = 'R';
  p = skip_space(p+1);
  size_t start = p - name.c_str();
  // change letters to lower case, except the letter after :
  for (size_t i = start; i < name.size(); ++i) {
    if (name[i] >= 'A' && name[i] <= 'Z')
      name[i] |= 0x20;  // to lowercase
    else if (name[i] == ':')
      while (++i < name.size())
        if (name[i] >= 'a' && name[i] <= 'z')
          name[i] &= ~0x20;  // to uppercase
  }
  // allow names ending with R or H, such as R3R instead of R3:R
  if (name.back() == 'h' || name.back() == 'r') {
    name.back() &= ~0x20;  // to uppercase
    name.insert(name.end() - 1, ':');
  }
  // The string that const char* p points to was just modified.
  // This confuses some compilers (GCC 4.8), so let's re-assign p.
  p = name.c_str() + start;

  for (const SpaceGroup& sg : spacegroup_tables::main)
    if (sg.hm[0] == first) {
      if (sg.hm[2] == *p) {
        const char* a = skip_space(p + 1);
        const char* b = skip_space(sg.hm + 3);
        // In IT 1935 and 1952, symbols of centrosymmetric, cubic space groups
        // 200-206 and 221-230 had symbol 3 (not -3), e.g. Pm3 instead of Pm-3,
        // as listed in Table 3.3.3.1 in ITfC (2016) vol. A, p.788.
        while ((*a == *b && *b != '\0') ||
               (*a == '3' && *b == '-' && b == sg.hm + 4 && *++b == '3')) {
          a = skip_space(a+1);
          b = skip_space(b+1);
        }
        if (*b == '\0') {
          if (*a == '\0') {
            // Change hexagonal settings to rhombohedral if the unit cell
            // angles are more consistent with the latter.
            // We have possible ambiguity in the hexagonal crystal family.
            // For instance, "R 3" may mean "R 3:H" (hexagonal setting) or
            // "R 3:R" (rhombohedral setting). The :H symbols come first
            // in the table and are used by default. The ratio gamma:alpha
            // is 120:90 in the hexagonal system and 1:1 in rhombohedral.
            // We assume that the 'R' entry follows directly the 'H' entry.
            if (sg.ext == 'H' && (alpha == 0. ? prefer_R : gamma < 1.125 * alpha))
              return &sg + 1;
            // Similarly, the origin choice #2 follows directly #1.
            if (sg.ext == '1' && prefer_2)
              return &sg + 1;
            return &sg;
          }
          if (*a == ':' && *skip_space(a+1) == sg.ext)
            return &sg;
        }
      } else if (sg.hm[2] == '1' && sg.hm[3] == ' ') {
        // check monoclinic short names, matching P2 to "P 1 2 1";
        // as an exception "B 2" == "B 1 1 2" (like in the PDB)
        const char* b = sg.hm + 4;
        if (*b != '1' || (first == 'B' && *++b == ' ' && *++b != '1')) {
          char end = (b == sg.hm + 4 ? ' ' : '\0');
          const char* a = skip_space(p);
          while (*a == *b && *b != end) {
            ++a;
            ++b;
          }
          if (*skip_space(a) == '\0' && *b == end)
            return &sg;
        }
      }
    }
  for (const SpaceGroupAltName& sg : spacegroup_tables::alt_names)
    if (sg.hm[0] == first && sg.hm[2] == *p) {
      const char* a = skip_space(p + 1);
      const char* b = skip_space(sg.hm + 3);
      while (*a == *b && *b != '\0') {
        a = skip_space(a+1);
        b = skip_space(b+1);
      }
      if (*b == '\0' &&
          (*a == '\0' || (*a == ':' && *skip_space(a+1) == sg.ext)))
        return &spacegroup_tables::main[sg.pos];
    }
  return nullptr;
}

} // namespace gemmi

