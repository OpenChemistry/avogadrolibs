/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/utilities.h>

#include <clocale>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

using Avogadro::Core::caseInsensitiveEquals;
using Avogadro::Core::contains;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::parseDouble;
using Avogadro::Core::parseFloat;
using Avogadro::Core::split;
using Avogadro::Core::splitWhitespace;
using Avogadro::Core::startsWith;
using Avogadro::Core::toLower;
using Avogadro::Core::trimmed;
using std::string;

namespace {

// Switches the C locale to one with a comma as the decimal separator, and
// restores the previous locale on destruction. This is what Qt does at start
// up (setlocale(LC_ALL, "")) on a German system.
class CommaDecimalLocale
{
public:
  CommaDecimalLocale()
  {
    const char* current = std::setlocale(LC_ALL, nullptr);
    if (current != nullptr)
      m_previous = current;
    for (const char* name : { "de_DE.UTF-8", "de_DE.utf8", "de_DE" }) {
      if (std::setlocale(LC_ALL, name) != nullptr) {
        m_active = true;
        return;
      }
    }
  }

  ~CommaDecimalLocale() { std::setlocale(LC_ALL, m_previous.c_str()); }

  bool active() const { return m_active; }

private:
  string m_previous = "C";
  bool m_active = false;
};

// Parses all of @p text; nullopt if nothing was parsed or text was left over.
std::optional<double> parseAllDouble(const string& text)
{
  double value = 0.0;
  const char* first = text.data();
  const char* last = first + text.size();
  if (parseDouble(first, last, value) != last)
    return std::nullopt;
  return value;
}

} // namespace

TEST(UtilitiesTest, split)
{
  string test(" trim white space    ");
  EXPECT_EQ(split(test, ' ').size(), 3);
}

TEST(UtilitiesTest, splitEmpty)
{
  string test(" trim white space    ");
  EXPECT_EQ(split(test, ' ', false).size(), 7);
}

TEST(UtilitiesTest, splitWhitespace)
{
  using Tokens = std::vector<string>;

  EXPECT_EQ(splitWhitespace(""), Tokens());
  EXPECT_EQ(splitWhitespace(" \t\r\n  \n"), Tokens());

  EXPECT_EQ(splitWhitespace("token"), Tokens({ "token" }));
  EXPECT_EQ(splitWhitespace("  lead"), Tokens({ "lead" }));
  EXPECT_EQ(splitWhitespace("trail  "), Tokens({ "trail" }));
  EXPECT_EQ(splitWhitespace("  a   b  c  "), Tokens({ "a", "b", "c" }));

  EXPECT_EQ(splitWhitespace("a\tb"), Tokens({ "a", "b" }));
  EXPECT_EQ(splitWhitespace("a\r\nb\n"), Tokens({ "a", "b" }));
  EXPECT_EQ(splitWhitespace("\t a \t\r\n b \n\n"), Tokens({ "a", "b" }));

  // A Hall symbol as it might come from a file.
  EXPECT_EQ(splitWhitespace("  -P   2yn \n"), Tokens({ "-P", "2yn" }));

  // split() takes a single delimiter, so tabs stay inside the tokens.
  EXPECT_EQ(split("a\tb c", ' '), Tokens({ "a\tb", "c" }));
  EXPECT_EQ(splitWhitespace("a\tb c"), Tokens({ "a", "b", "c" }));
}

TEST(UtilitiesTest, trimmed)
{
  string test(" trim white space \n\t\r");
  EXPECT_EQ(trimmed(test), "trim white space");
  EXPECT_EQ(trimmed("test"), "test");
  EXPECT_EQ(trimmed("H"), "H");
  EXPECT_EQ(trimmed("  H"), "H");
  EXPECT_EQ(trimmed("H  "), "H");
  EXPECT_EQ(trimmed(" H  "), "H");
}

TEST(UtilitiesTest, lexicalCast)
{
  EXPECT_EQ(lexicalCast<int>("5"), 5);
  EXPECT_EQ(lexicalCast<double>("5.3"), 5.3);
  EXPECT_EQ(lexicalCast<double>("5.3E-10"), 5.3e-10);
}

TEST(UtilitiesTest, lexicalCastOutOfRange)
{
  // Some programs write exponents a double cannot represent. These are
  // effectively zero and should not abort reading the rest of a file.
  EXPECT_EQ(lexicalCast<double>("2.61793E-500"), 0.0);
  EXPECT_EQ(lexicalCast<double>("-7.5467E-6000"), 0.0);

  // Overflow is clamped rather than becoming an infinity.
  EXPECT_EQ(lexicalCast<double>("1.0E+500"),
            std::numeric_limits<double>::max());
  EXPECT_EQ(lexicalCast<double>("-1.0E+500"),
            std::numeric_limits<double>::lowest());

  // Values that are not numbers still fail, including the special literals.
  // Whether operator>> accepts these depends on the standard library, so keep
  // every spelling strtod would take covered on both libstdc++ and libc++.
  EXPECT_EQ(lexicalCast<double>("five"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("NaN"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("-nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("-inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("infinity"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>(""), std::nullopt);
}

TEST(UtilitiesTest, lexicalCastFloatOutOfRange)
{
  // The float extractor rejects a merely subnormal result, because strtof
  // reports underflow as ERANGE. Quantum chemistry codes write the decaying
  // tail of a density well past FLT_MIN, so these must still be read.
  EXPECT_NE(lexicalCast<float>("9.293354777E-39"), std::nullopt);
  EXPECT_NEAR(lexicalCast<float>("9.293354777E-39").value_or(-1.0f),
              9.293354777e-39f, 1.0e-40f);
  EXPECT_NEAR(lexicalCast<float>("1.505124610E-39").value_or(-1.0f),
              1.505124610e-39f, 1.0e-40f);

  // Below even a subnormal float, or below double, is effectively zero.
  EXPECT_EQ(lexicalCast<float>("1.0E-60"), 0.0f);
  EXPECT_EQ(lexicalCast<float>("2.61793E-500"), 0.0f);

  // Overflow is clamped rather than becoming an infinity, including a value
  // that is in range for double but not for float.
  EXPECT_EQ(lexicalCast<float>("1.0E+300"), std::numeric_limits<float>::max());
  EXPECT_EQ(lexicalCast<float>("-1.0E+300"),
            std::numeric_limits<float>::lowest());
  EXPECT_EQ(lexicalCast<float>("1.0E+500"), std::numeric_limits<float>::max());

  // Ordinary values are unaffected.
  EXPECT_FLOAT_EQ(lexicalCast<float>("1.000000000").value_or(0.0f), 1.0f);

  // Values that are not numbers still fail.
  EXPECT_EQ(lexicalCast<float>("five"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>(""), std::nullopt);
}

TEST(UtilitiesTest, parseDouble)
{
  EXPECT_EQ(parseAllDouble("5.3"), 5.3);
  EXPECT_EQ(parseAllDouble("-5.3"), -5.3);
  EXPECT_EQ(parseAllDouble("+5.3"), 5.3);
  EXPECT_EQ(parseAllDouble("  \t5.3"), 5.3);
  EXPECT_EQ(parseAllDouble("5.3E-10"), 5.3e-10);
  EXPECT_EQ(parseAllDouble("5"), 5.0);
  EXPECT_EQ(parseAllDouble(".5"), 0.5);
  EXPECT_EQ(parseAllDouble("5."), 5.0);

  // The return value points one past the number.
  const string text = "1.5 2.5";
  double value = 0.0;
  const char* end = parseDouble(text.data(), text.data() + text.size(), value);
  EXPECT_EQ(value, 1.5);
  EXPECT_EQ(end, text.data() + 3);

  // A Fortran 'D' exponent is consumed whole; a letterless one is not, so
  // that a caller can see "1-5" is not a single number.
  EXPECT_EQ(parseAllDouble("1.0D-03"), 0.001);
  EXPECT_EQ(parseAllDouble("1.0d+03"), 1000.0);
  EXPECT_EQ(parseAllDouble("1.0D3"), 1000.0);
  const string range = "1-5";
  value = 0.0;
  end = parseDouble(range.data(), range.data() + range.size(), value);
  EXPECT_EQ(value, 1.0);
  EXPECT_EQ(end, range.data() + 1);
  // "D" with no exponent digits is left unconsumed.
  const string bareD = "1.5D";
  end = parseDouble(bareD.data(), bareD.data() + bareD.size(), value);
  EXPECT_EQ(value, 1.5);
  EXPECT_EQ(end, bareD.data() + 3);

  // The range is honored, not the terminating null.
  const char digits[] = "12345";
  EXPECT_EQ(parseDouble(digits, digits + 3, value), digits + 3);
  EXPECT_EQ(value, 123.0);

  // Nothing parsed: nullptr, and the value is left alone.
  value = 42.0;
  for (const char* bad : { "", "abc", "nan", "inf", "-inf", "-", "+", "  " }) {
    const string text(bad);
    EXPECT_EQ(parseDouble(text.data(), text.data() + text.size(), value),
              nullptr)
      << "accepted: " << bad;
    EXPECT_EQ(value, 42.0);
  }
  EXPECT_EQ(parseDouble(nullptr, nullptr, value), nullptr);

  // Out of range: underflow is a signed zero, overflow is clamped.
  EXPECT_EQ(parseAllDouble("1.25E-500"), 0.0);
  EXPECT_FALSE(std::signbit(parseAllDouble("1.25E-500").value()));
  EXPECT_EQ(parseAllDouble("-2.61793E-500"), 0.0);
  EXPECT_TRUE(std::signbit(parseAllDouble("-2.61793E-500").value()));
  EXPECT_EQ(parseAllDouble("1e400"), std::numeric_limits<double>::max());
  EXPECT_EQ(parseAllDouble("-1e400"), std::numeric_limits<double>::lowest());
}

TEST(UtilitiesTest, parseFloat)
{
  float value = 0.0f;
  const string text = "-1.5e2 rest";
  const char* end = parseFloat(text.data(), text.data() + text.size(), value);
  EXPECT_EQ(value, -150.0f);
  EXPECT_EQ(end, text.data() + 6);

  // Parsed directly as float, so a subnormal is kept.
  const string subnormal = "9.293354777E-39";
  ASSERT_NE(
    parseFloat(subnormal.data(), subnormal.data() + subnormal.size(), value),
    nullptr);
  EXPECT_GT(value, 0.0f);
  EXPECT_LT(value, std::numeric_limits<float>::min());
  EXPECT_NEAR(value, 9.293354777e-39f, 1.0e-40f);

  // Overflow of float, even though the value is fine for a double.
  const string big = "1e39";
  ASSERT_NE(parseFloat(big.data(), big.data() + big.size(), value), nullptr);
  EXPECT_EQ(value, std::numeric_limits<float>::max());
  const string negBig = "-1e39";
  ASSERT_NE(parseFloat(negBig.data(), negBig.data() + negBig.size(), value),
            nullptr);
  EXPECT_EQ(value, std::numeric_limits<float>::lowest());

  // Underflow, keeping the sign.
  const string tiny = "-1e-60";
  ASSERT_NE(parseFloat(tiny.data(), tiny.data() + tiny.size(), value), nullptr);
  EXPECT_EQ(value, 0.0f);
  EXPECT_TRUE(std::signbit(value));

  value = 7.0f;
  const string bad = "nan";
  EXPECT_EQ(parseFloat(bad.data(), bad.data() + bad.size(), value), nullptr);
  EXPECT_EQ(value, 7.0f);
}

TEST(UtilitiesTest, lexicalCastDoubleTermination)
{
  EXPECT_EQ(lexicalCast<double>("5.3"), 5.3);
  EXPECT_EQ(lexicalCast<double>("+5.3"), 5.3);
  EXPECT_EQ(lexicalCast<double>("  5.3"), 5.3);
  EXPECT_EQ(lexicalCast<double>("5.3  "), 5.3);
  EXPECT_EQ(lexicalCast<double>("5.3\n"), 5.3);

  // The first token is used, as with a stream extractor.
  EXPECT_EQ(lexicalCast<double>("1.5 2.0"), 1.5);
  // Punctuation cannot continue a number.
  EXPECT_EQ(lexicalCast<double>("1.5,"), 1.5);
  EXPECT_EQ(lexicalCast<double>("1.5)"), 1.5);

  // Fortran double precision exponents read like 'E' ones.
  EXPECT_DOUBLE_EQ(lexicalCast<double>("1.0D-03").value_or(0.0), 0.001);
  EXPECT_DOUBLE_EQ(lexicalCast<double>("1.0d+03").value_or(0.0), 1000.0);
  EXPECT_DOUBLE_EQ(lexicalCast<double>("1.0D3").value_or(0.0), 1000.0);
  EXPECT_DOUBLE_EQ(lexicalCast<double>("-2.5D-2").value_or(0.0), -0.025);
  EXPECT_EQ(lexicalCast<double>("1.0D-500"), 0.0);
  EXPECT_EQ(lexicalCast<double>("1.0D+500"),
            std::numeric_limits<double>::max());

  // Malformed continuations are rejected, on every standard library. So are
  // the letterless Fortran exponents, which would misread "1-5" as 1e-5.
  EXPECT_EQ(lexicalCast<double>("1.5D"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1.5D+"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1-5"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1.5+2"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1.0-3"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("0.123456-100"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1.5abc"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1.2.3"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1.5e"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("1.5-2"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("abc"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>(""), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("-inf"), std::nullopt);

  // Range errors.
  EXPECT_EQ(lexicalCast<double>("1.25E-500"), 0.0);
  const auto negZero = lexicalCast<double>("-2.61793E-500");
  ASSERT_TRUE(negZero.has_value());
  EXPECT_EQ(*negZero, 0.0);
  EXPECT_TRUE(std::signbit(*negZero));
  EXPECT_EQ(lexicalCast<double>("1e400"), std::numeric_limits<double>::max());
  EXPECT_EQ(lexicalCast<double>("-1e400"),
            std::numeric_limits<double>::lowest());
}

TEST(UtilitiesTest, lexicalCastFloatTermination)
{
  EXPECT_EQ(lexicalCast<float>("5.5"), 5.5f);
  EXPECT_EQ(lexicalCast<float>("+5.5"), 5.5f);
  EXPECT_EQ(lexicalCast<float>("  5.5 "), 5.5f);
  EXPECT_EQ(lexicalCast<float>("1.5 2.0"), 1.5f);
  EXPECT_EQ(lexicalCast<float>("1.5,"), 1.5f);
  EXPECT_EQ(lexicalCast<float>("1.5)"), 1.5f);

  EXPECT_FLOAT_EQ(lexicalCast<float>("1.0D-03").value_or(0.0f), 0.001f);
  EXPECT_FLOAT_EQ(lexicalCast<float>("1.0d+03").value_or(0.0f), 1000.0f);
  EXPECT_EQ(lexicalCast<float>("1.5D"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("1-5"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("1.5+2"), std::nullopt);

  EXPECT_EQ(lexicalCast<float>("1.5abc"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("1.2.3"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("abc"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>(""), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("-inf"), std::nullopt);

  const auto subnormal = lexicalCast<float>("9.293354777E-39");
  ASSERT_TRUE(subnormal.has_value());
  EXPECT_GT(*subnormal, 0.0f);
  EXPECT_LT(*subnormal, std::numeric_limits<float>::min());
  EXPECT_EQ(lexicalCast<float>("1e39"), std::numeric_limits<float>::max());
  EXPECT_EQ(lexicalCast<float>("-1e39"), std::numeric_limits<float>::lowest());

  const auto negZero = lexicalCast<float>("-1e-60");
  ASSERT_TRUE(negZero.has_value());
  EXPECT_EQ(*negZero, 0.0f);
  EXPECT_TRUE(std::signbit(*negZero));
}

// Qt calls setlocale(LC_ALL, "") on Unix, so the C locale follows the user's
// environment. strtod then wants "1,5" and reads "1.5" as 1.
TEST(UtilitiesTest, parsingIgnoresCommaDecimalLocale)
{
  CommaDecimalLocale locale;
  if (!locale.active())
    GTEST_SKIP() << "No de_DE locale is installed";

  EXPECT_DOUBLE_EQ(parseAllDouble("-76.4123").value_or(0.0), -76.4123);
  EXPECT_DOUBLE_EQ(lexicalCast<double>("-76.4123").value_or(0.0), -76.4123);
  EXPECT_FLOAT_EQ(lexicalCast<float>("-76.4123").value_or(0.0f), -76.4123f);
  EXPECT_EQ(lexicalCast<double>("1.25E-500"), 0.0);
}

TEST(UtilitiesTest, lexicalCastCheck)
{
  // Something simple that should pass.
  bool ok(false);
  lexicalCast<int>("5", ok);
  EXPECT_EQ(ok, true);

  // Pass something in that should fail.
  lexicalCast<int>("five", ok);
  EXPECT_EQ(ok, false);
}

TEST(UtilitiesTest, lexicalCastVector)
{
  {
    std::vector<std::string> strings{ "8.314", "6.02e23" };
    auto values = lexicalCast<double>(strings.begin(), strings.end());
    ASSERT_TRUE(values.has_value());
    EXPECT_EQ(values->size(), 2);
  }

  {
    std::vector<std::string> strings{ "96485", "XYZ", "137" };
    auto values = lexicalCast<int>(strings.begin(), strings.end());
    EXPECT_FALSE(values.has_value());
  }
}

TEST(UtilitiesTest, contains)
{
  EXPECT_TRUE(contains("hasFoo", "has"));
  EXPECT_TRUE(contains("hasFoo", "Foo"));
  EXPECT_FALSE(contains("hasFoo", "bar"));
}

TEST(UtilitiesTest, startsWith)
{
  EXPECT_TRUE(startsWith("hasFoo", "has"));
  EXPECT_FALSE(startsWith("hasFoo", "Foo"));
  EXPECT_FALSE(startsWith("hasFoo", "bar"));
}

TEST(UtilitiesTest, toLower)
{
  EXPECT_EQ(toLower("AbC xYz"), "abc xyz");
  EXPECT_EQ(toLower(""), "");
  // Digits and punctuation are unaffected.
  EXPECT_EQ(toLower("H2O-1.5"), "h2o-1.5");
  // Bytes above 127, including UTF-8 sequences, are left alone: only ASCII
  // 'T' lower-cases, the two-byte 'É' (0xC3 0x89) passes through untouched.
  EXPECT_EQ(toLower("\xC3\x89T"), "\xC3\x89t");
}

TEST(UtilitiesTest, caseInsensitiveEquals)
{
  EXPECT_TRUE(caseInsensitiveEquals("cif", "cif"));
  EXPECT_TRUE(caseInsensitiveEquals("cif", "CIF"));
  EXPECT_TRUE(caseInsensitiveEquals("CiF", "cIf"));
  EXPECT_FALSE(caseInsensitiveEquals("cif", "cim"));
  // Different lengths, including a prefix of the other string.
  EXPECT_FALSE(caseInsensitiveEquals("cif", "cifs"));
  EXPECT_FALSE(caseInsensitiveEquals("CIFS", "cif"));
  // Empty strings.
  EXPECT_TRUE(caseInsensitiveEquals("", ""));
  EXPECT_FALSE(caseInsensitiveEquals("", "a"));
  EXPECT_FALSE(caseInsensitiveEquals("a", ""));
  // Digits and punctuation compare exactly; the characters just outside the
  // letter ranges ('@' and '[' around 'A'-'Z', '`' and '{' around 'a'-'z')
  // are not folded into one another.
  EXPECT_TRUE(caseInsensitiveEquals("H2O-1.5", "h2o-1.5"));
  EXPECT_FALSE(caseInsensitiveEquals("H2O", "H3O"));
  EXPECT_FALSE(caseInsensitiveEquals("a-b", "a_b"));
  EXPECT_FALSE(caseInsensitiveEquals("@", "`"));
  EXPECT_FALSE(caseInsensitiveEquals("[", "{"));
  // Bytes above 127 are left as they are: "Ä" (0xC3 0x84) and "ä" (0xC3 0xA4)
  // differ, while the ASCII letters around them still fold.
  EXPECT_FALSE(caseInsensitiveEquals("\xC3\x84", "\xC3\xA4"));
  EXPECT_TRUE(caseInsensitiveEquals("\xC3\x84T", "\xC3\x84t"));
}

namespace {

// The bytes of a 32- or 64-bit pattern in the requested byte order.
template <typename Bits>
std::string bytesOf(Bits bits, Avogadro::Core::ByteOrder endian)
{
  std::string out(sizeof(Bits), '\0');
  for (std::size_t i = 0; i < sizeof(Bits); ++i) {
    const std::size_t shift =
      endian == Avogadro::Core::ByteOrder::BigEndian ? sizeof(Bits) - 1 - i : i;
    out[i] = static_cast<char>((bits >> (8 * shift)) & 0xff);
  }
  return out;
}

float decodeFloat(uint32_t bits, Avogadro::Core::ByteOrder endian)
{
  return Avogadro::Core::unpackFloat(bytesOf(bits, endian).data(), endian);
}

double decodeDouble(uint64_t bits, Avogadro::Core::ByteOrder endian)
{
  return Avogadro::Core::unpackDouble(bytesOf(bits, endian).data(), endian);
}

} // namespace

TEST(UtilitiesTest, unpackInt32)
{
  using Avogadro::Core::unpackInt32;
  const char big[] = { 0x00, 0x00, 0x07, static_cast<char>(0xc9) };
  EXPECT_EQ(unpackInt32(big, Avogadro::Core::ByteOrder::BigEndian), 1993);
  EXPECT_EQ(unpackInt32(big, Avogadro::Core::ByteOrder::LittleEndian),
            static_cast<int32_t>(0xc9070000u));
  const char neg[] = { static_cast<char>(0xff), static_cast<char>(0xff),
                       static_cast<char>(0xff), static_cast<char>(0xfe) };
  EXPECT_EQ(unpackInt32(neg, Avogadro::Core::ByteOrder::BigEndian), -2);
  const char negLittle[] = { static_cast<char>(0xfe), static_cast<char>(0xff),
                             static_cast<char>(0xff), static_cast<char>(0xff) };
  EXPECT_EQ(unpackInt32(negLittle, Avogadro::Core::ByteOrder::LittleEndian),
            -2);
  const char minInt[] = { static_cast<char>(0x80), 0, 0, 0 };
  EXPECT_EQ(unpackInt32(minInt, Avogadro::Core::ByteOrder::BigEndian),
            std::numeric_limits<int32_t>::min());
}

TEST(UtilitiesTest, unpackFloat)
{
  for (auto endian : { Avogadro::Core::ByteOrder::BigEndian,
                       Avogadro::Core::ByteOrder::LittleEndian }) {
    EXPECT_EQ(decodeFloat(0x3fc00000u, endian), 1.5f);
    EXPECT_EQ(decodeFloat(0xc2f6e979u, endian), -123.456f);

    const float negZero = decodeFloat(0x80000000u, endian);
    EXPECT_EQ(negZero, 0.0f);
    EXPECT_TRUE(std::signbit(negZero));
    const float posZero = decodeFloat(0x00000000u, endian);
    EXPECT_EQ(posZero, 0.0f);
    EXPECT_FALSE(std::signbit(posZero));

    EXPECT_EQ(decodeFloat(0x00000001u, endian),
              std::numeric_limits<float>::denorm_min());
    EXPECT_EQ(decodeFloat(0x00800000u, endian),
              std::numeric_limits<float>::min());
    EXPECT_EQ(decodeFloat(0x007fffffu, endian),
              std::nextafter(std::numeric_limits<float>::min(), 0.0f));
    EXPECT_EQ(decodeFloat(0x7f800000u, endian),
              std::numeric_limits<float>::infinity());
    EXPECT_EQ(decodeFloat(0xff800000u, endian),
              -std::numeric_limits<float>::infinity());
    EXPECT_TRUE(std::isnan(decodeFloat(0x7fc00000u, endian)));
  }
}

TEST(UtilitiesTest, unpackDouble)
{
  for (auto endian : { Avogadro::Core::ByteOrder::BigEndian,
                       Avogadro::Core::ByteOrder::LittleEndian }) {
    EXPECT_EQ(decodeDouble(0x3ff8000000000000ull, endian), 1.5);
    EXPECT_EQ(decodeDouble(0xc05edd2f1a9fbe77ull, endian), -123.456);

    const double negZero = decodeDouble(0x8000000000000000ull, endian);
    EXPECT_EQ(negZero, 0.0);
    EXPECT_TRUE(std::signbit(negZero));

    EXPECT_EQ(decodeDouble(0x0000000000000001ull, endian),
              std::numeric_limits<double>::denorm_min());
    EXPECT_EQ(decodeDouble(0x0010000000000000ull, endian),
              std::numeric_limits<double>::min());
    EXPECT_EQ(decodeDouble(0x7ff0000000000000ull, endian),
              std::numeric_limits<double>::infinity());
    EXPECT_EQ(decodeDouble(0xfff0000000000000ull, endian),
              -std::numeric_limits<double>::infinity());
    EXPECT_TRUE(std::isnan(decodeDouble(0x7ff8000000000000ull, endian)));
  }
}
