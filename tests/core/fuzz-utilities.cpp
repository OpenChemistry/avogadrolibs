/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/utilities.h>

#include <cstdlib>
#include <cstring>
#include <string_view>
#include <vector>

#include "fuzzhelpers.h"

using namespace Avogadro::Core;
using namespace Avogadro::FuzzHelpers;

// Fuzz string parsing and conversion utilities
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  std::string input = consumeString(fdp);
  split(input, ' ');
  split(input, ',', false);
  split(input, '\n');
  trimmed(input);
  lexicalCast<int>(input);
  lexicalCast<double>(input);
  lexicalCast<float>(input);
  contains(input, "test");
  contains(input, "TEST", false);
  startsWith(input, "begin");
  endsWith(input, "end");

  // The in-place tokenizer and string_view casts must agree with the
  // std::string versions. Integers are not compared: stream extractors
  // differ between standard libraries.
  std::vector<std::string_view> tokens;
  tokenize(input, tokens);
  const auto expected = splitWhitespace(input);
  if (tokens.size() != expected.size())
    std::abort();
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    if (tokens[i] != expected[i] || tokens[i].empty())
      std::abort();
  }
  lexicalCast<int>(std::string_view(input));
  lexicalCast<unsigned int>(std::string_view(input));
  lexicalCast<std::size_t>(std::string_view(input));
  lexicalCast<short int>(std::string_view(input));
  for (const auto& token : tokens) {
    const std::string copy(token);
    if (lexicalCast<double>(token) != lexicalCast<double>(copy))
      std::abort();
    if (lexicalCast<float>(token) != lexicalCast<float>(copy))
      std::abort();
    lexicalCast<int>(token);
  }
  if (lexicalCast<double>(std::string_view(input)) !=
      lexicalCast<double>(input))
    std::abort();
  if (lexicalCast<float>(std::string_view(input)) != lexicalCast<float>(input))
    std::abort();

  return 0;
}
