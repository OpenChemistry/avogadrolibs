/**
 * We expect to get two arguments, plus an optional third argument. The first
 * argument should be the input file name, the second the output file name and
 * if supplied the final one would be the variable name.
 */

#include <iostream>
#include <fstream>

int main(int argc, char *argv[])
{
  if (argc < 3) {
    std::cout << "Error: we need a file as input." << std::endl;
    return 1;
  }

  std::ifstream input(argv[1]);
  if (!input.is_open()) {
    std::cout << "Failed to open input file: " << argv[1] << std::endl;
    return 1;
  }

  std::ofstream output(argv[2]);
  if (!output.is_open()) {
    std::cout << "Failed to open output file:" << argv[2] << std::endl;
    return 1;
  }

  output << "const char *";
  if (argc > 3)
    output << argv[3];
  else
    output << "inputvariable";
  output << " =";
  while (!input.eof()) {
    char buffer[256];
    input.getline(buffer, 256);
    output << std::endl << "  \"" << buffer << "\\n\"";
  }
  output << ";" << std::endl;

  return 0;
}
