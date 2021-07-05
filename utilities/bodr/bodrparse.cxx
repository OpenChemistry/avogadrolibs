/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <pugixml.cpp>

#include <avogadro/core/utilities.h>

#include <fstream>
#include <string>
#include <iostream>
#include <vector>

using std::ifstream;
using std::ofstream;
using std::string;
using std::cout;
using std::endl;
using std::vector;

using pugi::xml_document;
using pugi::xml_node;
using pugi::xml_attribute;

struct Color {
  Color() { c[0] = c[1] = c[2] = 0; }
  Color(unsigned char r, unsigned char g, unsigned char b)
  {
    c[0] = r; c[1] = g; c[2] = b;
  }
  unsigned char c[3];
};

struct Element {
  Element(const string &_id) : symbol(_id), atomicNumber(0), mass(-1.0),
    radiusCovalent(-1.0), radiusVDW(-1.0)
  {
  }
  string id; // This is the symbol normally.
  string symbol;
  string name;
  unsigned char atomicNumber;
  double mass;
  double radiusCovalent;
  double radiusVDW;
  Color color;
};

// Separate the three components, then cast for unsigned char and store.
bool colorFromString(const std::string &str, Color &color)
{
  std::vector<std::string> tokens = Avogadro::Core::split(str, ' ');
  if (tokens.size() != 3) {// Corrupted file/input we don't understand
    cout << "Error processing color, wrong number of components "
         << tokens.size() << endl;
    return false;
  }

  for (unsigned char i = 0; i < 3; ++i)
    color.c[i] =
      static_cast<unsigned char>(255.0 * strtod(tokens[i].c_str(), nullptr));

  return true;
}

int main(int argc, char* argv[])
{
  if (argc != 3) {
    cout << "Incorrrect number of arguments specified. "
         << "2 arguments expected, path to input xml, and output file name."
         << endl;
    return 1;
  }

  ifstream file(argv[1]);
  if (!file.is_open()) {
    cout << "Failed to open file " << argv[1] << endl;
    return 1;
  }

  xml_document document;
  pugi::xml_parse_result result = document.load(file);
  if (!result) {
    cout << "Error parsing XML: " << result.description() << endl;
    return 1;
  }

  // Construct a vector to contain all of the elements
  std::vector<Element> elements;
  int elementCount = 0;

  xml_node rootNode = document.child("list");
  if (rootNode) {
    xml_node atomNode = rootNode.child("atom");
    while (atomNode) {
      xml_attribute attribute = atomNode.attribute("id");
      if (attribute) {
        elements.push_back(Element(string(attribute.value())));
      }
      else {
        cout << "Error, no atom id found. Skipping this entry." << endl;
        atomNode = atomNode.next_sibling("atom");
        continue;
      }

      // Get the data we care about, put it into out struct.
      xml_node labelNode = atomNode.child("label");
      while (labelNode) {
        attribute = labelNode.attribute("dictRef");
        if (attribute) {
          string value(attribute.value());
          if (value == "bo:symbol")
            elements.back().symbol = labelNode.attribute("value").value();
          else if (value == "bo:name")
            elements.back().name = labelNode.attribute("value").value();
        }
        labelNode = labelNode.next_sibling("label");
      }
      xml_node scalarNode = atomNode.child("scalar");
      while (scalarNode) {
        attribute = scalarNode.attribute("dictRef");
        if (attribute) {
          string value(attribute.value());
          if (value == "bo:atomicNumber") {
            elements.back().atomicNumber =
                static_cast<unsigned char>(atoi(scalarNode.child_value()));
          }
          else if (value == "bo:mass") {
            elements.back().mass = strtod(scalarNode.child_value(), nullptr);
          }
          else if (value == "bo:radiusCovalent") {
            elements.back().radiusCovalent =
                strtod(scalarNode.child_value(), nullptr);
          }
          else if (value == "bo:radiusVDW") {
            elements.back().radiusVDW =
              strtod(scalarNode.child_value(), nullptr);
          }
        }
        scalarNode = scalarNode.next_sibling("scalar");
      }
      xml_node arrayNode = atomNode.child("array");
      while (arrayNode) {
        attribute = arrayNode.attribute("dictRef");
        if (attribute) {
          string value(attribute.value());
          if (value == "bo:elementColor")
            colorFromString(arrayNode.child_value(), elements.back().color);
        }
        arrayNode = arrayNode.next_sibling("array");
      }

      ++elementCount;
      atomNode = atomNode.next_sibling("atom");
    }
  }
  file.close();

  // Now to write our source files.
  string outputFileName = string(argv[2]) + ".h";
  ofstream output(outputFileName.c_str());
  if (!output.is_open()) {
    cout << "Failed to open file " << outputFileName << endl;
    return 1;
  }

  output << "// This file is automatically generated. Do not edit.\n\n"
         << "#ifndef AVOGADRO_CORE_ELEMENTS_DATA\n"
         << "#define AVOGADRO_CORE_ELEMENTS_DATA\n\n"
         << "namespace Avogadro {\nnamespace Core {\n\n";

  output << "unsigned char element_count = " << elements.size() << ";\n\n";

  // First generate the symbol table.

  output << "const char* element_symbols[] = { ";
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i > 0)
      output << ",";
    if (i % 10 == 0)
      output <<"\n ";
    output << " \"" << elements[i].symbol << "\"";
  }
  output << " };\n\n";

  output << "const char* element_names[] = { ";
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i > 0)
      output << ",";
    if (i % 5 == 0)
      output <<"\n ";
    output << " \"" << elements[i].name << "\"";
  }
  output << " };\n\n";

  output << "double element_masses[] = { ";
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i > 0)
      output << ",";
    if (i % 7 == 0)
      output <<"\n ";
    output << " " << elements[i].mass;
  }
  output << " };\n\n";

  output << "double element_VDW[] = { ";
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i > 0)
      output << ",";
    if (i % 10 == 0)
      output <<"\n ";
    output << " " << elements[i].radiusVDW;
  }
  output << " };\n\n";

  output << "double element_covalent[] = { ";
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i > 0)
      output << ",";
    if (i % 10 == 0)
      output <<"\n ";
    output << " " << elements[i].radiusCovalent;
  }
  output << " };\n\n";

  output << "unsigned char element_color[][3] = { ";
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i > 0)
      output << ",";
    if (i % 3 == 0)
      output <<"\n ";
    output << " {" << int(elements[i].color.c[0])
           << ", " << int(elements[i].color.c[1])
           << ", " << int(elements[i].color.c[2]) << "}";
  }
  output << " };\n\n";

  output << "}\n}\n\n#endif\n";

  output.close();

  return 0;
}
