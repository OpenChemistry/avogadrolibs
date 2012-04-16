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

#include "cmlformat.h"

#include <avogadro/core/elements.h>

#include <rapidxml.hpp>

#include <boost/algorithm/string.hpp>

#include <fstream>
#include <streambuf>
#include <iostream>
#include <map>

namespace Avogadro {
namespace Io {

using std::ifstream;
using std::string;
using std::cout;
using std::endl;

using rapidxml::xml_document;
using rapidxml::xml_node;
using rapidxml::xml_attribute;

using namespace Core;

namespace {
class CmlFormatPrivate
{
public:
  CmlFormatPrivate(std::vector<Molecule *> &molecules,
                   rapidxml::xml_document<> &document)
    : success(false), molecule(NULL), moleculeNode(NULL)
  {
    // Parse the CML document, and create molecules/elements as necessary.
    moleculeNode = document.first_node("molecule");
    if (moleculeNode) {
      if (molecules.size() == 0) {
        molecules.resize(1, new Molecule());
      }
      else {
        delete molecules[0];
        molecules[0] = new Molecule();
      }
      // We know there is a molecule, and only one molecule.
      molecule = molecules[0];
      // Parse the various components we know about.
      properties();
      bool atomsExist(atoms());
      bool bondsExist(bonds());
      success = atomsExist && bondsExist;
    }
    else {
      cout << "Error, no molecule node found." << endl;
      success = false;
    }
  }

  void properties()
  {
    xml_attribute<> *attribute(0);
    xml_node<> *node(0);
    node = moleculeNode->first_node("name");
    if (node && node->value())
      molecule->setData("name", std::string(node->value()));
    node = moleculeNode->first_node("identifier");
    if (node && node->value()) {
      attribute = node->first_attribute("convention");
      if (attribute && std::string(attribute->value()) == "iupac:inchi") {
        attribute = node->first_attribute("value");
        if (attribute && std::string(attribute->name()) == "value")
          molecule->setData("inchi", std::string(attribute->value()));
      }
    }
  }

  bool atoms()
  {
    xml_node<> *atomArray = moleculeNode->first_node("atomArray");
    if (!atomArray)
      return false;

    xml_node<> *node = atomArray->first_node("atom");
    Atom atom;
    while (node) {
      // Step through all of the atom attributes and store them.
      xml_attribute<> *attribute = node->first_attribute("elementType");
      if (attribute) {
        unsigned char atomicNumber =
          Elements::atomicNumberFromSymbol(attribute->value());
        atom = molecule->addAtom(atomicNumber);
      }
      else {
        // There is no element data, this atom node is corrupt.
        cout << "Warning, corrupt element node found." << endl;
        return false;
      }

      attribute = node->first_attribute("id");
      if (attribute)
        atomIds[std::string(attribute->value())] = atom.index();
      else // Atom nodes must have IDs - bail.
        return false;

      // Check for 3D geometry.
      attribute = node->first_attribute("x3");
      if (attribute) {
        xml_attribute<> *y3 = node->first_attribute("y3");
        xml_attribute<> *z3 = node->first_attribute("z3");
        if (y3 && z3) {
          // It looks like we have a valid 3D position.
          Vector3 position(strtod(attribute->value(), 0),
                           strtod(y3->value(), 0),
                           strtod(z3->value(), 0));
          atom.setPosition3d(position);
        }
        else {
          // Corrupt 3D position supplied for atom.
          return false;
        }
      }

      // Check for 2D geometry.
      attribute = node->first_attribute("x2");
      if (attribute) {
        xml_attribute<> *y2 = node->first_attribute("y2");
        if (y2) {
          Vector2 position(strtod(attribute->value(), 0),
                           strtod(y2->value(), 0));
          atom.setPosition2d(position);
        }
        else {
          // Corrupt 2D position supplied for atom.
          return false;
        }
      }

      // Move on to the next atom node (if there is one).
      node = node->next_sibling("atom");
    }
    return true;
  }

  bool bonds()
  {
    xml_node<> *bondArray = moleculeNode->first_node("bondArray");
    if (!bondArray)
      return false;

    xml_node<> *node = bondArray->first_node("bond");

    while (node) {
      xml_attribute<> *attribute = node->first_attribute("atomRefs2");
      Bond bond;
      if (attribute) {
        // Should contain two elements separated by a space.
        std::string refs(attribute->value());
        std::vector<std::string> tokens;
        boost::split(tokens, refs, boost::is_any_of(" "));
        if (tokens.size() != 2) // Corrupted file/input we don't understand
          return false;
        std::map<std::string, size_t>::const_iterator begin, end;
        begin = atomIds.find(tokens[0]);
        end = atomIds.find(tokens[1]);
        if (begin != atomIds.end() && end != atomIds.end()
            && begin->second < molecule->atomCount()
            && end->second < molecule->atomCount()) {
          bond = molecule->addBond(molecule->atom(begin->second),
                                   molecule->atom(end->second));
        }
        else { // Couldn't parse the bond begin and end.
          return false;
        }
      }

      attribute = node->first_attribute("order");
      if (attribute)
        bond.setOrder(atoi(attribute->value()));

      // Move on to the next bond node (if there is one).
      node = node->next_sibling("bond");
    }

    return true;
  }

  bool success;
  Molecule *molecule;
  xml_node<> *moleculeNode;
  std::map<std::string, size_t> atomIds;
};
}

CmlFormat::CmlFormat()
{
}

CmlFormat::~CmlFormat()
{
}

bool CmlFormat::readFile(const std::string &fileName)
{
  // Read the file into a string.
  std::ifstream file(fileName.c_str());
  std::string contents((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

  xml_document<> document;
  try {
    document.parse<0>(const_cast<char *>(contents.c_str()));
  }
  catch (rapidxml::parse_error &e) {
    cout << "Error parsing XML: " << e.what();
    return false;
  }

  CmlFormatPrivate parser(m_molecules, document);

  return parser.success;
}

bool CmlFormat::writeFile(const std::string &)
{
  return true;
}

Molecule * CmlFormat::molecule(size_t index)
{
  if (index < m_molecules.size())
    return m_molecules[index];
  else
    return 0;
}

} // end Io namespace
} // end Avogadro namespace
