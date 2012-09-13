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

#include <pugixml.cpp>

#include <boost/algorithm/string.hpp>

#include <fstream>
#include <streambuf>
#include <iostream>
#include <sstream>
#include <map>

namespace Avogadro {
namespace Io {

using std::ifstream;
using std::string;
using std::cout;
using std::endl;

using pugi::xml_document;
using pugi::xml_node;
using pugi::xml_attribute;

using namespace Core;

namespace {
class CmlFormatPrivate
{
public:
  CmlFormatPrivate(Molecule *mol, xml_document &document)
    : success(false), molecule(mol), moleculeNode(NULL)
  {
    // Parse the CML document, and create molecules/elements as necessary.
    moleculeNode = document.child("molecule");
    if (moleculeNode) {
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
    xml_attribute attribute;
    xml_node node;
    node = moleculeNode.child("name");
    if (node && node.value())
      molecule->setData("name", std::string(node.child_value()));
    node = moleculeNode.child("identifier");
    if (node && node.value()) {
      attribute = node.attribute("convention");
      if (attribute && std::string(attribute.value()) == "iupac:inchi") {
        attribute = node.attribute("value");
        if (attribute && std::string(attribute.name()) == "value")
          molecule->setData("inchi", std::string(attribute.value()));
      }
    }
  }

  bool atoms()
  {
    xml_node atomArray = moleculeNode.child("atomArray");
    if (!atomArray)
      return false;

    xml_node node = atomArray.child("atom");
    Atom atom;
    while (node) {
      // Step through all of the atom attributes and store them.
      xml_attribute attribute = node.attribute("elementType");
      if (attribute) {
        unsigned char atomicNumber =
          Elements::atomicNumberFromSymbol(attribute.value());
        atom = molecule->addAtom(atomicNumber);
      }
      else {
        // There is no element data, this atom node is corrupt.
        cout << "Warning, corrupt element node found." << endl;
        return false;
      }

      attribute = node.attribute("id");
      if (attribute)
        atomIds[std::string(attribute.value())] = atom.index();
      else // Atom nodes must have IDs - bail.
        return false;

      // Check for 3D geometry.
      attribute = node.attribute("x3");
      if (attribute) {
        xml_attribute y3 = node.attribute("y3");
        xml_attribute z3 = node.attribute("z3");
        if (y3 && z3) {
          // It looks like we have a valid 3D position.
          Vector3 position(strtod(attribute.value(), 0),
                           strtod(y3.value(), 0),
                           strtod(z3.value(), 0));
          atom.setPosition3d(position);
        }
        else {
          // Corrupt 3D position supplied for atom.
          return false;
        }
      }

      // Check for 2D geometry.
      attribute = node.attribute("x2");
      if (attribute) {
        xml_attribute y2 = node.attribute("y2");
        if (y2) {
          Vector2 position(strtod(attribute.value(), 0),
                           strtod(y2.value(), 0));
          atom.setPosition2d(position);
        }
        else {
          // Corrupt 2D position supplied for atom.
          return false;
        }
      }

      // Move on to the next atom node (if there is one).
      node = node.next_sibling("atom");
    }
    return true;
  }

  bool bonds()
  {
    xml_node bondArray = moleculeNode.child("bondArray");
    if (!bondArray)
      return false;

    xml_node node = bondArray.child("bond");

    while (node) {
      xml_attribute attribute = node.attribute("atomRefs2");
      Bond bond;
      if (attribute) {
        // Should contain two elements separated by a space.
        std::string refs(attribute.value());
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

      attribute = node.attribute("order");
      if (attribute)
        bond.setOrder(atoi(attribute.value()));

      // Move on to the next bond node (if there is one).
      node = node.next_sibling("bond");
    }

    return true;
  }

  bool success;
  Molecule *molecule;
  xml_node moleculeNode;
  std::map<std::string, size_t> atomIds;
};
}

CmlFormat::CmlFormat()
{
}

CmlFormat::~CmlFormat()
{
}

bool CmlFormat::readFile(const std::string &fileName, Core::Molecule &mol)
{
  // Read the file into a string.
  std::ifstream file(fileName.c_str());
  if (!file.is_open()) {
    cout << "Error opening file: " << fileName << endl;
    return false;
  }

  xml_document document;
  pugi::xml_parse_result result = document.load(file);
  if (!result) {
    cout << "Error parsing XML: " << result.description() << endl;
    return false;
  }

  CmlFormatPrivate parser(&mol, document);

  return true;
}

bool CmlFormat::writeFile(const std::string &fileName,
                          const Core::Molecule &mol)
{
  xml_document document;

  // Add a custom declaration node.
  xml_node declaration = document.prepend_child(pugi::node_declaration);
  declaration.append_attribute("version") = "1.0";
  declaration.append_attribute("encoding") = "UTF-8";

  xml_node moleculeNode = document.append_child("molecule");
  // Standard XML namespaces for CML.
  moleculeNode.append_attribute("xmlns") = "http://www.xml-cml.org/schema";
  moleculeNode.append_attribute("xmlns:cml") = "http://www.xml-cml.org/dict/cml";
  moleculeNode.append_attribute("xmlns:units") = "http://www.xml-cml.org/units/units";
  moleculeNode.append_attribute("xmlns:xsd") = "http://www.w3c.org/2001/XMLSchema";
  moleculeNode.append_attribute("xmlns:iupac") = "http://www.iupac.org";

  // Molecule identifier.
  moleculeNode.append_attribute("id") = "CS_Ethane";

  // If the InChI is available, embed that in the CML file.
  if (mol.data("inchi").type() == Variant::String) {
    xml_node node = moleculeNode.append_child("identifier");
    node.append_attribute("convention") = "iupac:inchi";
    node.append_attribute("value") = mol.data("inchi").toString().c_str();
  }

  xml_node atomArrayNode = moleculeNode.append_child("atomArray");
  for (size_t i = 0; i < mol.atomCount(); ++i) {
    xml_node atomNode = atomArrayNode.append_child("atom");
    std::ostringstream index;
    index << 'a' <<  i + 1;
    atomNode.append_attribute("id") = index.str().c_str();
    Atom a = mol.atom(i);
    atomNode.append_attribute("elementType") = Elements::symbol(a.atomicNumber());
    atomNode.append_attribute("x3") = a.position3d().x();
    atomNode.append_attribute("y3") = a.position3d().y();
    atomNode.append_attribute("z3") = a.position3d().z();
  }

  xml_node bondArrayNode = moleculeNode.append_child("bondArray");
  for (size_t i = 0; i < mol.bondCount(); ++i) {
    xml_node bondNode = bondArrayNode.append_child("bond");
    Bond b = mol.bond(i);
    std::ostringstream index;
    index << "a" << b.atom1().index() + 1 << " a" << b.atom2().index() + 1;
    bondNode.append_attribute("atomRefs2") = index.str().c_str();
    bondNode.append_attribute("order") = b.order();
  }

  document.save(std::cout, "  ");
  document.save_file(fileName.c_str(), "  ");

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
