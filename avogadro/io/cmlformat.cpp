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

#include "hdf5dataformat.h"
#include "utilities.h"

#include <avogadro/core/molecule.h>
#include <avogadro/core/elements.h>

#include <pugixml.cpp>

#include <streambuf>
#include <sstream>
#include <map>

namespace Avogadro {
namespace Io {

using std::string;

using pugi::xml_document;
using pugi::xml_node;
using pugi::xml_attribute;

using namespace Core;

namespace {

class CmlFormatPrivate
{
public:
  CmlFormatPrivate(Molecule *mol, xml_document &document, std::string filename_)
    : success(false), molecule(mol), moleculeNode(NULL), filename(filename_)
  {
    // Parse the CML document, and create molecules/elements as necessary.
    moleculeNode = document.child("molecule");
    if (moleculeNode) {
      // Parse the various components we know about.
      data();
      properties();
      success = atoms();
      if (success)
        bonds();
    }
    else {
      error += "Error, no molecule node found.";
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
        error += "Warning, corrupt element node found.";
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
        std::vector<std::string> tokens = split(refs, ' ');
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
        bond.setOrder(static_cast<unsigned char>(atoi(attribute.value())));

      // Move on to the next bond node (if there is one).
      node = node.next_sibling("bond");
    }

    return true;
  }

  bool data()
  {
    xml_node dataNode = moleculeNode.child("dataMap").first_child();
    if (!dataNode)
      return true;

    Hdf5DataFormat hdf5;
    hdf5.openFile(filename + ".h5", Hdf5DataFormat::ReadOnly);

    do {
      std::string dataNodeName = dataNode.name();
      std::string dataName = dataNode.attribute("name").as_string();
      std::string dataType = dataNode.attribute("dataType").as_string();
      std::stringstream dataStream(dataNode.text().as_string());
      Variant variant;

      // Read data from HDF5?
      if (dataNodeName == "hdf5data") {
        if (!hdf5.isOpen()) {
          error += "CmlFormatPrivate::data: Cannot read data member '"
                   + dataName + "'. Cannot open file " + filename + ".h5.";
          continue;
        }

        if (dataType != "xsd:double") {
          error += "CmlFormatPrivate::data: Cannot read data member '"
                   + dataName + "'. Data type is not 'double'.";
          continue;
        }

        MatrixX matrix;
        if (!hdf5.readDataset(dataStream.str(), matrix)) {
          error += "CmlFormatPrivate::data: Cannot read data member '"
                   + dataName + "': Unable to read data set '"
                   + dataStream.str() + "' from " + filename + ".h5";
          continue;
        }

        variant.setValue(matrix);
      }

      // or read data from CML?
      else if (dataNodeName == "scalar") {
        if (dataType == "xsd:boolean") {
          bool tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        }
        else if (dataType == "xsd:int") {
          int tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        }
        else if (dataType == "xsd:long") {
          long tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        }
        else if (dataType == "xsd:float") {
          float tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        }
        else if (dataType == "xsd:double") {
          double tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        }
        else if (dataType == "xsd:string") {
          string tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        }
        else {
          error += "CmlFormatPrivate::data: handled scalar data type: "
                   + dataType;
          continue;
        }
      }
      molecule->setData(dataName, variant);
    } while ((dataNode = dataNode.next_sibling()));

    hdf5.closeFile();
    return true;
  }

  bool success;
  Molecule *molecule;
  xml_node moleculeNode;
  std::map<std::string, size_t> atomIds;
  string filename;
  string error;
};
}

CmlFormat::CmlFormat()
{
}

CmlFormat::~CmlFormat()
{
}

bool CmlFormat::read(std::istream &file, Core::Molecule &mol)
{
  xml_document document;
  pugi::xml_parse_result result = document.load(file);
  if (!result) {
    appendError("Error parsing XML: " + std::string(result.description()));
    return false;
  }

  CmlFormatPrivate parser(&mol, document, fileName());
  if (!parser.success)
    appendError(parser.error);

  return parser.success;
}

bool CmlFormat::write(std::ostream &out, const Core::Molecule &mol)
{
  xml_document document;

  // Add a custom declaration node.
  xml_node declaration = document.prepend_child(pugi::node_declaration);
  declaration.append_attribute("version") = "1.0";
  declaration.append_attribute("encoding") = "UTF-8";

  xml_node moleculeNode = document.append_child("molecule");
  // Standard XML namespaces for CML.
  moleculeNode.append_attribute("xmlns") = "http://www.xml-cml.org/schema";
  moleculeNode.append_attribute("xmlns:cml") =
      "http://www.xml-cml.org/dict/cml";
  moleculeNode.append_attribute("xmlns:units") =
      "http://www.xml-cml.org/units/units";
  moleculeNode.append_attribute("xmlns:xsd") =
      "http://www.w3c.org/2001/XMLSchema";
  moleculeNode.append_attribute("xmlns:iupac") = "http://www.iupac.org";

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
    atomNode.append_attribute("elementType") =
        Elements::symbol(a.atomicNumber());
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

  Hdf5DataFormat hdf5;
  bool openFile = true;

  xml_node dataMapNode = moleculeNode.append_child("dataMap");
  VariantMap dataMap = mol.dataMap();
  for (VariantMap::const_iterator it = dataMap.constBegin(),
       itEnd = dataMap.constEnd(); it != itEnd; ++it) {
    const std::string &name_ = (*it).first;

    // Skip names that are handled elsewhere:
    if (name_ == "inchi")
      continue;

    const Variant &var = (*it).second;
    if (var.type() == Variant::Null) {
      appendError("CmlFormat::writeFile: skipping null dataMap member '"
                  + name_ + "'.");
      continue;
    }

    xml_node dataNode = dataMapNode.append_child();
    dataNode.append_attribute("name") = name_.c_str();

    switch (var.type()) {
    case Variant::Null:
      // Already skipped above
      break;
    case Variant::Bool:
      dataNode.set_name("scalar");
      dataNode.append_attribute("dataType") = "xsd:boolean";
      dataNode.text() = var.toBool();
      break;
    case Variant::Int:
      dataNode.set_name("scalar");
      dataNode.append_attribute("dataType") = "xsd:int";
      dataNode.text() = var.toInt();
      break;
    case Variant::Long:
      dataNode.set_name("scalar");
      dataNode.append_attribute("dataType") = "xsd:long";
      dataNode.text() = var.toString().c_str();
      break;
    case Variant::Float:
      dataNode.set_name("scalar");
      dataNode.append_attribute("dataType") = "xsd:float";
      dataNode.text() = var.toFloat();
      break;
    case Variant::Double:
      dataNode.set_name("scalar");
      dataNode.append_attribute("dataType") = "xsd:double";
      dataNode.text() = var.toDouble();
      break;
    case Variant::Pointer:
      appendError("CmlFormat::writeFile: Skipping void* molecule data member '"
                  + name_ + "'");
      break;
    case Variant::String:
      dataNode.set_name("scalar");
      dataNode.append_attribute("dataType") = "xsd:string";
      dataNode.text() = var.toString().c_str();
      break;
    case Variant::Matrix: {
      if(openFile) {
        if (!hdf5.openFile(fileName() + ".h5", Hdf5DataFormat::ReadWriteAppend)) {
          appendError("CmlFormat::writeFile: Cannot open file: "
                      + fileName() + ".h5");
        }
        openFile = false;
      }

      dataNode.set_name("hdf5data");
      dataNode.append_attribute("dataType") = "xsd:double";
      dataNode.append_attribute("ndims") = "2";
      const MatrixX &matrix = var.toMatrixRef();
      std::stringstream stream;
      stream << matrix.rows() << " " << matrix.cols();
      dataNode.append_attribute("dims") = stream.str().c_str();
      std::string h5Path = std::string("molecule/dataMap/") + name_;
      dataNode.text() = h5Path.c_str();
      hdf5.writeDataset(h5Path, matrix);
    }
      break;
    default:
      appendError("CmlFormat::writeFile: Unrecognized type for member '"
                  + name_ + "'.");
      break;
    }
  }

  hdf5.closeFile();

  document.save(out, "  ");

  return true;
}

std::vector<std::string> CmlFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("cml");
  return ext;
}

std::vector<std::string> CmlFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("chemical/x-cml");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
