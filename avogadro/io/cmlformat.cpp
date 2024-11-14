/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cmlformat.h"

#ifdef AVO_USE_HDF5
#include "hdf5dataformat.h"
#endif

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>

#include <pugixml.hpp>

#include <bitset>
#include <cmath>
#include <locale>
#include <map>
#include <sstream>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace Avogadro::Io {

namespace {
const Real DEG_TO_RAD = static_cast<Avogadro::Real>(M_PI / 180.0);
const Real RAD_TO_DEG = static_cast<Avogadro::Real>(180.0 / M_PI);
}

using std::string;

using pugi::xml_document;
using pugi::xml_node;
using pugi::xml_attribute;

using namespace Core;

namespace {

class CmlFormatPrivate
{
public:
  CmlFormatPrivate(Molecule* mol, xml_document& document, std::string filename_)
    : success(false), molecule(mol), moleculeNode(nullptr), filename(filename_)
  {
    // Parse the CML document, and create molecules/elements as necessary.
    moleculeNode = document.child("molecule");
    xml_node cmlNode = document.child("cml");
    if (cmlNode)
      moleculeNode = cmlNode.child("molecule");

    if (moleculeNode) {
// Parse the various components we know about.
#ifdef AVO_USE_HDF5
      data();
#endif
      success = properties();
      if (success)
        success = atoms();
      if (success)
        success = bonds();
    } else {
      error += "Error, no molecule node found.";
      success = false;
    }
  }

  bool properties()
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

    // Unit cell:
    node = moleculeNode.child("crystal");
    if (node) {
      float a(0);
      float b(0);
      float c(0);
      float alpha(0);
      float beta(0);
      float gamma(0);
      enum
      {
        CellA = 0,
        CellB,
        CellC,
        CellAlpha,
        CellBeta,
        CellGamma
      };
      std::bitset<6> parsedValues;
      for (pugi::xml_node scalar = node.child("scalar"); scalar;
           scalar = scalar.next_sibling("scalar")) {
        pugi::xml_attribute title = scalar.attribute("title");
        const float degToRad(static_cast<float>(M_PI) / 180.0f);
        if (title) {
          std::string titleStr(title.value());
          if (titleStr == "a") {
            a = scalar.text().as_float();
            parsedValues.set(CellA);
          } else if (titleStr == "b") {
            b = scalar.text().as_float();
            parsedValues.set(CellB);
          } else if (titleStr == "c") {
            c = scalar.text().as_float();
            parsedValues.set(CellC);
          } else if (titleStr == "alpha") {
            alpha = scalar.text().as_float() * degToRad;
            parsedValues.set(CellAlpha);
          } else if (titleStr == "beta") {
            beta = scalar.text().as_float() * degToRad;
            parsedValues.set(CellBeta);
          } else if (titleStr == "gamma") {
            gamma = scalar.text().as_float() * degToRad;
            parsedValues.set(CellGamma);
          }
        }
      }
      if (parsedValues.count() != 6) {
        error += "Incomplete unit cell description.";
        return false;
      }

      // look for space group, e.g.
      // <symmetry spaceGroup="F -4 2 3">
      xml_node symmetry = node.child("symmetry");
      unsigned short hall = 0;
      if (symmetry) {
        xml_attribute spaceGroup = symmetry.attribute("spaceGroup");
        if (spaceGroup) {
          // look for space group in the space group table
          hall = Core::SpaceGroups::hallNumber(std::string(spaceGroup.value()));
        }
      }

      auto* cell = new UnitCell;
      cell->setCellParameters(a, b, c, alpha, beta, gamma);
      molecule->setUnitCell(cell);
      if (hall != 0)
        molecule->setHallNumber(hall);
    }
    return true;
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
      {
        /* Element Attribute Check */
        xml_attribute elementAtt = node.attribute("elementType");
        if (elementAtt) {
          unsigned char atomicNumber =
            Elements::atomicNumberFromSymbol(elementAtt.value());
          atom = molecule->addAtom(atomicNumber);
        } else {
          // There is no element data, this atom node is corrupt.
          error += "Warning, corrupt element node found.";
          return false;
        }
      }

      {
        /* ID Attribute Check */
        xml_attribute idAtt = node.attribute("id");
        if (idAtt)
          atomIds[std::string(idAtt.value())] = atom.index();
        else // Atom nodes must have IDs - bail.
          return false;
      }

      // Check for 3D geometry.
      {
        /* XYZ3 and Fract Attribute Check */
        xml_attribute x3Att = node.attribute("x3");
        xml_attribute xFractAtt = node.attribute("xFract");
        if (x3Att) {
          xml_attribute y3 = node.attribute("y3");
          xml_attribute z3 = node.attribute("z3");
          if (y3 && z3) {
            // It looks like we have a valid 3D position.
            Vector3 position(lexicalCast<double>(x3Att.value()),
                             lexicalCast<double>(y3.value()),
                             lexicalCast<double>(z3.value()));
            atom.setPosition3d(position);
          } else {
            // Corrupt 3D position supplied for atom.
            return false;
          }
        } else if (xFractAtt) {
          if (!molecule->unitCell()) {
            error += "No unit cell defined. "
                     "Cannot interpret fractional coordinates.";
            return false;
          }
          xml_attribute yF = node.attribute("yFract");
          xml_attribute zF = node.attribute("zFract");
          if (yF && zF) {
            Vector3 coord(static_cast<Real>(xFractAtt.as_float()),
                          static_cast<Real>(yF.as_float()),
                          static_cast<Real>(zF.as_float()));
            molecule->unitCell()->toCartesian(coord, coord);
            atom.setPosition3d(coord);
          } else {
            error += "Missing y or z fractional coordinate on atom.";
            return false;
          }
        }
      }

      // Check for 2D geometry.
      {
        /* XY2 Attribute Check */
        xml_attribute x2Att = node.attribute("x2");
        if (x2Att) {
          xml_attribute y2 = node.attribute("y2");
          if (y2) {
            Vector2 position(lexicalCast<double>(x2Att.value()),
                             lexicalCast<double>(y2.value()));
            atom.setPosition2d(position);
          } else {
            // Corrupt 2D position supplied for atom.
            return false;
          }
        }
      }

      // Check formal charge.
      {
        /* Formal Charge Attribute Check */
        xml_attribute formalChargeAtt = node.attribute("formalCharge");
        if (formalChargeAtt) {
          auto formalCharge = lexicalCast<signed int>(formalChargeAtt.value());
          atom.setFormalCharge(formalCharge);
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
      return true;

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
        std::map<std::string, Index>::const_iterator begin, end;
        begin = atomIds.find(tokens[0]);
        end = atomIds.find(tokens[1]);
        if (begin != atomIds.end() && end != atomIds.end() &&
            begin->second < molecule->atomCount() &&
            end->second < molecule->atomCount()) {
          bond = molecule->addBond(molecule->atom(begin->second),
                                   molecule->atom(end->second));
        } else { // Couldn't parse the bond begin and end.
          return false;
        }
      }

      attribute = node.attribute("order");
      if (attribute && strlen(attribute.value()) == 1) {
        char o = attribute.value()[0];
        switch (o) {
          case '1':
          case 'S':
          case 's':
            bond.setOrder(1);
            break;
          case '2':
          case 'D':
          case 'd':
            bond.setOrder(2);
            break;
          case '3':
          case 'T':
          case 't':
            bond.setOrder(3);
            break;
          case '4':
            bond.setOrder(4);
            break;
          case '5':
            bond.setOrder(5);
            break;
          case '6':
            bond.setOrder(6);
            break;
          default:
            bond.setOrder(1);
        }
      } else {
        bond.setOrder(1);
      }

      // Move on to the next bond node (if there is one).
      node = node.next_sibling("bond");
    }

    return true;
  }

#ifdef AVO_USE_HDF5
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
          error += "CmlFormatPrivate::data: Cannot read data member '" +
                   dataName + "'. Cannot open file " + filename + ".h5.";
          continue;
        }

        if (dataType != "xsd:double") {
          error += "CmlFormatPrivate::data: Cannot read data member '" +
                   dataName + "'. Data type is not 'double'.";
          continue;
        }

        MatrixX matrix;
        if (!hdf5.readDataset(dataStream.str(), matrix)) {
          error += "CmlFormatPrivate::data: Cannot read data member '" +
                   dataName + "': Unable to read data set '" +
                   dataStream.str() + "' from " + filename + ".h5";
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
        } else if (dataType == "xsd:int") {
          int tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        } else if (dataType == "xsd:long") {
          long tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        } else if (dataType == "xsd:float") {
          float tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        } else if (dataType == "xsd:double") {
          double tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        } else if (dataType == "xsd:string") {
          string tmp;
          dataStream >> tmp;
          variant.setValue(tmp);
        } else {
          error +=
            "CmlFormatPrivate::data: handled scalar data type: " + dataType;
          continue;
        }
      }
      molecule->setData(dataName, variant);
    } while ((dataNode = dataNode.next_sibling()));

    hdf5.closeFile();
    return true;
  }
#endif

  bool success;
  Molecule* molecule;
  xml_node moleculeNode;
  std::map<std::string, Index> atomIds;
  string filename;
  string error;
};
}

bool CmlFormat::read(std::istream& file, Core::Molecule& mol)
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

std::string formatNumber(std::stringstream &s, double n)
{
  s.str(""); // clear it
  s.precision(6);
  s << n;
  return s.str();
}

std::string formatNumber(std::stringstream &s, int n)
{
  s.str(""); // clear it
  s << n;
  return s.str();
}

bool CmlFormat::write(std::ostream& out, const Core::Molecule& mol)
{
  xml_document document;

  // Imbue the output stream with the C numeric locale
  //   i.e. modify current stream locale with "C" numeric
  std::locale currentLocale("");
  std::locale numLocale(out.getloc(), "C", std::locale::numeric);
  out.imbue(numLocale);  // imbue modified locale

  // We also need to set the locale temporarily for XML string formatting
  std::stringstream numberStream; // use this to format floats as C-format strings
  numberStream.imbue(numLocale);

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

  // Save the name if present into the file.
  if (mol.data("name").type() == Variant::String) {
    xml_node node = moleculeNode.append_child("name");
    node.text() = mol.data("name").toString().c_str();
  }

  // If the InChI is available, embed that in the CML file.
  if (mol.data("inchi").type() == Variant::String) {
    xml_node node = moleculeNode.append_child("identifier");
    node.append_attribute("convention") = "iupac:inchi";
    node.append_attribute("value") = mol.data("inchi").toString().c_str();
  }

  // Cell specification
  const UnitCell* cell = mol.unitCell();
  if (cell) {
    xml_node crystalNode = moleculeNode.append_child("crystal");

    // Add the unit cell parameters.
    xml_node crystalANode = crystalNode.append_child("scalar");
    xml_node crystalBNode = crystalNode.append_child("scalar");
    xml_node crystalCNode = crystalNode.append_child("scalar");
    xml_node crystalAlphaNode = crystalNode.append_child("scalar");
    xml_node crystalBetaNode = crystalNode.append_child("scalar");
    xml_node crystalGammaNode = crystalNode.append_child("scalar");

    crystalANode.append_attribute("title") = "a";
    crystalBNode.append_attribute("title") = "b";
    crystalCNode.append_attribute("title") = "c";
    crystalAlphaNode.append_attribute("title") = "alpha";
    crystalBetaNode.append_attribute("title") = "beta";
    crystalGammaNode.append_attribute("title") = "gamma";

    crystalANode.append_attribute("units") = "units:angstrom";
    crystalBNode.append_attribute("units") = "units:angstrom";
    crystalCNode.append_attribute("units") = "units:angstrom";
    crystalAlphaNode.append_attribute("units") = "units:degree";
    crystalBetaNode.append_attribute("units") = "units:degree";
    crystalGammaNode.append_attribute("units") = "units:degree";

    crystalANode.text() = formatNumber(numberStream, cell->a()).c_str();
    crystalBNode.text() = formatNumber(numberStream, cell->b()).c_str();
    crystalCNode.text() = formatNumber(numberStream, cell->c()).c_str();
    crystalAlphaNode.text() = formatNumber(numberStream, cell->alpha() * RAD_TO_DEG).c_str();
    crystalBetaNode.text() = formatNumber(numberStream, cell->beta() * RAD_TO_DEG).c_str();
    crystalGammaNode.text() = formatNumber(numberStream, cell->gamma() * RAD_TO_DEG).c_str();

    // add the space group
    unsigned short hall = mol.hallNumber();
    if (hall != 0) {
      xml_node spaceGroupNode = crystalNode.append_child("symmetry");
      spaceGroupNode.append_attribute("spaceGroup") = Core::SpaceGroups::international(hall);
    }
  }

  xml_node atomArrayNode = moleculeNode.append_child("atomArray");
  for (Index i = 0; i < mol.atomCount(); ++i) {
    xml_node atomNode = atomArrayNode.append_child("atom");
    std::ostringstream index;
    index << 'a' << i + 1;
    atomNode.append_attribute("id") = index.str().c_str();
    Atom a = mol.atom(i);
    atomNode.append_attribute("elementType") =
      Elements::symbol(a.atomicNumber());
    if (cell) {
      Vector3 fracPos = cell->toFractional(a.position3d());
      atomNode.append_attribute("xFract") = formatNumber(numberStream,fracPos.x()).c_str();
      atomNode.append_attribute("yFract") = formatNumber(numberStream,fracPos.y()).c_str();
      atomNode.append_attribute("zFract") = formatNumber(numberStream,fracPos.z()).c_str();
    } else {
      atomNode.append_attribute("x3") = formatNumber(numberStream,a.position3d().x()).c_str();
      atomNode.append_attribute("y3") = formatNumber(numberStream,a.position3d().y()).c_str();
      atomNode.append_attribute("z3") = formatNumber(numberStream,a.position3d().z()).c_str();
    }
    if(a.formalCharge() != 0) {
      atomNode.append_attribute("formalCharge") =
          formatNumber(numberStream, a.formalCharge()).c_str();
    }
  }

  xml_node bondArrayNode = moleculeNode.append_child("bondArray");
  for (Index i = 0; i < mol.bondCount(); ++i) {
    xml_node bondNode = bondArrayNode.append_child("bond");
    Bond b = mol.bond(i);
    std::ostringstream index;
    index << "a" << b.atom1().index() + 1 << " a" << b.atom2().index() + 1;
    bondNode.append_attribute("atomRefs2") = index.str().c_str();
    bondNode.append_attribute("order") = b.order();
  }

#ifdef AVO_USE_HDF5
  Hdf5DataFormat hdf5;
  bool openFile = true;

  xml_node dataMapNode = moleculeNode.append_child("dataMap");
  VariantMap dataMap = mol.dataMap();
  for (VariantMap::const_iterator it = dataMap.constBegin(),
                                  itEnd = dataMap.constEnd();
       it != itEnd; ++it) {
    const std::string& name_ = (*it).first;

    // Skip names that are handled elsewhere:
    if (name_ == "inchi")
      continue;

    const Variant& var = (*it).second;
    if (var.type() == Variant::Null) {
      appendError("CmlFormat::writeFile: skipping null dataMap member '" +
                  name_ + "'.");
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
        appendError(
          "CmlFormat::writeFile: Skipping void* molecule data member '" +
          name_ + "'");
        break;
      case Variant::String:
        dataNode.set_name("scalar");
        dataNode.append_attribute("dataType") = "xsd:string";
        dataNode.text() = var.toString().c_str();
        break;
      case Variant::Matrix: {
        if (openFile) {
          if (!hdf5.openFile(fileName() + ".h5",
                             Hdf5DataFormat::ReadWriteAppend)) {
            appendError("CmlFormat::writeFile: Cannot open file: " +
                        fileName() + ".h5");
          }
          openFile = false;
        }

        dataNode.set_name("hdf5data");
        dataNode.append_attribute("dataType") = "xsd:double";
        dataNode.append_attribute("ndims") = "2";
        const MatrixX& matrix = var.toMatrixRef();
        std::stringstream stream;
        stream << matrix.rows() << " " << matrix.cols();
        dataNode.append_attribute("dims") = stream.str().c_str();
        std::string h5Path = std::string("molecule/dataMap/") + name_;
        dataNode.text() = h5Path.c_str();
        hdf5.writeDataset(h5Path, matrix);
      } break;
      default:
        appendError("CmlFormat::writeFile: Unrecognized type for member '" +
                    name_ + "'.");
        break;
    }
  }

  hdf5.closeFile();
#endif

  document.save(out, "  ");

  return true;
}

std::vector<std::string> CmlFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("cml");
  return ext;
}

std::vector<std::string> CmlFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-cml");
  return mime;
}

} // namespace Avogadro::Io
