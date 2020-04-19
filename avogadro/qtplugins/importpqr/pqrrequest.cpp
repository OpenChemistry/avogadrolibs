#include "pqrrequest.h"
#include "pqrwidget.h"

#include <avogadro/core/elements.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace Avogadro {
namespace QtPlugins {
/**
* @brief Constructor to initialize the NetworkAcessManager and set pointers to
* the widget's ui elements.
*/
PQRRequest::PQRRequest(QTableWidget* tw, QLabel* gv, QLineEdit* nd, QLabel* fd,
                       PQRWidget* w)
{
  // set pointers to ui elements now instead of in individual functions
  table = tw;          // pointer to ui table
  pngPreview = gv;     // png QLabel
  nameDisplay = nd;    // name
  formulaDisplay = fd; // formula

  // used to load molecule in Avogadro when downloaded
  widget = w;
  oNetworkAccessManager = new QNetworkAccessManager(this);
}

/**
* @brief Free the ui pointers
*/
PQRRequest::~PQRRequest()
{
  delete oNetworkAccessManager;
}

/**
* @brief Sends a network request to search for molecules from PQR;
* @param url The url to query
*/
void PQRRequest::sendRequest(QString url)
{
  reply = oNetworkAccessManager->get(QNetworkRequest(QUrl(url)));
  connect(reply, SIGNAL(finished()), this, SLOT(parseJson()));
}

/**
* @brief Sends a network request to download a file from PQR
* @param url The url to send the request to
* @param mol2 The mol2 representation of the molecule to download
*/
void PQRRequest::sendRequest(QString url, QString mol2)
{
  reply = oNetworkAccessManager->get(QNetworkRequest(QUrl(url)));
  currentMolName = nameDisplay->text(); // needed to load mol into Avogadro
  connect(reply, SIGNAL(finished()), this, SLOT(getFile()));
}

/**
* @brief Sends a network request to download a png form PQR
* @param url The url to send the request to
*/
void PQRRequest::sendPNGRequest(QString url)
{
  reply = oNetworkAccessManager->get(QNetworkRequest(QUrl(url)));
  connect(reply, SIGNAL(finished()), this, SLOT(SetPNG()));
}

/**
* @brief Called when a molecule is selected to display information about the
* molecule and start grabbing the SVG preview.
* @param num The row number of the table result selected
* @returns The mol2 of the result for the widget to reference
*/
QString PQRRequest::molSelected(int num)
{
  if (results.empty() || num > results.size())
    return QString("N/A");

  QString mol2 = results[num].mol2url;
  QString url = "https://pqr.pitt.edu/static/data/png/" + mol2 + ".png";
  sendPNGRequest(url);

  formulaDisplay->setText(parseSubscripts(results[num].formula));
  nameDisplay->setText(results[num].name);

  return mol2;
}

/**
* @brief Parses the JSON response from querying PQR
*/
void PQRRequest::parseJson()
{
  if (reply->error() == QNetworkReply::NoError) {
    // Reading the data from the response
    QByteArray bytes = reply->readAll();

    // parse the json
    json root = json::parse(bytes.data());

    int resultSize = root.size();

    results.clear();
    if (resultSize == 0) {
      table->setRowCount(1);
      table->setItem(0, 0, new QTableWidgetItem("No Results!"));
      table->setCellWidget(0, 1, new QLabel());
      table->setItem(0, 2, new QTableWidgetItem("N/A"));
    } else {
      table->setRowCount(resultSize);
      for (int i = 0; i < resultSize; i++) {
        results.push_back(result());

        // Loop through the keys
        for (auto it = root[i].cbegin(); it != root[i].cend(); ++it) {
          if (it.key() == "formula" && it.value().is_string())
            results[i].formula = it.value().get<std::string>().c_str();
          else if (it.key() == "inchikey" && it.value().is_string())
            results[i].inchikey = it.value().get<std::string>().c_str();
          else if (it.key() == "mol2url" && it.value().is_string())
            results[i].mol2url = it.value().get<std::string>().c_str();
          else if (it.key() == "name" && it.value().is_string())
            results[i].name = it.value().get<std::string>().c_str();
        }
        results[i].mass = getMolMass(results[i].formula);

        table->setItem(i, 0, new QTableWidgetItem(results[i].name));

        // clear possible QTableWidget if there were no results previously
        table->setItem(i, 1, nullptr);
        // use this to display subscripts, should automatically delete previous
        // QLabel according to documentation
        table->setCellWidget(i, 1,
                             new QLabel(parseSubscripts(results[i].formula)));

        // table->setItem(i, 2, new
        // QTableWidgetItem(QString::number(results[i].mass, 'f', 3) + QString("
        // g/mol")));
        QTableWidgetItem* massItem = new QTableWidgetItem();
        massItem->setData(Qt::DisplayRole, results[i].mass);
        table->setItem(i, 2, massItem);
      }
    }
  } else {
    table->setRowCount(3);
    table->setItem(0, 0, new QTableWidgetItem("Network Error!"));
    table->setItem(0, 1, new QTableWidgetItem("N/A"));
    table->setItem(0, 2, new QTableWidgetItem(reply->errorString()));
  }
  reply->deleteLater();
}

/**
* @brief Creates a file after requesting a file from PQR
*/
void PQRRequest::getFile()
{
  QByteArray molData = reply->readAll();
  widget->loadMolecule(molData, currentMolName);
  reply->deleteLater();
}

/**
* @brief Loads PNG data after sending a request
*/
void PQRRequest::SetPNG()
{
  QByteArray pngData = reply->readAll();
  widget->loadPNG(pngData);
  reply->deleteLater();
}

/**
* @brief Takes a formula string and returns a QString with subscript tags
* @param formula The formula string
*/
QString PQRRequest::parseSubscripts(QString formula)
{
  std::string str = formula.toStdString();
  QString toReturn;
  for (int i = 0; i < str.length(); i++) {
    if (isdigit(str[i])) {
      toReturn.append("<sub>");
      toReturn.append(str[i]);
      toReturn.append("</sub>");
    } else {
      toReturn.append(str[i]);
    }
  }
  return toReturn;
}

/**
* @brief Takes a formula string and returns the molecular mass of the molecule
* @param formula The formula string
*/
float PQRRequest::getMolMass(QString formula)
{
  std::string str = formula.toStdString();
  float totalMass = 0.0;
  int subscript = 1;
  std::string element;
  unsigned char atomicNum;
  for (int i = 0; i < str.length(); i++) {
    // each element will start with a capital letter
    if (isupper(str[i])) {
      // if next letter is a lower case then we know the whole element
      if (islower(str[i + 1])) {
        element = { str[i], str[i + 1] };
        // this might be the last element of the formula
        if (isdigit(str[i + 2])) {
          subscript = (int)str[i + 2] - '0';
          i += 2; // increment past lowercase and numeral
        } else {
          i += 1;
          subscript = 1;
        }
      }
      // get the subscript
      else if (isdigit(str[i + 1])) {
        if (isdigit(str[i + 2])) {
          // might be 2 digit subscript
          subscript = (int)str[i + 1] - '0';
          subscript *= 10; // shift forward one decimal place
          subscript += (int)str[i + 2] - '0';
          element = { str[i] };
          i += 2;
        } else {
          subscript = (int)str[i + 1] - '0';
          element = { str[i] };
          i += 1;
        }
      }
      // if the next letter is another uppercase or null, the current subscript
      // is 1
      else if (isupper(str[i + 1]) || str[i + 1] == 0) {
        subscript = 1;
        element = { str[i] };
      }
      atomicNum = Core::Elements::atomicNumberFromSymbol(element);
      totalMass += (subscript * Core::Elements::mass(atomicNum));
    }
  }
  return totalMass;
}
} // namespace QtPlugins
} // namespace Avogadro
