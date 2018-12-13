#ifndef PQRREQUEST_H
#define PQRREQUEST_H

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QSize>
#include <QtCore/QUrl>
#include <QtCore/QVariantMap>

#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTableWidgetItem>

#include <cctype>

/**
 * @brief The PQRRequest class sends and receives network requests to PQR and
 * updates ui elements from the widget.
 */
namespace Avogadro {
namespace QtPlugins {
class PQRWidget;

class PQRRequest : public QObject
{
  Q_OBJECT

public:
  /**
   * @brief Constructor to initialize the NetworkAcessManager and set pointers to
   * the widget's ui elements.
   * @param tw Pointer to ui's table widget
   * @param gv Pointer to ui's graphics view for SVG preview
   * @param nd Pointer to the name display
   * @param fd Pointer to the formula display
   */
  PQRRequest(QTableWidget*, QLabel*, QLineEdit*, QLabel*, PQRWidget*);

  /**
   * @brief Free the ui pointers
   */
  ~PQRRequest() override;

  /**
   * @brief Sends a network request to search for molecules from PQR;
   * @param url The url to query
   */
  void sendRequest(QString);

  /**
   * @brief Sends a network request to download a file from PQR
   * @param url The url to send the request to
   * @param mol2 The mol2 representation of the molecule to download
   */
  void sendRequest(QString, QString);

  /**
   * @brief Sends a network request to download a png form PQR
   * @param url The url to send the request to
   */
  void sendPNGRequest(QString url);

  /**
   * @brief Called when a molecule is selected to display information about the
   * molecule and start grabbing the SVG preview.
   * @param num The row number of the table result selected
   * @returns The mol2 of the result for the widget to reference
   */
  QString molSelected(int);

private slots:
  /**
   * @brief Parses the JSON response from querying PQR
   */
  void parseJson();

  /**
   * @brief Creates a file after requesting a file from PQR
   */
  void getFile();

  /**
   * @brief Loads PNG data after sending a request
   */
  void SetPNG();

private:
  /**
   * @brief The result struct holds all data received in each result from
   * querying PQR
   */
  struct result
  {
    QString inchikey;
    QString name;
    QString mol2url;
    QString formula;
    float mass;

    // Default constructor
    result()
      : inchikey("Error"), name("Error"), mol2url("Error"), formula("Error"),
        mass(-1.0)
    {}
  };
  /** An array to hold all results from a query */
  std::vector<result> results;

  /** Holds a reply from a network request */
  QNetworkReply* reply;
  /** Used to send/receive network request */
  QNetworkAccessManager* oNetworkAccessManager;
  /** Used to parse JSON results */
  QVariantMap m_jsonResult;

  /** Pointer to dialog */
  PQRWidget* widget;

  /** Pointers to a widget's ui elements */
  QTableWidget* table;
  QLineEdit* nameDisplay;
  QLabel* formulaDisplay;
  QLabel* pngPreview;

  /** Variables to fold file download information for getFile() */
  QString currentMolName;

  /**
   * @brief Takes a formula string and returns a QString with subscript tags
   * @param formula The formula string
   */
  QString parseSubscripts(QString);

  /**
   * @brief Takes a formula string and returns the molecular mass of the
   * molecule
   * @param formula The formula string
   */
  float getMolMass(QString);
};
} // namespace QtPlugins
} // namespace Avogadro
#endif // PQRRequest_H
