#ifndef AVOGADRO_PQRWIDGET_H
#define AVOGADRO_PQRWIDGET_H

#include <QtWidgets/QDialog>
#include <QtWidgets/QGraphicsRectItem>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTableWidgetItem>

#include <QtGui/QPixmap>

#include <QtNetwork/QNetworkReply>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QSortFilterProxyModel>

/**
 * PQRWidget is a class extending QDialog to provide the ui for
 * importing/downloading
 * molecules from PQR.
 */

namespace Ui {
class PQRWidget;
}

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {
class PQRRequest;
class ImportPQR;

class PQRWidget : public QDialog
{
  Q_OBJECT

public:
  PQRWidget(QWidget* parent = nullptr, ImportPQR* p = nullptr);
  ~PQRWidget() override;
  void loadMolecule(QByteArray&, QString);
  void loadPNG(QByteArray&);

private slots:

  /**
   * @brief Called when the search button is clicked to send a query to PQR
   */
  void searchAction();

  /**
   * @brief Called when a table result is double clicked to display preview
   * information
   * about the result before downloading.
   * @param row The row of the result selected.
   * @param col The column of the result selected.
   */
  void molSelected(int, int);

  /**
   * @brief Called when the download button is clicked to send a request to
   * download
   * molecule information from PQR.
   */
  void downloadMol();

private:
  /** The mol2 of the molecule result currently selected */
  QString currentlySelectedMol;
  /** Pointer to the ui objects */
  Ui::PQRWidget* ui;
  /** Pointer to a PQRRequest object to handle network requests */
  PQRRequest* request;
  /** Pointer to the plugin that opened the dialog */
  ImportPQR* plugin;
};
}
}
#endif // AVOGADRO_PQRWIDGET_H
