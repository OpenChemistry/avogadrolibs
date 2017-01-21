#ifndef AVOGADRO_DOWNLOADERWIDGET_H
#define AVOGADRO_DOWNLOADERWIDGET_H

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QtCore/QVariantMap>
#include <QtWidgets/QDialog>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTableWidgetItem>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QGraphicsRectItem>
#include <QtCore/QStandardPaths>
#include <QtCore/QList>
#include <QtCore/QFile>
#include <QtCore/QMutex>
#include <QtCore/QDir>
#include <QtCore/QStringList>
#include <json/json.h>

namespace Ui {
class DownloaderWidget;
}

namespace Avogadro {


namespace QtPlugins {
//class PQRRequest;
//class ImportPQR;

class DownloaderWidget : public QDialog
{
  Q_OBJECT

public:
  DownloaderWidget(QWidget *parent = 0);
  ~DownloaderWidget();

public slots:
	void handleRedirect();
	void downloadRepos();
	void updateRepos();
	void showREADME();
	void downloadREADME(int, int);
	void updateRepoData();
	void parsePluginType();
private:
	typedef struct repo
	{
		QString name;
		QString description;
		QString release;
	};
	void downloadNextPlugin();
	void getRepoData();
	void downloadNext();
	bool checkSHA1(QByteArray);

  Ui::DownloaderWidget *ui;
	QNetworkAccessManager *oNetworkAccessManager;
	QNetworkReply *reply;
  /** Jsoncpp reader to read JSON results */
  Json::Reader *read;
  /** Holds a node of JSON results */
  Json::Value root;
	/** Used to parse JSON results */
	QVariantMap m_jsonResult;
	QList<repo> repoData;
	QString filePath;
	QMutex tableLock;
	int currentTableIndex = 0;
	int numRepos;
	int numProcessed;
	QList<QString> repos;
	QList<QString> downloadList;
	QList<QString> pluginList;
	QList<QString> pluginTypes;
	QList<QString> nameList;
	bool ready;
};

}
}
#endif // AVOGADRO_DOWNLOADERWIDGET_H
