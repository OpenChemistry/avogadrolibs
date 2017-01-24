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
	void showREADME();
	void downloadREADME(int, int);
	void updateRepoData();
	void getCheckedRepos();
	void handleRedirect();
	void unzipPlugin();
private:
	typedef struct repo
	{
		QString name;
		QString description;
		QString release_version;
		QString updated_at;
		QString zipball_url;
		QString readme_url;
		bool has_release;
	};

	typedef struct downloadEntry
	{
		QString url;
		QString name;
		QString type;
	};
	void downloadNextPlugin();
	void getRepoData();
	void downloadNext();
	bool checkSHA1(QByteArray);
	struct repo* repoList;
  Ui::DownloaderWidget *ui;
	QNetworkAccessManager *oNetworkAccessManager;
	QNetworkReply *reply;
  /** Jsoncpp reader to read JSON results */
  Json::Reader *read;
  /** Holds a node of JSON results */
  Json::Value root;
	/** Used to parse JSON results */
	QVariantMap m_jsonResult;


	QString filePath;

	QList<downloadEntry> downloadList;
	int numRepos;

};

}
}
#endif // AVOGADRO_DOWNLOADERWIDGET_H
