/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PACKAGEMODEL_H
#define AVOGADRO_QTPLUGINS_PACKAGEMODEL_H

#include <QtCore/QAbstractTableModel>
#include <QtCore/QDateTime>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QVariantMap>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Table model combining online catalog packages with locally installed
 * packages. Supports install, update, and remove workflows.
 */
class PackageModel : public QAbstractTableModel
{
  Q_OBJECT

public:
  /** Columns exposed by the model. */
  enum Column
  {
    StatusColumn = 0,
    NameColumn = 1,
    AvailableColumn = 2,
    FeaturesColumn = 3,
    DescriptionColumn = 4,
    /**
     * Keywords and authors, hidden in the view but still matched by the
     * search filter, which scans every column of the source model.
     */
    KeywordsColumn = 5,
    ColumnCount = 6
  };

  /** Installation / update status for a package. */
  enum class PackageStatus
  {
    NotInstalled, ///< In catalog, not installed locally
    Installed,    ///< Installed, version matches online (or no online version)
    UpdateAvailable, ///< Installed, newer version available online
    LocalOnly        ///< Installed, not found in online catalog
  };

  /** Combined representation of one package (online + installed state). */
  struct PackageEntry
  {
    // Online catalog fields
    QString name;
    QString description;
    QString onlineVersion; ///< "release_version" from JSON, "" if no release
    QString updatedAt;     ///< Formatted date, fallback when no release version
    QDateTime onlineUpdatedAt; ///< Raw ISO timestamp for update heuristics.
    QString zipballUrl;
    QString baseUrl; ///< GitHub repo URL — primary match key
    QString readmeUrl;
    bool hasRelease = false;
    QString type;
    QString
      minimumAvogadroVersion; ///< from "minimum-avogadro-version", "" if none
    QStringList featureTypes; ///< from "feature-types" array
    QStringList keywords;     ///< from "keywords" ([project.keywords])
    QStringList authors;      ///< from "authors" ([project.authors] names)
    QString bugTrackerUrl;    ///< issue tracker, "" if none could be resolved
    int recentDownloads = -1; ///< downloads in the stats window, -1 = unknown

    // Installed state (populated from PackageManager)
    QString installedVersion; ///< from pyproject.toml [project.version]
    QString packageKey;       ///< Registered package key used by PackageManager
    QString installedDir;     ///< absolute path on disk, "" if not installed
    bool isSymlink = false;   ///< true if installedDir is a symlink

    // UI state
    PackageStatus status = PackageStatus::NotInstalled;
  };

  explicit PackageModel(QObject* parent = nullptr);
  ~PackageModel() override = default;

  // QAbstractTableModel interface
  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index,
                int role = Qt::DisplayRole) const override;
  bool setData(const QModelIndex& index, const QVariant& value,
               int role = Qt::EditRole) override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role = Qt::DisplayRole) const override;
  Qt::ItemFlags flags(const QModelIndex& index) const override;

  /**
   * Load the online package catalog from JSON bytes (plugins.json).
   * Resets the model; call mergeInstalledPackages() afterward.
   */
  void loadOnlineCatalog(const QByteArray& jsonBytes);

  /**
   * Overlay installed-package data from PackageManager onto the existing
   * entries. Also appends LocalOnly entries for installed packages not found
   * in the online catalog.
   */
  void mergeInstalledPackages();

  /**
   * Overlay per-plugin download counts from the download counter's @c /stats
   * response onto the existing entries. Entries the counter knows nothing
   * about keep a count of -1 (unknown) rather than being reported as zero.
   */
  void loadDownloadStats(const QByteArray& jsonBytes);

  /**
   * Length in days of the window the loaded download counts cover, or 0 if no
   * statistics have been loaded.
   */
  int downloadWindowDays() const { return m_downloadWindowDays; }

  // Accessors
  int entryCount() const { return static_cast<int>(m_entries.size()); }
  const PackageEntry& entry(int row) const { return m_entries[row]; }
  PackageEntry& entry(int row) { return m_entries[row]; }

  /** README URL for the given source-model row. */
  QString readmeUrl(int row) const;

  /**
   * Returns true when the running Avogadro version satisfies the entry's
   * minimum-avogadro-version requirement (or when no minimum is specified).
   */
  static bool versionCompatible(const PackageEntry& e);

  /** Short translated label for a feature type string. */
  static QString featureTypeLabel(const QString& featureType);

private:
  /**
   * Strip common Avogadro prefixes and normalise separators so that e.g.
   * "avogenerators" and "generators" map to the same key.
   */
  static QString normalizePackageName(const QString& name);

  /** Strip common Avogadro prefixes for display, preserving original case. */
  static QString displayName(const QString& name);

  /** Compute (or recompute) the status of one entry. */
  static PackageStatus computeStatus(const PackageEntry& e);
  static bool isOnlineNewerByDate(const PackageEntry& e);
  static bool parseSemVer(const QString& version, int& major, int& minor,
                          int& patch);
  static int compareSemVer(const QString& lhs, const QString& rhs, bool& ok);

  /** Emoji glyph for the given status. */
  static QString statusIcon(PackageStatus status);

  /** Unicode glyph for the given feature type string. */
  static QString featureGlyph(const QString& featureType);

  /**
   * Pick the issue tracker out of a [project.urls] table, falling back to the
   * GitHub issue form derived from @p repoUrl. Returns "" when neither is
   * available.
   */
  static QString issueTrackerUrl(const QVariantMap& urls,
                                 const QString& repoUrl);

  /**
   * Fill the authors, keywords and bug-tracker fields of @p entry from the
   * pyproject.toml of an installed package. Only fields still empty are
   * touched, so online catalog data always wins.
   */
  static void readLocalProjectMetadata(PackageEntry& entry);

  QList<PackageEntry> m_entries;
  int m_downloadWindowDays = 0;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PACKAGEMODEL_H
