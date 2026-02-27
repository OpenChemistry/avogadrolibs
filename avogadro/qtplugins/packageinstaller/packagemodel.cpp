/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packagemodel.h"

#include <avogadro/core/version.h>
#include <avogadro/qtgui/packagemanager.h>

#include <QtCore/QDateTime>
#include <QtCore/QFileInfo>
#include <QtCore/QHash>
#include <QtCore/QLocale>
#include <QtCore/QRegularExpression>
#include <QtCore/QStringList>
#include <QtGui/QColor>
#include <QtGui/QIcon>
#include <QtGui/QPainter>
#include <QtGui/QPixmap>

#include <nlohmann/json.hpp>

#include <cstring>

using json = nlohmann::json;

namespace Avogadro::QtPlugins {

PackageModel::PackageModel(QObject* parent) : QAbstractTableModel(parent) {}

// ---------------------------------------------------------------------------
// QAbstractTableModel interface
// ---------------------------------------------------------------------------

int PackageModel::rowCount(const QModelIndex& parent) const
{
  return parent.isValid() ? 0 : static_cast<int>(m_entries.size());
}

int PackageModel::columnCount(const QModelIndex& parent) const
{
  return parent.isValid() ? 0 : ColumnCount;
}

QVariant PackageModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid() || index.row() >= m_entries.size())
    return {};

  const PackageEntry& e = m_entries[index.row()];

  if (role == Qt::CheckStateRole && index.column() == StatusColumn)
    return e.checked ? Qt::Checked : Qt::Unchecked;

  if (role == Qt::DecorationRole && index.column() == StatusColumn)
    return statusIcon(e.status);

  if (role == Qt::DecorationRole && index.column() == FeaturesColumn) {
    if (!e.featureTypes.isEmpty())
      return featureIcon(e.featureTypes.first());
    return {};
  }

  if (role == Qt::ToolTipRole && index.column() == StatusColumn) {
    switch (e.status) {
      case PackageStatus::NotInstalled:
        return tr("Not installed");
      case PackageStatus::Installed:
        return tr("Installed (up to date)");
      case PackageStatus::UpdateAvailable:
        return tr("Update available");
      case PackageStatus::LocalOnly:
        return tr("Installed locally (not in online catalog)");
    }
  }

  if (role == Qt::ToolTipRole && index.column() == NameColumn) {
    if (!versionCompatible(e))
      return tr("Requires Avogadro %1 or later (running %2)")
        .arg(e.minimumAvogadroVersion,
             QString::fromLatin1(Avogadro::version()));
    return {};
  }

  if (role == Qt::ToolTipRole && index.column() == FeaturesColumn) {
    if (e.featureTypes.isEmpty())
      return {};
    // Build a human-readable list
    QStringList labels;
    for (const QString& ft : e.featureTypes)
      labels.append(featureTypeLabel(ft));
    return labels.join(QStringLiteral(", "));
  }

  // Red foreground for version-incompatible packages
  if (role == Qt::ForegroundRole && !versionCompatible(e))
    return QColor(Qt::red);

  if (role == Qt::DisplayRole) {
    switch (index.column()) {
      case StatusColumn:
        return {};
      case NameColumn:
        return e.name;
      case AvailableColumn:
        if (e.status == PackageStatus::LocalOnly)
          return e.installedVersion;
        return e.hasRelease ? e.onlineVersion : e.updatedAt;
      case FeaturesColumn: {
        if (e.featureTypes.isEmpty())
          return {};
        QStringList labels;
        for (const QString& ft : e.featureTypes)
          labels.append(featureTypeLabel(ft));
        return labels.join(QStringLiteral(", "));
      }
      case DescriptionColumn:
        return e.description;
      default:
        return {};
    }
  }

  return {};
}

bool PackageModel::setData(const QModelIndex& index, const QVariant& value,
                           int role)
{
  if (!index.isValid() || index.row() >= m_entries.size())
    return false;

  if (role == Qt::CheckStateRole && index.column() == StatusColumn) {
    m_entries[index.row()].checked = (value.toInt() == Qt::Checked);
    emit dataChanged(index, index, { Qt::CheckStateRole });
    return true;
  }
  return false;
}

QVariant PackageModel::headerData(int section, Qt::Orientation orientation,
                                  int role) const
{
  if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
    return {};
  switch (section) {
    case StatusColumn:
      return tr("Status");
    case NameColumn:
      return tr("Name");
    case AvailableColumn:
      return tr("Version");
    case FeaturesColumn:
      return tr("Features");
    case DescriptionColumn:
      return tr("Description");
    default:
      return {};
  }
}

Qt::ItemFlags PackageModel::flags(const QModelIndex& index) const
{
  if (!index.isValid())
    return Qt::NoItemFlags;

  Qt::ItemFlags f = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
  if (index.column() == StatusColumn)
    f |= Qt::ItemIsUserCheckable;
  return f;
}

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

void PackageModel::loadOnlineCatalog(const QByteArray& jsonBytes)
{
  beginResetModel();
  m_entries.clear();

  if (!json::accept(jsonBytes.data())) {
    endResetModel();
    return;
  }

  json root = json::parse(jsonBytes.data());
  if (!root.is_array()) {
    endResetModel();
    return;
  }

  for (const auto& item : root) {
    if (!item.is_object())
      continue;

    PackageEntry e;
    auto get = [&](const char* key, QString& out) {
      auto it = item.find(key);
      if (it != item.end() && it->is_string())
        out = QString::fromStdString(it->get<std::string>());
    };

    get("name", e.name);
    get("description", e.description);
    get("release_version", e.onlineVersion);
    get("type", e.type);
    get("zipball_url", e.zipballUrl);
    get("repo_url", e.baseUrl);
    get("readme_url", e.readmeUrl);
    get("minimum-avogadro-version", e.minimumAvogadroVersion);

    auto featIt = item.find("feature-types");
    if (featIt != item.end() && featIt->is_array()) {
      for (const auto& f : *featIt) {
        if (f.is_string())
          e.featureTypes.append(QString::fromStdString(f.get<std::string>()));
      }
    }

    auto hasIt = item.find("has_release");
    if (hasIt != item.end() && hasIt->is_boolean())
      e.hasRelease = hasIt->get<bool>();

    auto dateIt = item.find("updated_at");
    if (dateIt != item.end() && dateIt->is_string()) {
      QString raw = QString::fromStdString(dateIt->get<std::string>());
      e.onlineUpdatedAt = QDateTime::fromString(raw, Qt::ISODate);
      e.updatedAt =
        QLocale().toString(e.onlineUpdatedAt.date(), QLocale::ShortFormat);
    }

    // Derive readmeUrl from baseUrl if not supplied
    if (e.readmeUrl.isEmpty() && !e.baseUrl.isEmpty()) {
      QStringList parts = e.baseUrl.split('/');
      parts.append(QStringLiteral("readme"));
      e.readmeUrl = parts.join('/');
    }

    e.status = PackageStatus::NotInstalled;
    if (!e.name.isEmpty())
      m_entries.append(e);
  }

  endResetModel();
}

void PackageModel::mergeInstalledPackages()
{
  // Use a full model reset because we may be adding or removing LocalOnly rows.
  beginResetModel();

  // First, clear any previously set installed state from catalog entries
  for (PackageEntry& e : m_entries) {
    if (e.status != PackageStatus::LocalOnly) {
      e.installedVersion.clear();
      e.packageKey.clear();
      e.installedDir.clear();
      e.isSymlink = false;
      e.status = PackageStatus::NotInstalled;
      e.checked = false;
    }
  }
  // Remove any previously added LocalOnly entries
  m_entries.removeIf(
    [](const PackageEntry& e) { return e.status == PackageStatus::LocalOnly; });

  QtGui::PackageManager* pm = QtGui::PackageManager::instance();
  const QStringList installed = pm->registeredPackages();

  // Build a single lookup map keyed on the normalised package name.
  // Each catalog entry is indexed by its name and its repo-slug (last segment
  // of baseUrl), both normalised, so "avogenerators" == "generators", etc.
  QHash<QString, int> byNormName;
  for (int i = 0; i < m_entries.size(); ++i) {
    const PackageEntry& e = m_entries[i];
    if (!e.name.isEmpty())
      byNormName.insert(normalizePackageName(e.name), i);
    if (!e.baseUrl.isEmpty()) {
      const QString slug = e.baseUrl.split('/').last();
      if (!slug.isEmpty())
        byNormName.insert(normalizePackageName(slug), i);
    }
  }

  for (const QString& pkgName : installed) {
    QtGui::PackageManager::PackageInfo info = pm->packageInfo(pkgName);

    // Determine if the installed directory is a symlink
    bool symlink = QFileInfo(info.directory).isSymLink();

    // Try to find a matching entry in the online catalog using normalised
    // names.
    int idx = byNormName.value(normalizePackageName(pkgName), -1);

    // Also try the directory base name (handles cases where pkgName != repo
    // name)
    if (idx == -1) {
      const QString dirBase = QFileInfo(info.directory).fileName();
      idx = byNormName.value(normalizePackageName(dirBase), -1);
    }

    if (idx != -1) {
      PackageEntry& e = m_entries[idx];
      e.installedVersion = info.version;
      e.packageKey = pkgName;
      e.installedDir = info.directory;
      e.isSymlink = symlink;
      e.status = computeStatus(e);
    } else {
      // LocalOnly — installed but not in the online catalog
      PackageEntry e;
      e.name = pkgName;
      e.description = info.description;
      e.installedVersion = info.version;
      e.packageKey = pkgName;
      e.installedDir = info.directory;
      e.isSymlink = symlink;
      e.status = PackageStatus::LocalOnly;
      m_entries.append(e);
    }
  }

  // Pre-check any UpdateAvailable entries
  for (PackageEntry& e : m_entries) {
    if (e.status == PackageStatus::UpdateAvailable)
      e.checked = true;
  }

  endResetModel();
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

QString PackageModel::readmeUrl(int row) const
{
  if (row < 0 || row >= m_entries.size())
    return {};
  return m_entries[row].readmeUrl;
}

QList<int> PackageModel::checkedRows() const
{
  QList<int> result;
  for (int i = 0; i < m_entries.size(); ++i) {
    if (m_entries[i].checked)
      result.append(i);
  }
  return result;
}

void PackageModel::setChecked(int row, bool checked)
{
  if (row < 0 || row >= m_entries.size())
    return;
  m_entries[row].checked = checked;
  QModelIndex idx = index(row, StatusColumn);
  emit dataChanged(idx, idx, { Qt::CheckStateRole });
}

void PackageModel::uncheckAll()
{
  for (PackageEntry& e : m_entries)
    e.checked = false;
  emit dataChanged(index(0, StatusColumn), index(rowCount() - 1, StatusColumn),
                   { Qt::CheckStateRole });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

PackageModel::PackageStatus PackageModel::computeStatus(const PackageEntry& e)
{
  if (e.installedDir.isEmpty())
    return PackageStatus::NotInstalled;
  if (e.status == PackageStatus::LocalOnly)
    return PackageStatus::LocalOnly;

  // Prefer semantic version ordering when both versions parse cleanly.
  if (!e.installedVersion.isEmpty() && !e.onlineVersion.isEmpty()) {
    bool semverComparable = false;
    const int cmp =
      compareSemVer(e.installedVersion, e.onlineVersion, semverComparable);
    if (semverComparable)
      return cmp < 0 ? PackageStatus::UpdateAvailable
                     : PackageStatus::Installed;
  }

  // Fallback: if the online catalog update timestamp is newer than the local
  // package metadata file, treat it as an available update.
  if (isOnlineNewerByDate(e))
    return PackageStatus::UpdateAvailable;

  return PackageStatus::Installed;
}

bool PackageModel::isOnlineNewerByDate(const PackageEntry& e)
{
  if (!e.onlineUpdatedAt.isValid() || e.installedDir.isEmpty())
    return false;

  QDateTime localModified;
  const QFileInfo pyproject(e.installedDir + QStringLiteral("/pyproject.toml"));
  if (pyproject.exists())
    localModified = pyproject.lastModified();
  if (!localModified.isValid())
    localModified = QFileInfo(e.installedDir).lastModified();
  if (!localModified.isValid())
    return false;

  return e.onlineUpdatedAt > localModified;
}

bool PackageModel::parseSemVer(const QString& version, int& major, int& minor,
                               int& patch)
{
  static const QRegularExpression re(
    QStringLiteral("^v?(\\d+)\\.(\\d+)(?:\\.(\\d+))?(?:[-+].*)?$"));
  const QRegularExpressionMatch match = re.match(version.trimmed());
  if (!match.hasMatch())
    return false;

  bool okMajor = false;
  bool okMinor = false;
  bool okPatch = true;
  major = match.captured(1).toInt(&okMajor);
  minor = match.captured(2).toInt(&okMinor);
  patch = match.captured(3).isEmpty() ? 0 : match.captured(3).toInt(&okPatch);
  return okMajor && okMinor && okPatch;
}

int PackageModel::compareSemVer(const QString& lhs, const QString& rhs,
                                bool& ok)
{
  int lhsMajor = 0;
  int lhsMinor = 0;
  int lhsPatch = 0;
  int rhsMajor = 0;
  int rhsMinor = 0;
  int rhsPatch = 0;

  const bool lhsValid = parseSemVer(lhs, lhsMajor, lhsMinor, lhsPatch);
  const bool rhsValid = parseSemVer(rhs, rhsMajor, rhsMinor, rhsPatch);
  ok = lhsValid && rhsValid;
  if (!ok)
    return 0;

  if (lhsMajor != rhsMajor)
    return lhsMajor < rhsMajor ? -1 : 1;
  if (lhsMinor != rhsMinor)
    return lhsMinor < rhsMinor ? -1 : 1;
  if (lhsPatch != rhsPatch)
    return lhsPatch < rhsPatch ? -1 : 1;
  return 0;
}

QIcon PackageModel::statusIcon(PackageStatus status)
{
  switch (status) {
    case PackageStatus::NotInstalled:
      return QIcon::fromTheme(QStringLiteral("package-available"),
                              QIcon::fromTheme(QStringLiteral("list-add")));
    case PackageStatus::Installed:
      return QIcon::fromTheme(
        QStringLiteral("package-installed-updated"),
        QIcon::fromTheme(QStringLiteral("dialog-ok-apply")));
    case PackageStatus::UpdateAvailable:
      return QIcon::fromTheme(
        QStringLiteral("package-upgrade"),
        QIcon::fromTheme(QStringLiteral("software-update-available")));
    case PackageStatus::LocalOnly:
      return QIcon::fromTheme(QStringLiteral("folder-development"),
                              QIcon::fromTheme(QStringLiteral("folder")));
  }
  return {};
}

QString PackageModel::normalizePackageName(const QString& name)
{
  QString n = name.toLower();
  // Strip common Avogadro prefixes, longest first to avoid partial matches.
  static const char* prefixes[] = { "avogadro-", "avogadro_", "avogadro",
                                    "avo-",      "avo_",      "avo" };
  for (const char* prefix : prefixes) {
    if (n.startsWith(QLatin1String(prefix))) {
      n = n.mid(static_cast<int>(strlen(prefix)));
      break;
    }
  }
  // Fold hyphens and underscores so "my-plugin" == "my_plugin".
  n.replace('-', '_');
  return n;
}

QString PackageModel::featureTypeLabel(const QString& featureType)
{
  if (featureType == QLatin1String("electrostatic-models"))
    return tr("Electrostatic");
  if (featureType == QLatin1String("energy-models"))
    return tr("Energy");
  if (featureType == QLatin1String("file-formats"))
    return tr("File Formats");
  if (featureType == QLatin1String("input-generators"))
    return tr("Input Gen.");
  if (featureType == QLatin1String("menu-commands"))
    return tr("Commands");
  // Unknown feature type — return as-is (capitalised for readability)
  if (featureType.isEmpty())
    return {};
  QString label = featureType;
  label[0] = label[0].toUpper();
  return label.replace('-', ' ');
}

static QIcon glyphIcon(const QString& glyph, bool bold = false)
{
  const int sz = 22;
  QPixmap pm(sz, sz);
  pm.fill(Qt::transparent);
  QPainter p(&pm);
  QFont f = p.font();
  f.setPixelSize(sz - 2);
  f.setBold(bold);
  p.setFont(f);
  p.drawText(QRect(0, 0, sz, sz), Qt::AlignCenter, glyph);
  return QIcon(pm);
}

QIcon PackageModel::featureIcon(const QString& featureType)
{
  // U+26A1 LIGHTNING BOLT
  if (featureType == QLatin1String("electrostatic-models"))
    return glyphIcon(QStringLiteral("\u26A1"));
  // Bold capital E for energy
  if (featureType == QLatin1String("energy-models"))
    return glyphIcon(QStringLiteral("E"), true);
  // U+1F4C4 PAGE FACING UP
  if (featureType == QLatin1String("file-formats"))
    return glyphIcon(QStringLiteral("\U0001F4C4"));
  // U+269B ATOM SYMBOL
  if (featureType == QLatin1String("input-generators"))
    return glyphIcon(QStringLiteral("\u269B"));
  if (featureType == QLatin1String("menu-commands"))
    return QIcon::fromTheme(
      QStringLiteral("application-menu"),
      QIcon::fromTheme(QStringLiteral("preferences-other")));
  return {};
}

bool PackageModel::versionCompatible(const PackageEntry& e)
{
  if (e.minimumAvogadroVersion.isEmpty())
    return true;
  bool ok = false;
  const int cmp = compareSemVer(QString::fromLatin1(Avogadro::version()),
                                e.minimumAvogadroVersion, ok);
  // If either string didn't parse as semver, assume compatible.
  return !ok || cmp >= 0;
}

} // namespace Avogadro::QtPlugins
