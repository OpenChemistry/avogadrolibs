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

#include <nlohmann/json.hpp>

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
    // Build one line per feature to clearly map displayed glyphs to labels.
    QStringList labels;
    for (const QString& ft : e.featureTypes) {
      const QString label = featureTypeLabel(ft);
      const QString glyph = featureGlyph(ft);
      if (!glyph.isEmpty())
        labels.append(QStringLiteral("%1\t%2").arg(glyph, label));
      else
        labels.append(label);
    }
    return labels.join(QLatin1Char('\n'));
  }

  // Red foreground for version-incompatible packages
  if (role == Qt::ForegroundRole && !versionCompatible(e))
    return QColor(Qt::red);

  if (role == Qt::DisplayRole) {
    switch (index.column()) {
      case StatusColumn:
        return {};
      case NameColumn:
        return displayName(e.name);
      case AvailableColumn:
        if (e.status == PackageStatus::LocalOnly)
          return e.installedVersion;
        return e.hasRelease ? e.onlineVersion : e.updatedAt;
      case FeaturesColumn: {
        if (e.featureTypes.isEmpty())
          return {};
        QStringList glyphs;
        for (const QString& ft : e.featureTypes) {
          const QString g = featureGlyph(ft);
          if (!g.isEmpty())
            glyphs.append(g);
        }
        return glyphs.join(QLatin1Char(' '));
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
  if (orientation != Qt::Horizontal)
    return {};

  if (role == Qt::ToolTipRole && section == FeaturesColumn) {
    const QStringList featureTypes = { QStringLiteral("electrostatic-models"),
                                       QStringLiteral("energy-models"),
                                       QStringLiteral("file-formats"),
                                       QStringLiteral("input-generators"),
                                       QStringLiteral("menu-commands") };
    QStringList lines;
    for (const QString& featureType : featureTypes) {
      const QString label = featureTypeLabel(featureType);
      const QString glyph = featureGlyph(featureType);
      if (!glyph.isEmpty())
        lines.append(QStringLiteral("%1\t%2").arg(glyph, label));
      else
        lines.append(label);
    }
    return tr("Feature icons:\n%1").arg(lines.join(QLatin1Char('\n')));
  }

  if (role != Qt::DisplayRole)
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

  json root =
    json::parse(jsonBytes.data(), nullptr, /*allow_exceptions=*/false);
  if (root.is_discarded() || !root.is_array()) {
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
    get("version", e.onlineVersion);
    get("minimum-avogadro-version", e.minimumAvogadroVersion);

    // git.repo is a clone URL; strip .git suffix for a web base URL
    auto gitIt = item.find("git");
    if (gitIt != item.end() && gitIt->is_object()) {
      auto repoIt = gitIt->find("repo");
      if (repoIt != gitIt->end() && repoIt->is_string()) {
        e.baseUrl = QString::fromStdString(repoIt->get<std::string>());
        if (e.baseUrl.endsWith(QStringLiteral(".git")))
          e.baseUrl.chop(4);
      }
    }

    // src may be either:
    // - object: {url, sha256}
    // - array:  [{url, sha256}, ...] (legacy)
    // Use the first available url.
    auto srcIt = item.find("src");
    const auto setSrcUrl = [&](const json& srcObj) {
      auto urlIt = srcObj.find("url");
      if (urlIt != srcObj.end() && urlIt->is_string()) {
        e.zipballUrl = QString::fromStdString(urlIt->get<std::string>());
        e.hasRelease = true;
      }
    };
    if (srcIt != item.end()) {
      if (srcIt->is_object()) {
        setSrcUrl(*srcIt);
      } else if (srcIt->is_array() && !srcIt->empty() &&
                 srcIt->front().is_object()) {
        setSrcUrl(srcIt->front());
      }
    }

    // readme-url is a GitHub blob page URL; convert to raw for fetching
    get("readme-url", e.readmeUrl);
    if (!e.readmeUrl.isEmpty()) {
      e.readmeUrl.replace(QStringLiteral("github.com"),
                          QStringLiteral("raw.githubusercontent.com"));
      e.readmeUrl.replace(QStringLiteral("/blob/"), QStringLiteral("/"));
    }

    auto featIt = item.find("feature-types");
    if (featIt != item.end() && featIt->is_array()) {
      for (const auto& f : *featIt) {
        if (f.is_string())
          e.featureTypes.append(QString::fromStdString(f.get<std::string>()));
      }
    }

    auto dateIt = item.find("last-update");
    if (dateIt != item.end() && dateIt->is_string()) {
      QString raw = QString::fromStdString(dateIt->get<std::string>());
      e.onlineUpdatedAt = QDateTime::fromString(raw, Qt::ISODate);
      e.updatedAt =
        QLocale().toString(e.onlineUpdatedAt.date(), QLocale::ShortFormat);
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
  if (!m_entries.isEmpty())
    emit dataChanged(index(0, StatusColumn),
                     index(rowCount() - 1, StatusColumn),
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

// Common Avogadro prefixes, longest first to avoid partial matches.
static const char* s_avoPrefixes[] = { "avogadro-", "avogadro_", "avogadro",
                                       "avo-",      "avo_",      "avo" };

/// Return the length of the first matching prefix, or 0 if none match.
static int avoPrefixLength(const QString& name, Qt::CaseSensitivity cs)
{
  for (const char* prefix : s_avoPrefixes) {
    const QLatin1String p(prefix);
    if (name.startsWith(p, cs))
      return p.size();
  }
  return 0;
}

QString PackageModel::normalizePackageName(const QString& name)
{
  QString n = name.toLower();
  int len = avoPrefixLength(n, Qt::CaseSensitive);
  if (len > 0)
    n = n.mid(len);
  // Fold hyphens and underscores so "my-plugin" == "my_plugin".
  n.replace('-', '_');
  return n;
}

QString PackageModel::displayName(const QString& name)
{
  int len = avoPrefixLength(name, Qt::CaseInsensitive);
  if (len > 0)
    return name.mid(len);
  return name;
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

QString PackageModel::featureGlyph(const QString& featureType)
{
  if (featureType == QLatin1String("electrostatic-models"))
    return QStringLiteral("\u26A1"); // ⚡ LIGHTNING BOLT
  if (featureType == QLatin1String("energy-models"))
    return QStringLiteral("E");
  if (featureType == QLatin1String("file-formats"))
    return QStringLiteral("\U0001F4C4"); // 📄 PAGE FACING UP
  if (featureType == QLatin1String("input-generators"))
    return QStringLiteral("\u269B"); // ⚛ ATOM SYMBOL
  if (featureType == QLatin1String("menu-commands"))
    return QStringLiteral("\u2630"); // ☰ TRIGRAM / HAMBURGER MENU
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
