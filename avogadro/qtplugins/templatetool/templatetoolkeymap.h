/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_TEMPLATETOOLKEYMAP_H
#define AVOGADRO_QTPLUGINS_TEMPLATETOOLKEYMAP_H

#include <QtCore/QString>

#include <map>

namespace Avogadro {
namespace QtPlugins {

// Lookup table mapping key buffer strings to fragment CJSON paths
// for the ligands tab (currentTab == 1)
inline const std::map<QString, QString>& ligandKeyMap()
{
  static const std::map<QString, QString> keyMap = {
    // Monodentate
    { "a", "1-aqua" },
    { "co", "1-carbonyl" },
    { "cn", "1-cyano" },
    { "n", "1-ammine" },
    { "o", "1-aqua" },
    { "p", "1-phosphine" },
    { "pyr", "1-pyridyl" },
    { "s", "1-thiol" },
    // Bidentate
    { "acac", "2-acetylacetonate" },
    { "bpy", "2-bipyridine" },
    { "dmg", "dimethylglyoxime" },
    { "dmpe", "dppe-1,2-bis(dimethylphosphino)ethane" },
    { "dppe", "dppe-1,2-bis(diphenylphosphino)ethane" },
    { "en", "2-ethylenediamine" },
    { "ox", "oxalate" },
    { "phen", "phenanthroline" },
    // Tridentate
    { "tpy", "3-terpyridine" },
    // Tetradentate
    { "pc", "4-phthalocyanine" },
    { "por", "4-porphin" },
    { "sal", "4-salen" },
    // Hexadentate
    { "edta", "6-edta" },
    // Haptic
    { "e2", "eta2-ethylene" },
    { "e3", "eta3-alyl" },
    { "e4", "eta4-cyclo-octadiene" },
    { "e5", "eta5-cyclopentyl" },
    { "e6", "eta6-benzene" },
  };
  return keyMap;
}

// Lookup table mapping key buffer strings to fragment CJSON paths
// for the functional groups tab (currentTab == 2)
inline const std::map<QString, QString>& groupKeyMap()
{
  static const std::map<QString, QString> keyMap = {
    // Aromatic
    { "a", "phenyl" },
    // Alkyl chains (n-alkyl)
    { "c1", "1-methyl" },
    { "c2", "ethyl" },
    { "c3", "propyl" },
    { "c4", "butyl" },
    { "c5", "pentyl" },
    { "c6", "hexyl" },
    { "c7", "heptyl" },
    { "c8", "octyl" },
    { "c9", "nonyl" },
    { "c0", "decyl" },
    { "C3", "cyclopropane" },
    { "C4", "cyclobutane" },
    { "C5", "cyclopentane" },
    { "C6", "cyclohexane" },
    { "C7", "cycloheptane" },
    { "C8", "cyclooctane" },
    { "C9", "cyclononane" },
    { "C0", "cyclodecane" },
    // Branched alkyl
    { "I", "1-isopropyl" },
    { "K", "1-t-butyl" },
    // others
    { "boc", "boc-tert-butyloxycarbonyl" },
    { "C", "carboxylate" },
    { "cbz", "cbz-benzyloxycarbonyl" },
    { "cm", "t-butyl" },
    { "cn", "nitrile" },
    { "co", "aldehyde" },
    { "co2", "carboxylate" },
    { "cs", "thial" },
    { "cso", "carbothioic_O-acid" },
    { "ep", "epoxide" },
    { "F", "trifluoromethyl" },
    { "fmoc", "fmoc-fluorenylmethoxycarbonyl" },
    { "H", "cbz-benzyloxycarbonyl" },
    { "im", "imine" },
    { "L", "trichloromethyl" },
    { "mes", "mesityl" },
    { "ms", "mesyl" },
    { "N", "nitro" },
    { "nc", "isocyano" },
    { "ncs", "isothiocyanate" },
    { "nn", "azo" },
    { "no", "nitroso" },
    { "no2", "nitro" },
    { "n3", "azide" },
    { "O", "peroxide" },
    { "om", "methoxy" },
    { "ono", "nitrite" },
    { "oo", "peroxide" },
    { "otf", "triflate" },
    { "P", "phosphate" },
    { "po3", "phosphate" },
    { "Q", "fmoc-fluorenylmethoxycarbonyl" },
    { "R", "tribromomethyl" },
    { "S", "sulfonate" },
    { "scn", "thiocyanate" },
    { "so3", "sulfonate" },
    { "ss", "disulfide" },
    { "T", "troc-2,2,2-trichloroethoxycarbonyl" },
    { "tf", "triflyl" },
    { "tr", "trityl" },
    { "ts", "tosyl" },
    { "V", "ethylene" },
    { "W", "ethyne" },
    { "Y", "boc-tert-butyloxycarbonyl" },
  };
  return keyMap;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_TEMPLATETOOLKEYMAP_H
