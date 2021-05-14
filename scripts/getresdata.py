#!/usr/bin/env python

from __future__ import print_function

import os
import sys

import requests

from openbabel import pybel
from openbabel import openbabel as ob

# TODO: process Open Babel resdata.txt
#   if we can find certain non-standard residues
mdLigands = [
"ASH", # Neutral ASP
"CYX", # SS-bonded CYS
"CYM", # Negative CYS
"GLH", # Neutral GLU
"HIP", # Positive HIS
"HID", # Neutral HIS, proton HD1 present
"HIE", # Neutral HIS, proton HE2 present
"LYN", # Neutral LYS
"TYM", # Negative TYR
]

# the location of the LigandExpo list by count
ligandURL = "http://ligand-expo.rcsb.org/dictionaries/cc-counts.tdd"
# URL for the ideal geometry
# e.g http://ligand-expo.rcsb.org/reports/H/HEM/HEM_ideal.pdb
sdfTemplate = "http://ligand-expo.rcsb.org/reports/{}/{}/{}_ideal.sdf"
# URL for the ideal geometry (PDB)
pdbTemplate = "http://ligand-expo.rcsb.org/reports/{}/{}/{}_ideal.pdb"
# save ligands with at least this # of occurrences

ligandThresh = 500

# default ligand list
ligands = [
# amino acids
"ALA", "CYS", "ASP", "GLU", "PHE", "GLY", "HIS", "ILE", "LYS", "LEU",
"MET", "ASN", "PRO", "GLN", "ARG", "SER", "THR", "VAL", "TRP", "TYR",
# DNA nucleic
"DA", "DC", "DG", "DT", "DI",
# RNA nucleic
"A", "C", "G", "U", "I",
# misc
"HEM", "HOH"
]

# okay, we build up the list of ligands to fetch
r = requests.get(ligandURL, stream=True)
for line in r.iter_lines(decode_unicode=True):
    if 'count' in str(line):
        continue # skip first line

    name, count = line.split()
    if (int(count) < ligandThresh):
        # too rare, we'll skip the rest of the list
        break
    if str(name) not in ligands:
        ligands.append(str(name))

print(
'''
#ifndef AVOGADRO_CORE_RESIDUE_DATA
#define AVOGADRO_CORE_RESIDUE_DATA

#include <map>
#include <string>
#include <vector>
namespace Avogadro {
namespace Core {

class ResidueData
{
private:
  std::string m_residueName;
  std::map<std::string, int> m_residueAtomNames;
  std::vector<std::pair<std::string, std::string>> m_residueSingleBonds;
  std::vector<std::pair<std::string, std::string>> m_residueDoubleBonds;

public:
  ResidueData() {}
  ResidueData(std::string name,
              std::map<std::string, int> atomNames,
              std::vector<std::pair<std::string, std::string>> singleBonds,
              std::vector<std::pair<std::string, std::string>> doubleBonds)
  {
    m_residueName = name;
    m_residueAtomNames = atomNames;
    m_residueSingleBonds = singleBonds;
    m_residueDoubleBonds = doubleBonds;
  }

  ResidueData(const ResidueData& other)
  {
    m_residueName = other.m_residueName;
    m_residueAtomNames = other.m_residueAtomNames;
    m_residueSingleBonds = other.m_residueSingleBonds;
    m_residueDoubleBonds = other.m_residueDoubleBonds;
  }

  ResidueData& operator=(ResidueData other)
  {
    using std::swap;
    swap(*this, other);
    return *this;
  }

  std::map<std::string, int> residueAtoms() {
    return m_residueAtomNames;
  }

  std::vector<std::pair<std::string, std::string>> residueSingleBonds()
  {
    return m_residueSingleBonds;
  }

  std::vector<std::pair<std::string, std::string>> residueDoubleBonds()
  {
    return m_residueDoubleBonds;
  }
};
'''
)

final_ligands = []
for ligand in ligands:
    sdf = requests.get(sdfTemplate.format(ligand[0], ligand, ligand))
    # there *must* be a way to do this from a requests buffer, but this works
    with open('temp.sdf', 'wb') as handle:
        for block in sdf.iter_content(1024):
            handle.write(block)

    try:
      mol_sdf = next(pybel.readfile("sdf", 'temp.sdf'))
    except StopIteration:
      continue

    if len(mol_sdf.atoms) < 2:
        continue
    final_ligands.append(ligand)

    pdb = requests.get(pdbTemplate.format(ligand[0], ligand, ligand))
    with open('temp.pdb', 'wb') as handle:
        for block in pdb.iter_content(1024):
            handle.write(block)

    try:
      mol_pdb = next(pybel.readfile("pdb", 'temp.pdb'))
    except StopIteration:
      continue
    
    atom_map = {}
    for i in range(len(mol_sdf.atoms)):
        idx = mol_sdf.atoms[i].idx
        atom = mol_pdb.atoms[i].OBAtom
        res = atom.GetResidue()
        # build up a map between atom index and atom ID
        atom_map[idx] = res.GetAtomID(atom).strip().rstrip(), atom.GetAtomicNum()

    # go through bonds
    single_bonds = []
    double_bonds = []
    for bond in ob.OBMolBondIter(mol_sdf.OBMol):
        begin = bond.GetBeginAtomIdx()
        end = bond.GetEndAtomIdx()
        if bond.GetBondOrder() == 2:
            double_bonds.append((atom_map[begin][0], atom_map[end][0]))
        elif bond.GetBondOrder() == 1:
            single_bonds.append((atom_map[begin][0], atom_map[end][0]))

    # print out the residue data
    print('ResidueData %sData("%s",' % (ligand, ligand))
    print('// Atoms')
    print('{')
    for atom in list(atom_map.values())[:-1]:
        print('{ "%s", %d },' % (atom[0], atom[1]), end='')
    print('{"%s", %d }' % (atom[0], atom[1]))
    print('},')

    print('// Single Bonds')
    print('{')
    for bond in single_bonds[:-1]:
        print('{ "%s", "%s" },' % bond, end='')
    print('{ "%s", "%s" }' % single_bonds[-1])
    print('},')

    print('// Double Bonds')
    print('{')
    if len(double_bonds):
        for bond in double_bonds[:-1]:
            print('{ "%s", "%s" },' % bond, end='')
        print('{ "%s", "%s" }' % double_bonds[-1])

    print('}')

    print(');')

print('''std::map<std::string, ResidueData> residueDict = {''')

# print the list of ligands
for ligand in final_ligands:
    print('{ "%s", %sData },' % (ligand, ligand))

print('''
};
}
}

#endif
'''
)
os.remove("temp.sdf")
os.remove('temp.pdb')
