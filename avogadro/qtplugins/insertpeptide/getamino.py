#!/usr/bin/env python

import os

import requests

from openbabel import pybel
from openbabel import openbabel as ob

# URL for the ideal geometry (PDB)
pdbTemplate = "http://ligand-expo.rcsb.org/reports/{}/{}/{}_ideal.pdb"

# default ligand list
ligands = [
    # 20 common amino acids
    "ALA",
    "ARG",
    "ASP",
    "ASN",
    "CYS",
    "GLU",
    "GLN",
    "GLY",
    "HIS",
    "ILE",
    "LEU",
    "LYS",
    "MET",
    "PHE",
    "PRO",
    "SER",
    "THR",
    "TRP",
    "TYR",
    "VAL",
    # extra
    "PYL",
    "SEC",  # "MLY", "MLZ", "PYL",
    # caps
    "NME",
    "ACE",
    # misc
    "AIB",
]

for ligand in ligands:
    pdb = requests.get(pdbTemplate.format(ligand[0], ligand, ligand))
    with open("temp.pdb", "wb") as handle:
        for block in pdb.iter_content(1024):
            handle.write(block)

    try:
        mol_pdb = next(pybel.readfile("pdb", "temp.pdb"))
    except StopIteration:
        continue

    # fix up some atom orders
    if ligand == "ACE":
        # reorder the atoms to make sure C=O are 3, 4
        # unfortunately, OB won't let H be the first atom
        new_order = [3, 4, 1, 2, 5, 6, 7]
        mol_pdb.OBMol.RenumberAtoms(new_order)
    elif ligand == "SEC":
        new_order = [1, 2, 5, 6, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14]
        mol_pdb.OBMol.RenumberAtoms(new_order)
    elif ligand == "PYL":
        new_order = [18, 14, 15, 17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,36, 37, 38, 39]
        mol_pdb.OBMol.RenumberAtoms(new_order)
    # TODO: MLY, MLZ and others

    # remove the "extra" atoms (H2, OXT, HXT)
    removeAtoms = []
    for atom in mol_pdb.atoms:
      name = atom.OBAtom.GetResidue().GetAtomID(atom.OBAtom)

#      if name.find("HXT") != -1 or name.find("OXT") != -1:
#        removeAtoms.append(atom.OBAtom)
      # NME is tricky
      if ligand == "NME" and name.find("HN2") != -1:
        removeAtoms.append(atom.OBAtom)
      if ligand != "NME" and name.find("H2") != -1:
        removeAtoms.append(atom.OBAtom)
      
    for atom in removeAtoms:
        mol_pdb.OBMol.DeleteAtom(atom, False)

    # convert to a MOPAC internal
    internal = mol_pdb.write("mopin")

    # drop the first two lines of internal
    with open(ligand + ".zmat", "w") as f:
        i = 0
        # drop the first two lines
        for line in internal.splitlines()[2:]:
            items = line.split()
            if len(items) < 10:
                continue

            element = items[0]
            length = items[1]
            angle = items[3]
            torsion = items[5]
            atom1, atom2, atom3 = items[7], items[8], items[9]

            obatom = mol_pdb.atoms[i].OBAtom
            name = obatom.GetResidue().GetAtomID(obatom)
            i += 1

            f.write(
                f"{element:2} {name} {length:2.6} {angle:4.8} {torsion:4.8} {atom1:>3} {atom2:>3} {atom3:>3}\n"
            )

os.remove("temp.pdb")
