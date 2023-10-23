#  This source file is part of the Avogadro project.
#  This source code is released under the 3-Clause BSD License, (see "LICENSE").

import argparse
import json
import sys

try:
    from openbabel import pybel
    import numpy as np

    imported = True
except ImportError:
    imported = False


def getMetaData():
    # before we return metadata, make sure xtb is in the path
    if not imported:
        return {}  # Avogadro will ignore us now

    metaData = {
        "name": "UFF",
        "identifier": "UFF",
        "description": "Calculate UFF energies and gradients",
        "inputFormat": "cml",
        "elements": "1-86",
        "unitCell": False,
        "gradients": True,
        "ion": False,
        "radical": False,
    }
    return metaData


def run(filename):
    # we get the molecule from the supplied filename
    #  in cjson format (it's a temporary file created by Avogadro)
    mol = next(pybel.readfile("cml", filename))

    ff = pybel._forcefields["uff"]
    success = ff.Setup(mol.OBMol)
    if not success:
        # should never happen, but just in case
        sys.exit("UFF force field setup failed")

    # we loop forever - Avogadro will kill the process when done
    num_atoms = len(mol.atoms)
    while True:
        # read new coordinates from stdin
        for i in range(num_atoms):
            coordinates = np.fromstring(input(), sep=" ")
            atom = mol.atoms[i]
            atom.OBAtom.SetVector(coordinates[0], coordinates[1], coordinates[2])

        # update the molecule geometry for the next energy
        ff.SetCoordinates(mol.OBMol)

        # first print the energy of these coordinates
        energy = ff.Energy(True)  # in kJ/mol
        print("AvogadroEnergy:", energy)  # in kJ/mol

        # now print the gradient on each atom
        print("AvogadroGradient:")
        for atom in mol.atoms:
            grad = ff.GetGradient(atom.OBAtom)
            print(grad.GetX(), grad.GetY(), grad.GetZ())


if __name__ == "__main__":
    parser = argparse.ArgumentParser("UFF calculator")
    parser.add_argument("--display-name", action="store_true")
    parser.add_argument("--metadata", action="store_true")
    parser.add_argument("-f", "--file", nargs=1)
    parser.add_argument("--lang", nargs="?", default="en")
    args = vars(parser.parse_args())

    if args["metadata"]:
        print(json.dumps(getMetaData()))
    elif args["display_name"]:
        name = getMetaData().get("name")
        if name:
            print(name)
        else:
            sys.exit("pybel is unavailable")
    elif args["file"]:
        run(args["file"][0])
