#  This source file is part of the Avogadro project.
#  This source code is released under the 3-Clause BSD License, (see "LICENSE").

import argparse
import json
import sys

try:
    import msgpack
    msgpack_available = True
except ImportError:
    msgpack_available = False

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
        "name": "GAFF",
        "identifier": "GAFF",
        "description": "Calculate GAFF energies and gradients",
        "inputFormat": "cml",
        "elements": "1,6-9,14-17,35,53",
        "unitCell": False,
        "gradients": True,
        "ion": False,
        "radical": False,
    }
    if (msgpack_available):
        metaData["msgpack"] = True
    return metaData


def run(filename):
    # we get the molecule from the supplied filename
    #  in cjson format (it's a temporary file created by Avogadro)
    mol = next(pybel.readfile("cml", filename))

    ff = pybel._forcefields["gaff"]
    success = ff.Setup(mol.OBMol)
    if not success:
        # should never happen, but just in case
        sys.exit("GAFF setup failed")

    # we loop forever - Avogadro will kill the process when done
    num_atoms = len(mol.atoms)
    while True:
        # read new coordinates from stdin
        if (msgpack_available):
            # unpack the coordinates
            data = msgpack.unpackb(sys.stdin.buffer.read())
            np_coords = np.array(data["coordinates"], dtype=float).reshape(-1, 3)
            for i in range(num_atoms):
                atom = mol.atoms[i]
                atom.OBAtom.SetVector(np_coords[i][0], np_coords[i][1], np_coords[i][2])
        else:
            for i in range(num_atoms):
                coordinates = np.fromstring(input(), sep=" ")
                atom = mol.atoms[i]
                atom.OBAtom.SetVector(coordinates[0], coordinates[1], coordinates[2])

        # update the molecule geometry for the next energy
        ff.SetCoordinates(mol.OBMol)

        # first print the energy of these coordinates
        energy = ff.Energy(True)  # in kJ/mol
        if (msgpack_available):
            response = {"energy": energy}
        else:
            print("AvogadroEnergy:", energy)  # in kJ/mol

        # now print the gradient on each atom
        if (msgpack_available):
            gradient = []
            for atom in mol.atoms:
                grad = ff.GetGradient(atom.OBAtom)
                gradient.append([-1.0*grad.GetX(), -1.0*grad.GetY(), -1.0*grad.GetZ()])
            response["gradient"] = gradient
            print(msgpack.packb(response))
        else:
            print("AvogadroGradient:")
            for atom in mol.atoms:
                grad = ff.GetGradient(atom.OBAtom)
                print(-1.0*grad.GetX(), -1.0*grad.GetY(), -1.0*grad.GetZ())


if __name__ == "__main__":
    parser = argparse.ArgumentParser("GAFF calculator")
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
