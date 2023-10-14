#  This source file is part of the Avogadro project.
#  This source code is released under the 3-Clause BSD License, (see "LICENSE").

import argparse
import json
import sys

try:
    import numpy as np
    from xtb.libxtb import VERBOSITY_MUTED
    from xtb.interface import Calculator, Param
    imported = True
except ImportError:
    imported = False

def getMetaData():
    # before we return metadata, make sure xtb is in the path
    if not imported:
        return {}  # Avogadro will ignore us now

    metaData = {
        "name": "GFN1",
        "identifier": "GFN1",
        "description": "Calculate GFN1-xtb energies and gradients",
        "inputFormat": "cjson",
        "elements": "1-86",
        "unitCell": False,
        "gradients": True,
        "ion": True,
        "radical": True,
    }
    return metaData


def run(filename):
    # we get the molecule from the supplied filename
    #  in cjson format (it's a temporary file created by Avogadro)
    with open(filename, "r") as f:
        mol_cjson = json.load(f)

    # first setup the calculator
    atoms = np.array(mol_cjson["atoms"]["elements"]["number"])
    coord_list = mol_cjson["atoms"]["coords"]["3d"]
    coordinates = np.array(coord_list, dtype=float).reshape(-1, 3)
    # .. we need to convert from Angstrom to Bohr
    coordinates /= 0.52917721067

    # check for total charge
    # and spin multiplicity
    charge = None  # neutral
    spin = None  # singlet
    if "properties" in mol_cjson:
        if "totalCharge" in mol_cjson["properties"]:
            charge = mol_cjson["properties"]["totalCharge"]
        if "totalSpinMultiplicity" in mol_cjson["properties"]:
            spin = mol_cjson["properties"]["totalSpinMultiplicity"]

    calc = Calculator(Param.GFN1xTB, atoms, coordinates,
                        charge=charge, uhf=spin)
    calc.set_verbosity(VERBOSITY_MUTED)
    res = calc.singlepoint()

    # we loop forever - Avogadro will kill the process when done
    while(True):
        # first print the energy of these coordinates
        print(res.get_energy()) # in Hartree

        # now print the gradient 
        # .. we don't want the "[]" in the output
        output = np.array2string(res.get_gradient())
        output = output.replace("[", "").replace("]", "")
        print(output)

        # read new coordinates from stdin
        for i in range(len(atoms)):
            coordinates[i] = np.fromstring(input(), sep=" ")
        # .. convert from Angstrom to Bohr
        coordinates /= 0.52917721067
        
        # update the calculator and run a new calculation
        calc.update(coordinates)
        calc.singlepoint(res)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("GFN1 calculator")
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
            sys.exit("xtb-python is unavailable")
    elif args["file"]:
        run(args["file"][0])
