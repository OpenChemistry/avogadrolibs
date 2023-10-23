#  This source file is part of the Avogadro project.
#  This source code is released under the 3-Clause BSD License, (see "LICENSE").

import argparse
import json
import sys

try:
    import torch
    import torchani
    import numpy as np

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = torchani.models.ANI2x(periodic_table_index=True).to(device)

    imported = True
except ImportError:
    imported = False


def getMetaData():
    # before we return metadata, make sure xtb is in the path
    if not imported:
        return {}  # Avogadro will ignore us now

    metaData = {
        "name": "ANI2x",
        "identifier": "ANI2x",
        "description": "Calculate ANI-2x energies and gradients",
        "inputFormat": "cjson",
        "elements": "1,6-9,16-17",
        "unitCell": False,
        "gradients": True,
        "ion": False,
        "radical": False,
    }
    return metaData


def run(filename):
    # we get the molecule from the supplied filename
    #  in cjson format (it's a temporary file created by Avogadro)
    with open(filename, "r") as f:
        mol_cjson = json.load(f)

    # first setup the calculator
    atoms = np.array(mol_cjson["atoms"]["elements"]["number"])
    species = torch.tensor([atoms], device=device)
    coord_list = mol_cjson["atoms"]["coords"]["3d"]
    np_coords = np.array(coord_list, dtype=float).reshape(-1, 3)
    coordinates = torch.tensor([np_coords], requires_grad=True, device=device)

    # we loop forever - Avogadro will kill the process when done
    num_atoms = len(atoms)
    while True:
        # read new coordinates from stdin
        for i in range(num_atoms):
            np_coords[i] = np.fromstring(input(), sep=" ")
        coordinates = torch.tensor([np_coords], requires_grad=True, device=device)

        # first print the energy of these coordinates
        energy = model((species, coordinates)).energies
        print("AvogadroEnergy:", energy)  # in Hartree

        # now print the gradient on each atom
        print("AvogadroGradient:")
        derivative = torch.autograd.grad(energy.sum(), coordinates)[0]
        for i in range(num_atoms):
            print(derivative[0][i][0].item(), derivative[0][i][1].item(), derivative[0][i][2].item())


if __name__ == "__main__":
    parser = argparse.ArgumentParser("ANI-2x calculator")
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
            sys.exit("ANI-2x is unavailable")
    elif args["file"]:
        run(args["file"][0])
