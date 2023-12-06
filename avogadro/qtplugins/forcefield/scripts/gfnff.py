#  This source file is part of the Avogadro project.
#  This source code is released under the 3-Clause BSD License, (see "LICENSE").

import argparse
import json
import sys
import os

try:
    import numpy as np
    from xtb.libxtb import VERBOSITY_MUTED
    from xtb.interface import Calculator, Param, Environment

    imported = True
except ImportError:
    imported = False

# we need to redirect stdout
# this is from https://eli.thegreenplace.net/2015/redirecting-all-kinds-of-stdout-in-python/
from contextlib import contextmanager
import ctypes
import io
import tempfile

libc = ctypes.CDLL(None)

@contextmanager
def stdout_redirector(stream):
    # The original fd stdout points to. Usually 1 on POSIX systems.
    original_stdout_fd = sys.stdout.fileno()

    def _redirect_stdout(to_fd):
        """Redirect stdout to the given file descriptor."""
        # Flush the C-level buffer stdout
        #libc.fflush(c_stdout)
        # Flush and close sys.stdout - also closes the file descriptor (fd)
        sys.stdout.close()
        # Make original_stdout_fd point to the same file as to_fd
        os.dup2(to_fd, original_stdout_fd)
        # Create a new sys.stdout that points to the redirected fd
        sys.stdout = io.TextIOWrapper(os.fdopen(original_stdout_fd, 'wb'))

    # Save a copy of the original stdout fd in saved_stdout_fd
    saved_stdout_fd = os.dup(original_stdout_fd)
    try:
        # Create a temporary file and redirect stdout to it
        tfile = tempfile.TemporaryFile(mode='w+b')
        _redirect_stdout(tfile.fileno())
        # Yield to caller, then redirect stdout back to the saved fd
        yield
        _redirect_stdout(saved_stdout_fd)
        # Copy contents of temporary file to the given stream
        tfile.flush()
        tfile.seek(0, io.SEEK_SET)
        stream.write(tfile.read())
    finally:
        tfile.close()
        os.close(saved_stdout_fd)


def getMetaData():
    # before we return metadata, make sure xtb is in the path
    if not imported:
        return {}  # Avogadro will ignore us now

    metaData = {
        "name": "GFN-FF",
        "identifier": "GFN-FF",
        "description": "Calculate GFNFF-xtb energies and gradients",
        "inputFormat": "cjson",
        "elements": "1-86",
        "unitCell": False,
        "gradients": True,
        "ion": True,
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

    # xtb doesn't properly mute
    # so we redirect stdout to a StringIO
    #  and then just ignore it
    f = io.BytesIO()
    with stdout_redirector(f):
        calc = Calculator(Param.GFNFF, atoms, coordinates, 
                        charge=charge, uhf=spin)
        calc.set_verbosity(VERBOSITY_MUTED)
        res = calc.singlepoint()

    # we loop forever - Avogadro will kill our process when done
    while True:
        # read new coordinates from stdin
        for i in range(len(atoms)):
            coordinates[i] = np.fromstring(input(), sep=' ')
        # .. convert from Angstrom to Bohr
        coordinates /= 0.52917721067

        # update the calculator and run a new calculation
        calc.update(coordinates)
        calc.singlepoint(res)

        print("AvogadroEnergy:", res.get_energy())  # in Hartree
        # times 2625.5 kJ/mol

        # now print the gradient
        # .. we don't want the "[]" in the output
        print("AvogadroGradient:")
        grad = res.get_gradient() * 4961.475  # convert units
        output = np.array2string(grad)
        output = output.replace("[", "").replace("]", "")
        print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("GFN-FF calculator")
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
