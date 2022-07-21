#  This source file is part of the Avogadro project.
#  This source code is released under the 3-Clause BSD License, (see "LICENSE").

# This assigns charges using AM1-BCC from antechamber
#  .. which is released under the GPL license

import argparse
import json
import sys
import os
from shutil import which
import tempfile
import subprocess


def getMetaData():
    # before we return metadata, make sure antechamber is in the path
    if which("antechamber") is None:
        return {}  # Avogadro will ignore us now

    metaData = {}
    metaData["inputFormat"] = "sdf"  # could be other formats, but this is fine
    metaData["identifier"] = "AM1BCC"
    metaData["name"] = "AM1-BCC"
    metaData["description"] = "Calculate atomic partial charges using AM1-BCC"
    metaData["charges"] = True
    metaData["potential"] = False
    metaData[
        "elements"
    ] = "1,6,7,8,9,14,15,16,17,35,53"  # H, C, N, O, F, Si, S, P, Cl, Br, I
    return metaData


def charges():
    # Avogadro will send us the sdf file as stdin
    # we need to write it to a temporary file

    # get the whole sdf file
    sdf = sys.stdin.read()

    fd, name = tempfile.mkstemp(".sdf")
    os.write(fd, sdf.encode())
    os.close(fd)

    # run xtb
    binary = which("antechamber")
    if binary is None:  # we check again
        return ""

    # for now, ignore the output itself
    tempdir = tempfile.mkdtemp()
    lig1 = tempdir + "/" + "lig1.mol2"
    lig2 = tempdir + "/" + "lig2.mol2"
    output = subprocess.run(
        [
            binary,
            "-i",
            name,
            "-fi",
            "sdf",
            "-o",
            lig1,
            "-fo",
            "mol2",
            "-c",
            "bcc",
            "-pf",
            "y",
            "-ek",
            "maxcyc=0, qm_theory='AM1', scfconv=1.d-10, ndiis_attempts=700,"
        ],
        stdout=subprocess.PIPE,
        cwd=tempdir,
        check=True,
    )
    output = subprocess.run(
        [
            binary,
            "-i",
            lig1,
            "-fi",
            "mol2",
            "-o",
            lig2,
            "-fo",
            "mol2",
            "-c",
            "wc",
            "-cf",
            "charges",
            "-pf",
            "y",
        ],
        stdout=subprocess.PIPE,
        cwd=tempdir,
        check=True,
    )
    # instead we read the "charges.txt" file
    result = ""
    with open(tempdir + "/" + "charges", "r", encoding="utf-8") as f:
        # we get lines with multiple charges per line
        for line in f:
            charges = line.split()
            for charge in charges:
                result += charge + "\n"

    # try to cleanup the temporary files
    os.remove(name)
    for filename in os.listdir(tempdir):
        try:
            os.remove(tempdir + "/" + filename)
        except:
            continue
    # and try to cleanup the directory
    try:
        os.rmdir(tempdir)
    except:
        pass

    # write the charges to stdout
    return result


def potential():
    # The default will calculate ESP from the partial charges

    # if your plugin has a potential, you can return it here
    # .. you'll get JSON with the file and the set of points
    #   e.g. { "xyz" : "xyz file contents", "points" : [ x,y,z, x,y,z, ... ] }
    #    or  { "sdf" : "sdf file contents", "points" : [ x,y,z, x,y,z, ... ] }
    # .. and you print the list of potentials to stdout
    return ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser("AM1-BCC partial charges")
    parser.add_argument("--display-name", action="store_true")
    parser.add_argument("--metadata", action="store_true")
    parser.add_argument("--charges", action="store_true")
    parser.add_argument("--potential", action="store_true")
    parser.add_argument("--lang", nargs="?", default="en")
    args = vars(parser.parse_args())

    if args["metadata"]:
        print(json.dumps(getMetaData()))
    elif args["display_name"]:
        name = getMetaData().get("name")
        if name:
            print(name)
        else:
            raise RuntimeError("antechamber is unavailable")
    elif args["charges"]:
        print(charges())
    elif args["potential"]:
        print(potential())
