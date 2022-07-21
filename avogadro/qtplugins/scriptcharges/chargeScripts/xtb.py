#  This source file is part of the Avogadro project.
#  This source code is released under the 3-Clause BSD License, (see "LICENSE").

import argparse
import json
import sys
import os
from shutil import which
import tempfile
import subprocess


def getMetaData():
    # before we return metadata, make sure xtb is in the path
    if which("xtb") is None:
        return {}  # Avogadro will ignore us now

    metaData = {}
    metaData["inputFormat"] = "mol"  # could be other formats, but this is fine
    metaData["identifier"] = "GFN2"
    metaData["name"] = "GFN2"
    metaData["description"] = "Calculate atomic partial charges using GFN2 and xtb"
    metaData["charges"] = True
    metaData["potential"] = False
    metaData["elements"] = "1-86"  # up to Radon
    return metaData


def charges():
    # Avogadro will send us the mol file as stdin
    # we need to write it to a temporary file

    # get the whole file
    mol = sys.stdin.read()

    fd, name = tempfile.mkstemp(".mol")
    os.write(fd, mol.encode())
    os.close(fd)

    # run xtb
    xtb = which("xtb")
    if xtb is None:  # we check again
        return ""

    # for now, ignore the output itself
    tempdir = tempfile.mkdtemp()
    output = subprocess.run(
        [xtb, name], stdout=subprocess.PIPE, cwd=tempdir, check=True
    )
    # instead we read the "charges" file
    result = ""
    with open(tempdir + "/" + "charges", "r", encoding="utf-8") as f:
        result = f.read()

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
    # at the moment, xtb doesn't have a good way to do this
    # and the method shouldn't be called anyway

    # if your plugin has a potential, you can return it here
    # .. you'll get JSON with the file and the set of points
    #   e.g. { "xyz" : "xyz file contents", "points" : [ x,y,z, x,y,z, ... ] }
    #    or  { "sdf" : "sdf file contents", "points" : [ x,y,z, x,y,z, ... ] }
    # .. and you print the list of potentials to stdout
    return ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser("GFN2 partial charges")
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
            raise RuntimeError("xtb is unavailable")
    elif args["charges"]:
        print(charges())
    elif args["potential"]:
        print(potential())
