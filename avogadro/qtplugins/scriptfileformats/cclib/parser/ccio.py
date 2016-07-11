# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2009-2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Tools for identifying and working with files and streams for any supported program"""

from __future__ import print_function

import os

from . import logfileparser
from .adfparser import ADF
from .daltonparser import DALTON
from .gamessparser import GAMESS
from .gamessukparser import GAMESSUK
from .gaussianparser import Gaussian
from .jaguarparser import Jaguar
from .molproparser import Molpro
from .nwchemparser import NWChem
from .orcaparser import ORCA
from .psiparser import Psi
from .qchemparser import QChem

try:
    from ..bridge import cclib2openbabel
    _has_cclib2openbabel = True
except ImportError:
    _has_cclib2openbabel = False


# Parser choice is triggered by certain phrases occuring the logfile. Where these
# strings are unique, we can set the parser and break. In other cases, the situation
# is a little but more complicated. Here are the exceptions:
#   1. The GAMESS trigger also works for GAMESS-UK files, so we can't break
#      after finding GAMESS in case the more specific phrase is found.
#   2. Molpro log files don't have the program header, but always contain
#      the generic string 1PROGRAM, so don't break here either to be cautious.
#   3. The Psi header has two different strings with some variation
#
# The triggers are defined by the tuples in the list below like so:
#   (parser, phrases, flag whether we should break)
triggers = [

    (ADF,       ["Amsterdam Density Functional"],                   True),
    (DALTON,    ["Dalton - An Electronic Structure Program"],       True),
    (GAMESS,    ["GAMESS"],                                         False),
    (GAMESS,    ["GAMESS VERSION"],                                 True),
    (GAMESSUK,  ["G A M E S S - U K"],                              True),
    (Gaussian,  ["Gaussian, Inc."],                                 True),
    (Jaguar,    ["Jaguar"],                                         True),
    (Molpro,    ["PROGRAM SYSTEM MOLPRO"],                          True),
    (Molpro,    ["1PROGRAM"],                                       False),
    (NWChem,    ["Northwest Computational Chemistry Package"],      True),
    (ORCA,      ["O   R   C   A"],                                  True),
    (Psi,       ["PSI", "Ab Initio Electronic Structure"],          True),
    (QChem,     ["A Quantum Leap Into The Future Of Chemistry"],    True),

]


def guess_filetype(inputfile):
    """Try to guess the filetype by searching for trigger strings."""

    if not inputfile:
        return None

    filetype = None
    for line in inputfile:
        for parser, phrases, do_break in triggers:
            if all([line.lower().find(p.lower()) >= 0 for p in phrases]):
                filetype = parser
                if do_break:
                    return filetype
    return filetype


def ccread(source, *args, **kargs):
    """Attempt to open and read computational chemistry data from a file.

    If the file is not appropriate for cclib parsers, a fallback mechanism
    will try to recognize some common chemistry formats and read those using
    the appropriate bridge such as OpenBabel.

    Inputs:
        source - a single logfile, a list of logfiles, or an input stream
    Returns:
        a ccData object containing cclib data attributes
    """

    log = ccopen(source, *args, **kargs)
    if log:
        if kargs.get('verbose', None):
            print('Identified logfile to be in %s format' % log.logname)
        return log.parse()
    else:
        if kargs.get('verbose', None):
            print('Attempting to use fallback mechanism to read file')
        return fallback(source)


def ccopen(source, *args, **kargs):
    """Guess the identity of a particular log file and return an instance of it.

    Inputs:
      source - a single logfile, a list of logfiles, or an input stream

    Returns:
      one of ADF, DALTON, GAMESS, GAMESS UK, Gaussian, Jaguar, Molpro, NWChem, ORCA,
        Psi, QChem, or None (if it cannot figure it out or the file does not
        exist).
    """

    inputfile = None
    isstream = False
    is_string = isinstance(source, str)
    is_listofstrings = isinstance(source, list) and all([isinstance(s, str) for s in source])

    # Try to open the logfile(s), using openlogfile, if the source if a string (filename)
    # or list of filenames. If it can be read, assume it is an open file object/stream.
    if is_string or is_listofstrings:
        try:
            inputfile = logfileparser.openlogfile(source)
        except IOError as error:
            if not kargs.get('quiet', False):
                (errno, strerror) = error.args
                print("I/O error %s (%s): %s" % (errno, source, strerror))
            return None
    elif hasattr(source, "read"):
        inputfile = source
        isstream = True

    # Proceed to return an instance of the logfile parser only if the filetype
    # could be guessed. Need to make sure the input file is closed before creating
    # an instance, because parsers will handle opening/closing on their own.
    filetype = guess_filetype(inputfile)
    if filetype:
        if not isstream:
            inputfile.close()
        return filetype(source, *args, **kargs)


def fallback(source):
    """Attempt to read standard molecular formats using other libraries.

    Currently this will read XYZ files with OpenBabel, but this can easily
    be extended to other formats and libraries, too.
    """

    if isinstance(source, str):
        ext = os.path.splitext(source)[1][1:].lower()
        if _has_cclib2openbabel:
            if ext in ('xyz', ):
                return cclib2openbabel.readfile(source, ext)
        else:
            print("Could not import openbabel, fallback mechanism might not work.")
