# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2006-2013, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Bridge for using cclib data in PyQuante (http://pyquante.sourceforge.net)."""

from __future__ import print_function

import sys

try:
    from PyQuante.Molecule import Molecule
except ImportError:
    # Fail silently for now.
    pass


def makepyquante(atomcoords, atomnos, charge=0, mult=1):
    """Create a PyQuante Molecule.

    >>> import numpy
    >>> from PyQuante.hartree_fock import hf
    >>> atomnos = numpy.array([1,8,1],"i")
    >>> a = numpy.array([[-1,1,0],[0,0,0],[1,1,0]],"f")
    >>> pyqmol = makepyquante(a,atomnos)
    >>> en,orbe,orbs = hf(pyqmol)
    >>> print int(en * 10) / 10. # Should be around -73.8
    -73.8
    """
    return Molecule("notitle", list(zip(atomnos, atomcoords)), units="Angstrom",
                    charge=charge, multiplicity=mult)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
