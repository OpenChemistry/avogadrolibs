# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2006, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Bridge for using cclib data in biopython (http://biopython.org)."""

try:
    from Bio.PDB.Atom import Atom
except ImportError:
    # Fail silently for now.
    pass

from cclib.parser.utils import PeriodicTable


def makebiopython(atomcoords, atomnos):
    """Create a list of BioPython Atoms.

    This creates a list of BioPython Atoms suitable for use
    by Bio.PDB.Superimposer, for example.

    >>> import numpy
    >>> from Bio.PDB.Superimposer import Superimposer
    >>> atomnos = numpy.array([1,8,1],"i")
    >>> a = numpy.array([[-1,1,0],[0,0,0],[1,1,0]],"f")
    >>> b = numpy.array([[1.1,2,0],[1,1,0],[2,1,0]],"f")
    >>> si = Superimposer()
    >>> si.set_atoms(makebiopython(a,atomnos),makebiopython(b,atomnos))
    >>> print si.rms
    0.29337859596
    """
    pt = PeriodicTable()
    bioatoms = []
    for coords, atomno in zip(atomcoords, atomnos):
        bioatoms.append(Atom(pt.element[atomno], coords, 0, 0, 0, 0, 0))
    return bioatoms


if __name__ == "__main__":
    import doctest
    doctest.testmod()
