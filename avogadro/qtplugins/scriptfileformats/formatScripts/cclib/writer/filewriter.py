# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Generic file writer and related tools"""

try:
    from cclib.bridge import makeopenbabel
    import openbabel as ob
    import pybel as pb
    has_openbabel = True
except ImportError:
    has_openbabel = False

from math import sqrt

from cclib.parser.utils import PeriodicTable


class Writer(object):
    """Abstract class for writer objects.

    Subclasses defined by cclib:
        CJSON, CML, XYZ
    """

    def __init__(self, ccdata, jobfilename=None, terse=False,
                 *args, **kwargs):
        """Initialize the Writer object.

        This should be called by a subclass in its own __init__ method.

        Inputs:
          ccdata - An instance of ccData, parsed from a logfile.
          jobfilename - The filename of the parsed logfile.
          terse - Whether to print the terse version of the output file - currently limited to cjson/json formats
        """

        self.ccdata = ccdata
        self.jobfilename = jobfilename
        self.terse = terse

        self.pt = PeriodicTable()
        self.elements = [self.pt.element[Z] for Z in self.ccdata.atomnos]

        # Open Babel isn't necessarily present.
        if has_openbabel:
            # Generate the Open Babel/Pybel representation of the molecule.
            # Used for calculating SMILES/InChI, formula, MW, etc.
            self.obmol, self.pbmol = self._make_openbabel_from_ccdata()
            self.bond_connectivities = self._make_bond_connectivity_from_openbabel(self.obmol)

    def generate_repr(self):
        """Generate the written representation of the logfile data.

        This should be overriden by all the subclasses inheriting from
        Writer.
        """
        pass

    def _make_openbabel_from_ccdata(self):
        """Create Open Babel and Pybel molecules from ccData.
        """
        obmol = makeopenbabel(self.ccdata.atomcoords,
                              self.ccdata.atomnos,
                              charge=self.ccdata.charge,
                              mult=self.ccdata.mult)
        if self.jobfilename is not None:
            obmol.SetTitle(self.jobfilename)
        return (obmol, pb.Molecule(obmol))

    def _calculate_total_dipole_moment(self):
        """Calculate the total dipole moment."""
        return sqrt(sum(self.ccdata.moments[1] ** 2))

    def _make_bond_connectivity_from_openbabel(self, obmol):
        """Based upon the Open Babel/Pybel molecule, create a list of tuples
        to represent bonding information, where the three integers are
        the index of the starting atom, the index of the ending atom,
        and the bond order.
        """
        bond_connectivities = []
        for obbond in ob.OBMolBondIter(obmol):
            bond_connectivities.append((obbond.GetBeginAtom().GetIndex(),
                                        obbond.GetEndAtom().GetIndex(),
                                        obbond.GetBondOrder()))
        return bond_connectivities


if __name__ == "__main__":
    pass
