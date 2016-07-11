# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2006-2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Parser for ADF output files"""

from __future__ import print_function

import numpy
import re

from . import logfileparser
from . import utils


class ADF(logfileparser.Logfile):
    """An ADF log file"""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(ADF, self).__init__(logname="ADF", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "ADF log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'ADF("%s")' % (self.filename)

    def normalisesym(self, label):
        """Use standard symmetry labels instead of ADF labels.

        To normalise:
        (1) any periods are removed (except in the case of greek letters)
        (2) XXX is replaced by X, and a " added.
        (3) XX is replaced by X, and a ' added.
        (4) The greek letters Sigma, Pi, Delta and Phi are replaced by
            their lowercase equivalent.

        >>> sym = ADF("dummyfile").normalisesym
        >>> labels = ['A','s','A1','A1.g','Sigma','Pi','Delta','Phi','Sigma.g','A.g','AA','AAA','EE1','EEE1']
        >>> map(sym,labels)
        ['A', 's', 'A1', 'A1g', 'sigma', 'pi', 'delta', 'phi', 'sigma.g', 'Ag', "A'", 'A"', "E1'", 'E1"']
        """
        greeks = ['Sigma', 'Pi', 'Delta', 'Phi']
        for greek in greeks:
            if label.startswith(greek):
                return label.lower()

        ans = label.replace(".", "")
        if ans[1:3] == "''":
            temp = ans[0] + '"'
            ans = temp

        l = len(ans)
        if l > 1 and ans[0] == ans[1]:  # Python only tests the second condition if the first is true
            if l > 2 and ans[1] == ans[2]:
                ans = ans.replace(ans[0]*3, ans[0]) + '"'
            else:
                ans = ans.replace(ans[0]*2, ans[0]) + "'"
        return ans

    def normalisedegenerates(self, label, num, ndict=None):
        """Generate a string used for matching degenerate orbital labels

        To normalise:
        (1) if label is E or T, return label:num
        (2) if label is P or D, look up in dict, and return answer
        """

        if not ndict:
            ndict = {
                'P': {0: "P:x", 1: "P:y", 2: "P:z"},
                'D': {0: "D:z2", 1: "D:x2-y2", 2: "D:xy", 3: "D:xz", 4: "D:yz"}
            }

        if label in ndict:
            if num in ndict[label]:
                return ndict[label][num]
            else:
                return "%s:%i" % (label, num+1)
        else:
            return "%s:%i" % (label, num+1)

    def before_parsing(self):

        # Used to avoid extracting the final geometry twice in a GeoOpt
        self.NOTFOUND, self.GETLAST, self.NOMORE = list(range(3))
        self.finalgeometry = self.NOTFOUND

        # Used for calculating the scftarget (variables names taken from the ADF manual)
        self.accint = self.SCFconv = self.sconv2 = None

        # keep track of nosym and unrestricted case to parse Energies since it doens't have an all Irreps section
        self.nosymflag = False
        self.unrestrictedflag = False

        SCFCNV, SCFCNV2 = list(range(2))  # used to index self.scftargets[]
        maxelem, norm = list(range(2))  # used to index scf.values

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        # If a file contains multiple calculations, currently we want to print a warning
        # and skip to the end of the file, since cclib parses only the main system, which
        # is usually the largest. Here we test this by checking if scftargets has already
        # been parsed when another INPUT FILE segment is found, although this might
        # not always be the best indicator.
        if line.strip() == "(INPUT FILE)" and hasattr(self, "scftargets"):
            self.logger.warning("Skipping remaining calculations")
            inputfile.seek(0, 2)
            return

        # We also want to check to make sure we aren't parsing "Create" jobs,
        # which normally come before the calculation we actually want to parse.
        if line.strip() == "(INPUT FILE)":
            while True:
                self.updateprogress(inputfile, "Unsupported Information", self.fupdate)
                line = next(inputfile) if line.strip() == "(INPUT FILE)" else None
                if line and not line[:6] in ("Create", "create"):
                    break
                line = next(inputfile)

        # In ADF 2014.01, there are (INPUT FILE) messages, so we need to use just
        # the lines that start with 'Create' and run until the title or something
        # else we are sure is is the calculation proper. It would be good to combine
        # this with the previous block, if possible.
        if line[:6] == "Create":
            while line[:5] != "title":
                line = inputfile.next()

        if line[1:10] == "Symmetry:":
            info = line.split()
            if info[1] == "NOSYM":
                self.nosymflag = True

        # Use this to read the subspecies of irreducible representations.
        # It will be a list, with each element representing one irrep.
        if line.strip() == "Irreducible Representations, including subspecies":

            self.skip_line(inputfile, 'dashes')

            self.irreps = []
            line = next(inputfile)
            while line.strip() != "":
                self.irreps.append(line.split())
                line = next(inputfile)

        if line[4:13] == 'Molecule:':
            info = line.split()
            if info[1] == 'UNrestricted':
                self.unrestrictedflag = True

        if line[1:6] == "ATOMS":
        # Find the number of atoms and their atomic numbers
        # Also extract the starting coordinates (for a GeoOpt anyway)
        # and the atommasses (previously called vibmasses)
            self.updateprogress(inputfile, "Attributes", self.cupdate)

            self.atomcoords = []

            self.skip_lines(inputfile, ['header1', 'header2', 'header3'])

            atomnos = []
            atommasses = []
            atomcoords = []
            coreelectrons = []
            line = next(inputfile)
            while len(line) > 2:  # ensure that we are reading no blank lines
                info = line.split()
                element = info[1].split('.')[0]
                atomnos.append(self.table.number[element])
                atomcoords.append(list(map(float, info[2:5])))
                coreelectrons.append(int(float(info[5]) - float(info[6])))
                atommasses.append(float(info[7]))
                line = next(inputfile)
            self.atomcoords.append(atomcoords)

            self.set_attribute('natom', len(atomnos))
            self.set_attribute('atomnos', atomnos)
            self.set_attribute('atommasses', atommasses)
            self.set_attribute('coreelectrons', coreelectrons)

        if line[1:10] == "FRAGMENTS":
            header = next(inputfile)

            self.frags = []
            self.fragnames = []

            line = next(inputfile)
            while len(line) > 2:  # ensure that we are reading no blank lines
                info = line.split()

                if len(info) == 7:  # fragment name is listed here
                    self.fragnames.append("%s_%s" % (info[1], info[0]))
                    self.frags.append([])
                    self.frags[-1].append(int(info[2]) - 1)

                elif len(info) == 5:  # add atoms into last fragment
                    self.frags[-1].append(int(info[0]) - 1)

                line = next(inputfile)

        # Extract charge
        if line[1:11] == "Net Charge":

            charge = int(line.split()[2])
            self.set_attribute('charge', charge)

            line = next(inputfile)
            if len(line.strip()):
                #  Spin polar: 1 (Spin_A minus Spin_B electrons)
                # (Not sure about this for higher multiplicities)
                mult = int(line.split()[2]) + 1
            else:
                mult = 1
            self.set_attribute('mult', mult)

        if line[1:22] == "S C F   U P D A T E S":
        # find targets for SCF convergence

            if not hasattr(self, "scftargets"):
                self.scftargets = []

            self.skip_lines(inputfile, ['e', 'b', 'numbers'])

            line = next(inputfile)
            self.SCFconv = float(line.split()[-1])
            line = next(inputfile)
            self.sconv2 = float(line.split()[-1])

        # In ADF 2013, the default numerical integration method is fuzzy cells,
        # although it used to be Voronoi polyhedra. Both methods apparently set
        # the accint parameter, although the latter does so indirectly, based on
        # a 'grid quality' setting. This is translated into accint using a
        # dictionary with values taken from the documentation.
        if "Numerical Integration : Voronoi Polyhedra (Te Velde)" in line:
            self.integration_method = "voronoi_polyhedra"
        if line[1:27] == 'General Accuracy Parameter':
            # Need to know the accuracy of the integration grid to
            # calculate the scftarget...note that it changes with time
            self.accint = float(line.split()[-1])
        if "Numerical Integration : Fuzzy Cells (Becke)" in line:
            self.integration_method = 'fuzzy_cells'
        if line[1:19] == "Becke grid quality":
            self.grid_quality = line.split()[-1]
            quality2accint = {
                'BASIC': 2.0,
                'NORMAL': 4.0,
                'GOOD': 6.0,
                'VERYGOOD': 8.0,
                'EXCELLENT': 10.0,
            }
            self.accint = quality2accint[self.grid_quality]

        # Half of the atomic orbital overlap matrix is printed since it is symmetric,
        # but this requires "PRINT Smat" to be in the input. There are extra blank lines
        # at the end of the block, which are used to terminate the parsing.
        #
        # ======  smat
        #
        # column           1                     2                     3                     4
        # row
        #    1    1.00000000000000E+00
        #    2    2.43370854175315E-01  1.00000000000000E+00
        #    3    0.00000000000000E+00  0.00000000000000E+00  1.00000000000000E+00
        # ...
        #
        if "======  smat" in line:

            # Initialize the matrix with Nones so we can easily check all has been parsed.
            overlaps = [[None] * self.nbasis for i in range(self.nbasis)]

            self.skip_line(inputfile, 'blank')

            line = inputfile.next()
            while line.strip():

                colline = line
                assert colline.split()[0] == "column"
                columns = [int(i) for i in colline.split()[1:]]

                rowline = inputfile.next()
                assert rowline.strip() == "row"

                line = inputfile.next()
                while line.strip():

                    i = int(line.split()[0])
                    vals = [float(col) for col in line.split()[1:]]
                    for j, o in enumerate(vals):
                        k = columns[j]
                        overlaps[k-1][i-1] = o
                        overlaps[i-1][k-1] = o

                    line = inputfile.next()

                line = inputfile.next()

            # Now all values should be parsed, and so no Nones remaining.
            assert all([all([x is not None for x in ao]) for ao in overlaps])

            self.set_attribute('aooverlaps', overlaps)

        if line[1:11] == "CYCLE    1":

            self.updateprogress(inputfile, "QM convergence", self.fupdate)

            newlist = []
            line = next(inputfile)

            if not hasattr(self, "geovalues"):
                # This is the first SCF cycle
                self.scftargets.append([self.sconv2*10, self.sconv2])
            elif self.finalgeometry in [self.GETLAST, self.NOMORE]:
                # This is the final SCF cycle
                self.scftargets.append([self.SCFconv*10, self.SCFconv])
            else:
                # This is an intermediate SCF cycle in a geometry optimization,
                # in which case the SCF convergence target needs to be derived
                # from the accint parameter. For Voronoi polyhedra integration,
                # accint is printed and parsed. For fuzzy cells, it can be inferred
                # from the grid quality setting, as is done somewhere above.
                if self.accint:
                    oldscftst = self.scftargets[-1][1]
                    grdmax = self.geovalues[-1][1]
                    scftst = max(self.SCFconv, min(oldscftst, grdmax/30, 10**(-self.accint)))
                    self.scftargets.append([scftst*10, scftst])

            while line.find("SCF CONVERGED") == -1 and line.find("SCF not fully converged, result acceptable") == -1 and line.find("SCF NOT CONVERGED") == -1:
                if line[4:12] == "SCF test":
                    if not hasattr(self, "scfvalues"):
                        self.scfvalues = []

                    info = line.split()
                    newlist.append([float(info[4]), abs(float(info[6]))])
                try:
                    line = next(inputfile)
                except StopIteration:  # EOF reached?
                    self.logger.warning("SCF did not converge, so attributes may be missing")
                    break

            if line.find("SCF not fully converged, result acceptable") > 0:
                self.logger.warning("SCF not fully converged, results acceptable")

            if line.find("SCF NOT CONVERGED") > 0:
                self.logger.warning("SCF did not converge! moenergies and mocoeffs are unreliable")

            if hasattr(self, "scfvalues"):
                self.scfvalues.append(newlist)

        # Parse SCF energy for SP calcs from bonding energy decomposition section.
        # It seems ADF does not print it earlier for SP calculations.
        # Geometry optimization runs also print this, and we want to parse it
        # for them, too, even if it repeats the last "Geometry Convergence Tests"
        # section (but it's usually a bit different).
        if line[:21] == "Total Bonding Energy:":

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []

            energy = utils.convertor(float(line.split()[3]), "hartree", "eV")
            self.scfenergies.append(energy)

        if line[51:65] == "Final Geometry":
            self.finalgeometry = self.GETLAST

        # Get the coordinates from each step of the GeoOpt.
        if line[1:24] == "Coordinates (Cartesian)" and self.finalgeometry in [self.NOTFOUND, self.GETLAST]:

            self.skip_lines(inputfile, ['e', 'b', 'title', 'title', 'd'])

            atomcoords = []
            line = next(inputfile)
            while list(set(line.strip())) != ['-']:
                atomcoords.append(list(map(float, line.split()[5:8])))
                line = next(inputfile)

            if not hasattr(self, "atomcoords"):
                self.atomcoords = []
            self.atomcoords.append(atomcoords)

            # Don't get any more coordinates in this case.
            # KML: I think we could combine this with optdone (see below).
            if self.finalgeometry == self.GETLAST:
                self.finalgeometry = self.NOMORE

        # There have been some changes in the format of the geometry convergence information,
        # and this is how it is printed in older versions (2007.01 unit tests).
        #
        # ==========================
        # Geometry Convergence Tests
        # ==========================
        #
        # Energy  old :         -5.14170647
        #         new :         -5.15951374
        #
        # Convergence tests:
        # (Energies in hartree, Gradients in hartree/angstr or radian, Lengths in angstrom, Angles in degrees)
        #
        #       Item               Value         Criterion    Conv.        Ratio
        # -------------------------------------------------------------------------
        # change in energy      -0.01780727     0.00100000    NO         0.00346330
        # gradient max           0.03219530     0.01000000    NO         0.30402650
        # gradient rms           0.00858685     0.00666667    NO         0.27221261
        # cart. step max         0.07674971     0.01000000    NO         0.75559435
        # cart. step rms         0.02132310     0.00666667    NO         0.55335378
        #
        if line[1:27] == 'Geometry Convergence Tests':

            if not hasattr(self, "geotargets"):
                self.geovalues = []
                self.geotargets = numpy.array([0.0, 0.0, 0.0, 0.0, 0.0], "d")

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []

            self.skip_lines(inputfile, ['e', 'b'])

            energies_old = next(inputfile)
            energies_new = next(inputfile)
            self.scfenergies.append(utils.convertor(float(energies_new.split()[-1]), "hartree", "eV"))

            self.skip_lines(inputfile, ['b', 'convergence', 'units', 'b', 'header', 'd'])

            values = []
            for i in range(5):
                temp = next(inputfile).split()
                self.geotargets[i] = float(temp[-3])
                values.append(float(temp[-4]))

            self.geovalues.append(values)

            # This is to make geometry optimization always have the optdone attribute,
            # even if it is to be empty for unconverged runs.
            if not hasattr(self, 'optdone'):
                self.optdone = []

        # After the test, there is a message if the search is converged:
        #
        # ***************************************************************************************************
        #                             Geometry CONVERGED
        # ***************************************************************************************************
        #
        if line.strip() == "Geometry CONVERGED":
            self.skip_line(inputfile, 'stars')
            self.optdone.append(len(self.geovalues) - 1)

        # Here is the corresponding geometry convergence info from the 2013.01 unit test.
        # Note that the step number is given, which it will be prudent to use in an assertion.
        #
        #----------------------------------------------------------------------
        #Geometry Convergence after Step   3       (Hartree/Angstrom,Angstrom)
        #----------------------------------------------------------------------
        #current energy                               -5.16274478 Hartree
        #energy change                      -0.00237544     0.00100000    F
        #constrained gradient max            0.00884999     0.00100000    F
        #constrained gradient rms            0.00249569     0.00066667    F
        #gradient max                        0.00884999
        #gradient rms                        0.00249569
        #cart. step max                      0.03331296     0.01000000    F
        #cart. step rms                      0.00844037     0.00666667    F
        if line[:31] == "Geometry Convergence after Step":

            stepno = int(line.split()[4])

            # This is to make geometry optimization always have the optdone attribute,
            # even if it is to be empty for unconverged runs.
            if not hasattr(self, 'optdone'):
                self.optdone = []

            # The convergence message is inline in this block, not later as it was before.
            if "** CONVERGED **" in line:
                if not hasattr(self, 'optdone'):
                    self.optdone = []
                self.optdone.append(len(self.geovalues) - 1)

            self.skip_line(inputfile, 'dashes')

            current_energy = next(inputfile)
            energy_change = next(inputfile)
            constrained_gradient_max = next(inputfile)
            constrained_gradient_rms = next(inputfile)
            gradient_max = next(inputfile)
            gradient_rms = next(inputfile)
            cart_step_max = next(inputfile)
            cart_step_rms = next(inputfile)

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []

            energy = utils.convertor(float(current_energy.split()[-2]), "hartree", "eV")
            self.scfenergies.append(energy)

            if not hasattr(self, "geotargets"):
                self.geotargets = numpy.array([0.0, 0.0, 0.0, 0.0, 0.0], "d")

            self.geotargets[0] = float(energy_change.split()[-2])
            self.geotargets[1] = float(constrained_gradient_max.split()[-2])
            self.geotargets[2] = float(constrained_gradient_rms.split()[-2])
            self.geotargets[3] = float(cart_step_max.split()[-2])
            self.geotargets[4] = float(cart_step_rms.split()[-2])

            if not hasattr(self, "geovalues"):
                self.geovalues = []

            self.geovalues.append([])
            self.geovalues[-1].append(float(energy_change.split()[-3]))
            self.geovalues[-1].append(float(constrained_gradient_max.split()[-3]))
            self.geovalues[-1].append(float(constrained_gradient_rms.split()[-3]))
            self.geovalues[-1].append(float(cart_step_max.split()[-3]))
            self.geovalues[-1].append(float(cart_step_rms.split()[-3]))

        if line.find('Orbital Energies, per Irrep and Spin') > 0 and not hasattr(self, "mosyms") and self.nosymflag and not self.unrestrictedflag:
        #Extracting orbital symmetries and energies, homos for nosym case
        #Should only be for restricted case because there is a better text block for unrestricted and nosym

            self.mosyms = [[]]

            self.moenergies = [[]]

            self.skip_lines(inputfile, ['e', 'header', 'd', 'label'])

            line = next(inputfile)
            info = line.split()

            if not info[0] == '1':
                self.logger.warning("MO info up to #%s is missing" % info[0])

            #handle case where MO information up to a certain orbital are missing
            while int(info[0]) - 1 != len(self.moenergies[0]):
                self.moenergies[0].append(99999)
                self.mosyms[0].append('A')

            homoA = None

            while len(line) > 10:
                info = line.split()
                self.mosyms[0].append('A')
                self.moenergies[0].append(utils.convertor(float(info[2]), 'hartree', 'eV'))
                if info[1] == '0.000' and not hasattr(self, 'homos'):
                    self.set_attribute('homos', [len(self.moenergies[0]) - 2])
                line = next(inputfile)

            self.moenergies = [numpy.array(self.moenergies[0], "d")]

        if line[1:29] == 'Orbital Energies, both Spins' and not hasattr(self, "mosyms") and self.nosymflag and self.unrestrictedflag:
        #Extracting orbital symmetries and energies, homos for nosym case
        #should only be here if unrestricted and nosym

            self.mosyms = [[], []]
            moenergies = [[], []]

            self.skip_lines(inputfile, ['d', 'b', 'header', 'd'])

            homoa = 0
            homob = None

            line = next(inputfile)
            while len(line) > 5:
                info = line.split()
                if info[2] == 'A':
                    self.mosyms[0].append('A')
                    moenergies[0].append(utils.convertor(float(info[4]), 'hartree', 'eV'))
                    if info[3] != '0.00':
                        homoa = len(moenergies[0]) - 1
                elif info[2] == 'B':
                    self.mosyms[1].append('A')
                    moenergies[1].append(utils.convertor(float(info[4]), 'hartree', 'eV'))
                    if info[3] != '0.00':
                        homob = len(moenergies[1]) - 1
                else:
                    print(("Error reading line: %s" % line))

                line = next(inputfile)

            self.moenergies = [numpy.array(x, "d") for x in moenergies]

            self.set_attribute('homos', [homoa, homob])

        # Extracting orbital symmetries and energies, homos.
        if line[1:29] == 'Orbital Energies, all Irreps' and not hasattr(self, "mosyms"):

            self.symlist = {}
            self.mosyms = [[]]
            self.moenergies = [[]]

            self.skip_lines(inputfile, ['e', 'b', 'header', 'd'])

            homoa = None
            homob = None

            #multiple = {'E':2, 'T':3, 'P':3, 'D':5}
            # The above is set if there are no special irreps
            names = [irrep[0].split(':')[0] for irrep in self.irreps]
            counts = [len(irrep) for irrep in self.irreps]
            multiple = dict(list(zip(names, counts)))
            irrepspecies = {}
            for n in range(len(names)):
                indices = list(range(counts[n]))
                subspecies = self.irreps[n]
                irrepspecies[names[n]] = dict(list(zip(indices, subspecies)))

            line = next(inputfile)
            while line.strip():
                info = line.split()
                if len(info) == 5:  # this is restricted
                    #count = multiple.get(info[0][0],1)
                    count = multiple.get(info[0], 1)
                    for repeat in range(count):  # i.e. add E's twice, T's thrice
                        self.mosyms[0].append(self.normalisesym(info[0]))
                        self.moenergies[0].append(utils.convertor(float(info[3]), 'hartree', 'eV'))

                        sym = info[0]
                        if count > 1:   # add additional sym label
                            sym = self.normalisedegenerates(info[0], repeat, ndict=irrepspecies)

                        try:
                            self.symlist[sym][0].append(len(self.moenergies[0])-1)
                        except KeyError:
                            self.symlist[sym] = [[]]
                            self.symlist[sym][0].append(len(self.moenergies[0])-1)

                    if info[2] == '0.00' and not hasattr(self, 'homos'):
                        self.homos = [len(self.moenergies[0]) - (count + 1)]  # count, because need to handle degenerate cases
                    line = next(inputfile)
                elif len(info) == 6:  # this is unrestricted
                    if len(self.moenergies) < 2:  # if we don't have space, create it
                        self.moenergies.append([])
                        self.mosyms.append([])
#                    count = multiple.get(info[0][0], 1)
                    count = multiple.get(info[0], 1)
                    if info[2] == 'A':
                        for repeat in range(count):  # i.e. add E's twice, T's thrice
                            self.mosyms[0].append(self.normalisesym(info[0]))
                            self.moenergies[0].append(utils.convertor(float(info[4]), 'hartree', 'eV'))

                            sym = info[0]
                            if count > 1:  # add additional sym label
                                sym = self.normalisedegenerates(info[0], repeat)

                            try:
                                self.symlist[sym][0].append(len(self.moenergies[0])-1)
                            except KeyError:
                                self.symlist[sym] = [[], []]
                                self.symlist[sym][0].append(len(self.moenergies[0])-1)

                        if info[3] == '0.00' and homoa is None:
                            homoa = len(self.moenergies[0]) - (count + 1)  # count because degenerate cases need to be handled

                    if info[2] == 'B':
                        for repeat in range(count):  # i.e. add E's twice, T's thrice
                            self.mosyms[1].append(self.normalisesym(info[0]))
                            self.moenergies[1].append(utils.convertor(float(info[4]), 'hartree', 'eV'))

                            sym = info[0]
                            if count > 1:  # add additional sym label
                                sym = self.normalisedegenerates(info[0], repeat)

                            try:
                                self.symlist[sym][1].append(len(self.moenergies[1])-1)
                            except KeyError:
                                self.symlist[sym] = [[], []]
                                self.symlist[sym][1].append(len(self.moenergies[1])-1)

                        if info[3] == '0.00' and homob is None:
                            homob = len(self.moenergies[1]) - (count + 1)

                    line = next(inputfile)

                else:  # different number of lines
                    print(("Error", info))

            if len(info) == 6:  # still unrestricted, despite being out of loop
                self.set_attribute('homos', [homoa, homob])

            self.moenergies = [numpy.array(x, "d") for x in self.moenergies]

        # Section on extracting vibdisps
        # Also contains vibfreqs, but these are extracted in the
        # following section (see below)
        if line[1:28] == "Vibrations and Normal Modes":

            self.vibdisps = []

            self.skip_lines(inputfile, ['e', 'b', 'header', 'header', 'b', 'b'])

            freqs = next(inputfile)
            while freqs.strip() != "":
                minus = next(inputfile)
                p = [[], [], []]
                for i in range(len(self.atomnos)):
                    broken = list(map(float, next(inputfile).split()[1:]))
                    for j in range(0, len(broken), 3):
                        p[j//3].append(broken[j:j+3])
                self.vibdisps.extend(p[:(len(broken)//3)])
                self.skip_lines(inputfile, ['b', 'b'])
                freqs = next(inputfile)
            self.vibdisps = numpy.array(self.vibdisps, "d")

        if line[1:24] == "List of All Frequencies":
        # Start of the IR/Raman frequency section
            self.updateprogress(inputfile, "Frequency information", self.fupdate)

        #                 self.vibsyms = []  # Need to look into this a bit more
            self.vibirs = []
            self.vibfreqs = []
            for i in range(8):
                line = next(inputfile)
            line = next(inputfile).strip()
            while line:
                temp = line.split()
                self.vibfreqs.append(float(temp[0]))
                self.vibirs.append(float(temp[2]))  # or is it temp[1]?
                line = next(inputfile).strip()
            self.vibfreqs = numpy.array(self.vibfreqs, "d")
            self.vibirs = numpy.array(self.vibirs, "d")
            if hasattr(self, "vibramans"):
                self.vibramans = numpy.array(self.vibramans, "d")

        #******************************************************************************************************************8
        #delete this after new implementation using smat, eigvec print,eprint?
        # Extract the number of basis sets
        if line[1:49] == "Total nr. of (C)SFOs (summation over all irreps)":
            nbasis = int(line.split(":")[1].split()[0])
            self.set_attribute('nbasis', nbasis)

        # now that we're here, let's extract aonames

            self.fonames = []
            self.start_indeces = {}
            self.atombasis = [[] for frag in self.frags] # parse atombasis in the case of trivial SFOs

            self.skip_line(inputfile, 'blank')

            note = next(inputfile)
            symoffset = 0

            self.skip_line(inputfile, 'blank')
            line = next(inputfile)
            if len(line) > 2:  # fix for ADF2006.01 as it has another note
                self.skip_line(inputfile, 'blank')
                line = next(inputfile)
            self.skip_line(inputfile, 'blank')

            self.nosymreps = []
            while len(self.fonames) < self.nbasis:

                symline = next(inputfile)
                sym = symline.split()[1]
                line = next(inputfile)
                num = int(line.split(':')[1].split()[0])
                self.nosymreps.append(num)

                #read until line "--------..." is found
                while line.find('-----') < 0:
                    line = next(inputfile)

                line = next(inputfile)  # the start of the first SFO

                while len(self.fonames) < symoffset + num:
                    info = line.split()

                    #index0 index1 occ2 energy3/4 fragname5 coeff6 orbnum7 orbname8 fragname9
                    if not sym in list(self.start_indeces.keys()):
                    #have we already set the start index for this symmetry?
                        self.start_indeces[sym] = int(info[1])

                    orbname = info[8]
                    orbital = info[7] + orbname.replace(":", "")

                    fragname = info[5]
                    frag = fragname + info[9]

                    coeff = float(info[6])

                    # parse atombasis only in the case that all coefficients are 1
                    #    and delete it otherwise
                    if hasattr(self, 'atombasis'):
                        if coeff == 1.:
                            ibas  = int(info[0]) - 1
                            ifrag = int(info[9]) - 1
                            iat = self.frags[ifrag][0]
                            self.atombasis[iat].append(ibas)
                        else:
                            del self.atombasis

                    line = next(inputfile)
                    while line.strip() and not line[:7].strip():  # while it's the same SFO
                        # i.e. while not completely blank, but blank at the start
                        info = line[43:].split()
                        if len(info) > 0:  # len(info)==0 for the second line of dvb_ir.adfout
                            frag += "+" + fragname + info[-1]
                            coeff = float(info[-4])
                            if coeff < 0:
                                orbital += '-' + info[-3] + info[-2].replace(":", "")
                            else:
                                orbital += '+' + info[-3] + info[-2].replace(":", "")
                        line = next(inputfile)
                    # At this point, we are either at the start of the next SFO or at
                    # a blank line...the end

                    self.fonames.append("%s_%s" % (frag, orbital))
                symoffset += num

                # blankline blankline
                next(inputfile)
                next(inputfile)

        if line[1:32] == "S F O   P O P U L A T I O N S ,":
        #Extract overlap matrix

#            self.fooverlaps = numpy.zeros((self.nbasis, self.nbasis), "d")

            symoffset = 0

            for nosymrep in self.nosymreps:

                line = next(inputfile)
                while line.find('===') < 10:  # look for the symmetry labels
                    line = next(inputfile)

                self.skip_lines(inputfile, ['b', 'b'])

                text = next(inputfile)
                if text[13:20] != "Overlap":  # verify this has overlap info
                    break

                self.skip_lines(inputfile, ['b', 'col', 'row'])

                if not hasattr(self, "fooverlaps"):  # make sure there is a matrix to store this
                    self.fooverlaps = numpy.zeros((self.nbasis, self.nbasis), "d")

                base = 0
                while base < nosymrep:  # have we read all the columns?

                    for i in range(nosymrep - base):

                        self.updateprogress(inputfile, "Overlap", self.fupdate)
                        line = next(inputfile)
                        parts = line.split()[1:]
                        for j in range(len(parts)):
                            k = float(parts[j])
                            self.fooverlaps[base + symoffset + j, base + symoffset + i] = k
                            self.fooverlaps[base + symoffset + i, base + symoffset + j] = k

                    #blank, blank, column
                    for i in range(3):
                        next(inputfile)

                    base += 4

                symoffset += nosymrep
                base = 0

# The commented code below makes the atombasis attribute based on the BAS function in ADF,
#   but this is probably not so useful, since SFOs are used to build MOs in ADF.
#        if line[1:54] == "BAS: List of all Elementary Cartesian Basis Functions":
#
#            self.atombasis = []
#
#            # There will be some text, followed by a line:
#            #       (power of) X  Y  Z  R     Alpha  on Atom
#            while not line[1:11] == "(power of)":
#                line = inputfile.next()
#            dashes = inputfile.next()
#            blank = inputfile.next()
#            line = inputfile.next()
#            # There will be two blank lines when there are no more atom types.
#            while line.strip() != "":
#                atoms = [int(i)-1 for i in line.split()[1:]]
#                for n in range(len(atoms)):
#                    self.atombasis.append([])
#                dashes = inputfile.next()
#                line = inputfile.next()
#                while line.strip() != "":
#                    indices = [int(i)-1 for i in line.split()[5:]]
#                    for i in range(len(indices)):
#                        self.atombasis[atoms[i]].append(indices[i])
#                    line = inputfile.next()
#                line = inputfile.next()

        if line[48:67] == "SFO MO coefficients":

            self.mocoeffs = [numpy.zeros((self.nbasis, self.nbasis), "d")]
            spin = 0
            symoffset = 0
            lastrow = 0

            # Section ends with "1" at beggining of a line.
            while line[0] != "1":
                line = next(inputfile)

                # If spin is specified, then there will be two coefficient matrices.
                if line.strip() == "***** SPIN 1 *****":
                    self.mocoeffs = [numpy.zeros((self.nbasis, self.nbasis), "d"),
                                     numpy.zeros((self.nbasis, self.nbasis), "d")]

                # Bump up the spin.
                if line.strip() == "***** SPIN 2 *****":
                    spin = 1
                    symoffset = 0
                    lastrow = 0

                # Next symmetry.
                if line.strip()[:4] == "=== ":
                    sym = line.split()[1]
                    if self.nosymflag:
                        aolist = list(range(self.nbasis))
                    else:
                        aolist = self.symlist[sym][spin]
                    # Add to the symmetry offset of AO ordering.
                    symoffset += lastrow

                # Blocks with coefficient always start with "MOs :".
                if line[1:6] == "MOs :":
                    # Next line has the MO index contributed to.
                    monumbers = [int(n) for n in line[6:].split()]

                    self.skip_lines(inputfile, ['occup', 'label'])

                    # The table can end with a blank line or "1".
                    row = 0
                    line = next(inputfile)
                    while not line.strip() in ["", "1"]:
                        info = line.split()

                        if int(info[0]) < self.start_indeces[sym]:
                        #check to make sure we aren't parsing CFs
                            line = next(inputfile)
                            continue

                        self.updateprogress(inputfile, "Coefficients", self.fupdate)
                        row += 1
                        coeffs = [float(x) for x in info[1:]]
                        moindices = [aolist[n-1] for n in monumbers]
                        # The AO index is 1 less than the row.
                        aoindex = symoffset + row - 1
                        for i in range(len(monumbers)):
                            self.mocoeffs[spin][moindices[i], aoindex] = coeffs[i]
                        line = next(inputfile)
                    lastrow = row

        # **************************************************************************
        # *                                                                        *
        # *   Final excitation energies from Davidson algorithm                    *
        # *                                                                        *
        # **************************************************************************
        #
        #     Number of loops in Davidson routine     =   20
        #     Number of matrix-vector multiplications =   24
        #     Type of excitations = SINGLET-SINGLET
        #
        # Symmetry B.u
        #
        # ... several blocks ...
        #
        # Normal termination of EXCITATION program part
        if line[4:53] == "Final excitation energies from Davidson algorithm":

            while line[1:9] != "Symmetry" and "Normal termination" not in line:
                line = next(inputfile)
            symm = self.normalisesym(line.split()[1])

            # Excitation energies E in a.u. and eV, dE wrt prev. cycle,
            # oscillator strengths f in a.u.
            #
            # no.  E/a.u.        E/eV      f           dE/a.u.
            # -----------------------------------------------------
            #   1 0.17084      4.6488     0.16526E-01  0.28E-08
            # ...
            while line.split() != ['no.', 'E/a.u.', 'E/eV', 'f', 'dE/a.u.'] and "Normal termination" not in line:
                line = next(inputfile)

            self.skip_line(inputfile, 'dashes')

            etenergies = []
            etoscs = []
            etsyms = []
            line = next(inputfile)
            while len(line) > 2:
                info = line.split()
                etenergies.append(utils.convertor(float(info[2]), "eV", "cm-1"))
                etoscs.append(float(info[3]))
                etsyms.append(symm)
                line = next(inputfile)

            # There is another section before this, with transition dipole moments,
            # but this should just skip past it.
            while line[1:53] != "Major MO -> MO transitions for the above excitations":
                line = next(inputfile)

            # Note that here, and later, the number of blank lines can vary between
            # version of ADF (extra lines are seen in 2013.01 unit tests, for example).
            self.skip_line(inputfile, 'blank')
            excitation_occupied = next(inputfile)
            header = next(inputfile)
            while not header.strip():
                header = next(inputfile)
            header2 = next(inputfile)
            x_y_z = next(inputfile)
            line = next(inputfile)
            while not line.strip():
                line = next(inputfile)

            # Before we start handeling transitions, we need to create mosyms
            # with indices; only restricted calcs are possible in ADF.
            counts = {}
            syms = []
            for mosym in self.mosyms[0]:
                if list(counts.keys()).count(mosym) == 0:
                    counts[mosym] = 1
                else:
                    counts[mosym] += 1
                syms.append(str(counts[mosym]) + mosym)

            etsecs = []
            printed_warning = False
            for i in range(len(etenergies)):

                etsec = []
                info = line.split()
                while len(info) > 0:

                    match = re.search('[^0-9]', info[1])
                    index1 = int(info[1][:match.start(0)])
                    text = info[1][match.start(0):]
                    symtext = text[0].upper() + text[1:]
                    sym1 = str(index1) + self.normalisesym(symtext)

                    match = re.search('[^0-9]', info[3])
                    index2 = int(info[3][:match.start(0)])
                    text = info[3][match.start(0):]
                    symtext = text[0].upper() + text[1:]
                    sym2 = str(index2) + self.normalisesym(symtext)

                    try:
                        index1 = syms.index(sym1)
                    except ValueError:
                        if not printed_warning:
                            self.logger.warning("Etsecs are not accurate!")
                            printed_warning = True

                    try:
                        index2 = syms.index(sym2)
                    except ValueError:
                        if not printed_warning:
                            self.logger.warning("Etsecs are not accurate!")
                            printed_warning = True

                    etsec.append([(index1, 0), (index2, 0), float(info[4])])

                    line = next(inputfile)
                    info = line.split()

                etsecs.append(etsec)

                # Again, the number of blank lines between transition can vary.
                line = next(inputfile)
                while not line.strip():
                    line = next(inputfile)

            if not hasattr(self, "etenergies"):
                self.etenergies = etenergies
            else:
                self.etenergies += etenergies

            if not hasattr(self, "etoscs"):
                self.etoscs = etoscs
            else:
                self.etoscs += etoscs

            if not hasattr(self, "etsyms"):
                self.etsyms = etsyms
            else:
                self.etsyms += etsyms

            if not hasattr(self, "etsecs"):
                self.etsecs = etsecs
            else:
                self.etsecs += etsecs

        if "M U L L I K E N   P O P U L A T I O N S" in line:
            if not hasattr(self, "atomcharges"):
                self.atomcharges = {}
            while line[1:5] != "Atom":
                line = next(inputfile)
            self.skip_line(inputfile, 'dashes')
            mulliken = []
            line = next(inputfile)
            while line.strip():
                mulliken.append(float(line.split()[2]))
                line = next(inputfile)
            self.atomcharges["mulliken"] = mulliken

        # Dipole moment is always printed after a point calculation,
        # and the reference point for this is always the origin (0,0,0)
        # and not necessarily the center of mass, as explained on the
        # ADF user mailing list (see cclib/cclib#113 for details).
        #
        # =============
        # Dipole Moment  ***  (Debye)  ***
        # =============
        #
        # Vector   :         0.00000000      0.00000000      0.00000000
        # Magnitude:         0.00000000
        #
        if line.strip()[:13] == "Dipole Moment":

            self.skip_line(inputfile, 'equals')

            # There is not always a blank line here, for example when the dipole and quadrupole
            # moments are printed after the multipole derived atomic charges. Still, to the best
            # of my knowledge (KML) the values are still in Debye.
            line = next(inputfile)
            if not line.strip():
                line = next(inputfile)

            assert line.split()[0] == "Vector"
            dipole = [float(d) for d in line.split()[-3:]]

            reference = [0.0, 0.0, 0.0]
            if not hasattr(self, 'moments'):
                self.moments = [reference, dipole]
            else:
                try:
                    assert self.moments[1] == dipole
                except AssertionError:
                    self.logger.warning('Overwriting previous multipole moments with new values')
                    self.moments = [reference, dipole]


if __name__ == "__main__":
    import doctest, adfparser
    doctest.testmod(adfparser, verbose=False)
