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

"""Parser for GAMESS-UK output files"""

import numpy
import re

from . import logfileparser
from . import utils


class GAMESSUK(logfileparser.Logfile):
    """A GAMESS UK log file"""
    SCFRMS, SCFMAX, SCFENERGY = list(range(3))  # Used to index self.scftargets[]

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(GAMESSUK, self).__init__(logname="GAMESSUK", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "GAMESS UK log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'GAMESSUK("%s")' % (self.filename)

    def normalisesym(self, label):
        """Use standard symmetry labels instead of GAMESS UK labels.

        >>> t = GAMESSUK("dummyfile.txt")
        >>> labels = ['a', 'a1', 'ag', "a'", 'a"', "a''", "a1''", 'a1"']
        >>> labels.extend(["e1+", "e1-"])
        >>> answer = [t.normalisesym(x) for x in labels]
        >>> answer
        ['A', 'A1', 'Ag', "A'", 'A"', 'A"', 'A1"', 'A1"', 'E1', 'E1']
        """
        label = label.replace("''", '"').replace("+", "").replace("-", "")
        ans = label[0].upper() + label[1:]

        return ans

    def before_parsing(self):

        # used for determining whether to add a second mosyms, etc.
        self.betamosyms = self.betamoenergies = self.betamocoeffs = False

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        if line[1:22] == "total number of atoms":
            natom = int(line.split()[-1])
            self.set_attribute('natom', natom)

        if line[3:44] == "convergence threshold in optimization run":
            # Assuming that this is only found in the case of OPTXYZ
            # (i.e. an optimization in Cartesian coordinates)
            self.geotargets = [float(line.split()[-2])]

        if line[32:61] == "largest component of gradient":
            # This is the geotarget in the case of OPTXYZ
            if not hasattr(self, "geovalues"):
                self.geovalues = []
            self.geovalues.append([float(line.split()[4])])

        if line[37:49] == "convergence?":
            # Get the geovalues and geotargets for OPTIMIZE
            if not hasattr(self, "geovalues"):
                self.geovalues = []
                self.geotargets = []
            geotargets = []
            geovalues = []
            for i in range(4):
                temp = line.split()
                geovalues.append(float(temp[2]))
                if not self.geotargets:
                    geotargets.append(float(temp[-2]))
                line = next(inputfile)
            self.geovalues.append(geovalues)
            if not self.geotargets:
                self.geotargets = geotargets

        # This is the only place coordinates are printed in single point calculations. Note that
        # in the following fragment, the basis set selection is not always printed:
        #
        #                                        ******************
        #                                        molecular geometry
        #                                        ******************
        #
        # ****************************************
        # * basis selected is sto     sto3g      *
        # ****************************************
        #
        #         *******************************************************************************
        #         *                                                                             *
        #         *     atom   atomic                coordinates                 number of      *
        #         *            charge       x             y              z       shells         *
        #         *                                                                             *
        #         *******************************************************************************
        #         *                                                                             *
        #         *                                                                             *
        #         *    c         6.0   0.0000000     -2.6361501      0.0000000       2          *
        #         *                                                                1s  2sp      *
        #         *                                                                             *
        #         *                                                                             *
        #         *    c         6.0   0.0000000      2.6361501      0.0000000       2          *
        #         *                                                                1s  2sp      *
        #         *                                                                             *
        # ...
        #
        if line.strip() == "molecular geometry":

            self.updateprogress(inputfile, "Coordinates")

            self.skip_lines(inputfile, ['s', 'b', 's'])
            line = next(inputfile)
            if "basis selected is" in line:
                self.skip_lines(inputfile, ['s', 'b', 's', 's'])

            self.skip_lines(inputfile, ['header1', 'header2', 's', 's'])

            atomnos = []
            atomcoords = []
            line = next(inputfile)
            while line.strip():
                line = next(inputfile)
                if line.strip()[1:10].strip() and list(set(line.strip())) != ['*']:
                    atomcoords.append([utils.convertor(float(x), "bohr", "Angstrom") for x in line.split()[3:6]])
                    atomnos.append(int(round(float(line.split()[2]))))

            if not hasattr(self, "atomcoords"):
                self.atomcoords = []
            self.atomcoords.append(atomcoords)
            self.set_attribute('atomnos', atomnos)

        # Each step of a geometry optimization will also print the coordinates:
        #
        # search  0
        #                                        *******************
        # point   0                              nuclear coordinates
        #                                        *******************
        #
        #         x              y              z            chg  tag
        #  ============================================================
        #        0.0000000     -2.6361501      0.0000000    6.00  c
        #        0.0000000      2.6361501      0.0000000    6.00  c
        # ..
        #
        if line[40:59] == "nuclear coordinates":

            self.updateprogress(inputfile, "Coordinates")

            # We need not remember the first geometry in geometry optimizations, as this will
            # be already parsed from the "molecular geometry" section (see above).
            if not hasattr(self, 'firstnuccoords') or self.firstnuccoords:
                self.firstnuccoords = False
                return

            self.skip_lines(inputfile, ['s', 'b', 'colname', 'e'])

            atomcoords = []
            atomnos = []
            line = next(inputfile)
            while list(set(line.strip())) != ['=']:

                cols = line.split()
                atomcoords.append([utils.convertor(float(x), "bohr", "Angstrom") for x in cols[0:3]])
                atomnos.append(int(float(cols[3])))

                line = next(inputfile)

            if not hasattr(self, "atomcoords"):
                self.atomcoords = []
            self.atomcoords.append(atomcoords)
            self.set_attribute('atomnos', atomnos)

        # This is printed when a geometry optimization succeeds, after the last gradient of the energy.
        if line[40:62] == "optimization converged":
            self.skip_line(inputfile, 's')
            if not hasattr(self, 'optdone'):
                self.optdone = []
            self.optdone.append(len(self.geovalues)-1)

        # This is apparently printed when a geometry optimization is not converged but the job ends.
        if "minimisation not converging" in line:
            self.skip_line(inputfile, 's')
            self.optdone = []

        if line[1:32] == "total number of basis functions":

            nbasis = int(line.split()[-1])
            self.set_attribute('nbasis', nbasis)

            while line.find("charge of molecule") < 0:
                line = next(inputfile)

            charge = int(line.split()[-1])
            self.set_attribute('charge', charge)

            mult = int(next(inputfile).split()[-1])
            self.set_attribute('mult', mult)

            alpha = int(next(inputfile).split()[-1])-1
            beta = int(next(inputfile).split()[-1])-1
            if self.mult == 1:
                self.homos = numpy.array([alpha], "i")
            else:
                self.homos = numpy.array([alpha, beta], "i")

        if line[37:69] == "s-matrix over gaussian basis set":
            self.aooverlaps = numpy.zeros((self.nbasis, self.nbasis), "d")

            self.skip_lines(inputfile, ['d', 'b'])

            i = 0
            while i < self.nbasis:
                self.updateprogress(inputfile, "Overlap")

                self.skip_lines(inputfile, ['b', 'b', 'header', 'b', 'b'])

                for j in range(self.nbasis):
                    temp = list(map(float, next(inputfile).split()[1:]))
                    self.aooverlaps[j, (0+i):(len(temp)+i)] = temp

                i += len(temp)

        if line[18:43] == 'EFFECTIVE CORE POTENTIALS':

            self.skip_line(inputfile, 'stars')

            self.coreelectrons = numpy.zeros(self.natom, 'i')
            line = next(inputfile)
            while line[15:46] != "*"*31:
                if line.find("for atoms ...") >= 0:
                    atomindex = []
                    line = next(inputfile)
                    while line.find("core charge") < 0:
                        broken = line.split()
                        atomindex.extend([int(x.split("-")[0]) for x in broken])
                        line = next(inputfile)
                    charge = float(line.split()[4])
                    for idx in atomindex:
                        self.coreelectrons[idx-1] = self.atomnos[idx-1] - charge
                line = next(inputfile)

        if line[3:27] == "Wavefunction convergence":
            self.scftarget = float(line.split()[-2])
            self.scftargets = []

        if line[11:22] == "normal mode":
            if not hasattr(self, "vibfreqs"):
                self.vibfreqs = []
                self.vibirs = []

            units = next(inputfile)
            xyz = next(inputfile)
            equals = next(inputfile)
            line = next(inputfile)
            while line != equals:
                temp = line.split()
                self.vibfreqs.append(float(temp[1]))
                self.vibirs.append(float(temp[-2]))
                line = next(inputfile)
            # Use the length of the vibdisps to figure out
            # how many rotations and translations to remove
            self.vibfreqs = self.vibfreqs[-len(self.vibdisps):]
            self.vibirs = self.vibirs[-len(self.vibdisps):]

        if line[44:73] == "normalised normal coordinates":

            self.skip_lines(inputfile, ['e', 'b', 'b'])

            self.vibdisps = []
            freqnum = next(inputfile)
            while freqnum.find("=") < 0:

                self.skip_lines(inputfile, ['b', 'e', 'freqs', 'e', 'b', 'header', 'e'])

                p = [[] for x in range(9)]
                for i in range(len(self.atomnos)):
                    brokenx = list(map(float, next(inputfile)[25:].split()))
                    brokeny = list(map(float, next(inputfile)[25:].split()))
                    brokenz = list(map(float, next(inputfile)[25:].split()))
                    for j, x in enumerate(list(zip(brokenx, brokeny, brokenz))):
                        p[j].append(x)
                self.vibdisps.extend(p)

                self.skip_lines(inputfile, ['b', 'b'])

                freqnum = next(inputfile)

        if line[26:36] == "raman data":
            self.vibramans = []

            self.skip_lines(inputfile, ['s', 'b', 'header', 'b'])

            line = next(inputfile)
            while line[1] != "*":
                self.vibramans.append(float(line.split()[3]))
                self.skip_line(inputfile, 'blank')
                line = next(inputfile)
            # Use the length of the vibdisps to figure out
            # how many rotations and translations to remove
            self.vibramans = self.vibramans[-len(self.vibdisps):]

        if line[3:11] == "SCF TYPE":
            self.scftype = line.split()[-2]
            assert self.scftype in ['rhf', 'uhf', 'gvb'], "%s not one of 'rhf', 'uhf' or 'gvb'" % self.scftype

        if line[15:31] == "convergence data":
            if not hasattr(self, "scfvalues"):
                self.scfvalues = []
            self.scftargets.append([self.scftarget])  # Assuming it does not change over time
            while line[1:10] != "="*9:
                line = next(inputfile)
            line = next(inputfile)
            tester = line.find("tester")  # Can be in a different place depending
            assert tester >= 0
            while line[1:10] != "="*9:  # May be two or three lines (unres)
                line = next(inputfile)

            scfvalues = []
            line = next(inputfile)
            while line.strip():
                # e.g. **** recalulation of fock matrix on iteration  4 (examples/chap12/pyridine.out)
                if line[2:6] != "****":
                    scfvalues.append([float(line[tester-5:tester+6])])
                try:
                    line = next(inputfile)
                except StopIteration:
                    self.logger.warning('File terminated before end of last SCF! Last tester: {}'.format(line.split()[5]))
                    break
            self.scfvalues.append(scfvalues)

        if line[10:22] == "total energy" and len(line.split()) == 3:
            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            scfenergy = utils.convertor(float(line.split()[-1]), "hartree", "eV")
            self.scfenergies.append(scfenergy)

        # Total energies after Moller-Plesset corrections
        # Second order correction is always first, so its first occurance
        #   triggers creation of mpenergies (list of lists of energies)
        # Further corrections are appended as found
        # Note: GAMESS-UK sometimes prints only the corrections,
        #   so they must be added to the last value of scfenergies
        if line[10:32] == "mp2 correlation energy" or \
           line[10:42] == "second order perturbation energy":
            if not hasattr(self, "mpenergies"):
                self.mpenergies = []
            self.mpenergies.append([])
            self.mp2correction = self.float(line.split()[-1])
            self.mp2energy = self.scfenergies[-1] + self.mp2correction
            self.mpenergies[-1].append(utils.convertor(self.mp2energy, "hartree", "eV"))
        if line[10:41] == "third order perturbation energy":
            self.mp3correction = self.float(line.split()[-1])
            self.mp3energy = self.mp2energy + self.mp3correction
            self.mpenergies[-1].append(utils.convertor(self.mp3energy, "hartree", "eV"))

        if line[40:59] == "molecular basis set":
            self.gbasis = []
            line = next(inputfile)
            while line.find("contraction coefficients") < 0:
                line = next(inputfile)
            equals = next(inputfile)
            blank = next(inputfile)
            atomname = next(inputfile)
            basisregexp = re.compile("\d*(\D+)")  # Get everything after any digits
            shellcounter = 1
            while line != equals:
                gbasis = []  # Stores basis sets on one atom
                blank = next(inputfile)
                blank = next(inputfile)
                line = next(inputfile)
                shellno = int(line.split()[0])
                shellgap = shellno - shellcounter
                shellsize = 0
                while len(line.split()) != 1 and line != equals:
                    if line.split():
                        shellsize += 1
                    coeff = {}
                    # coefficients and symmetries for a block of rows
                    while line.strip() and line != equals:
                        temp = line.strip().split()
                    # temp[1] may be either like (a) "1s" and "1sp", or (b) "s" and "sp"
                    # See GAMESS-UK 7.0 distribution/examples/chap12/pyridine2_21m10r.out
                    # for an example of the latter
                        sym = basisregexp.match(temp[1]).groups()[0]
                        assert sym in ['s', 'p', 'd', 'f', 'sp'], "'%s' not a recognized symmetry" % sym
                        if sym == "sp":
                            coeff.setdefault("S", []).append((float(temp[3]), float(temp[6])))
                            coeff.setdefault("P", []).append((float(temp[3]), float(temp[10])))
                        else:
                            coeff.setdefault(sym.upper(), []).append((float(temp[3]), float(temp[6])))
                        line = next(inputfile)
                    # either a blank or a continuation of the block
                    if coeff:
                        if sym == "sp":
                            gbasis.append(('S', coeff['S']))
                            gbasis.append(('P', coeff['P']))
                        else:
                            gbasis.append((sym.upper(), coeff[sym.upper()]))
                    if line == equals:
                        continue
                    line = next(inputfile)
                    # either the start of the next block or the start of a new atom or
                    # the end of the basis function section (signified by a line of equals)
                numtoadd = 1 + (shellgap // shellsize)
                shellcounter = shellno + shellsize
                for x in range(numtoadd):
                    self.gbasis.append(gbasis)

        if line[50:70] == "----- beta set -----":
            self.betamosyms = True
            self.betamoenergies = True
            self.betamocoeffs = True
            # betamosyms will be turned off in the next
            # SYMMETRY ASSIGNMENT section

        if line[31:50] == "SYMMETRY ASSIGNMENT":
            if not hasattr(self, "mosyms"):
                self.mosyms = []

            multiple = {'a': 1, 'b': 1, 'e': 2, 't': 3, 'g': 4, 'h': 5}

            equals = next(inputfile)
            line = next(inputfile)
            while line != equals:  # There may be one or two lines of title (compare mg10.out and duhf_1.out)
                line = next(inputfile)

            mosyms = []
            line = next(inputfile)
            while line != equals:
                temp = line[25:30].strip()
                if temp[-1] == '?':
                    # e.g. e? or t? or g? (see example/chap12/na7mg_uhf.out)
                    # for two As, an A and an E, and two Es of the same energy respectively.
                    t = line[91:].strip().split()
                    for i in range(1, len(t), 2):
                        for j in range(multiple[t[i][0]]):  # add twice for 'e', etc.
                            mosyms.append(self.normalisesym(t[i]))
                else:
                    for j in range(multiple[temp[0]]):
                        mosyms.append(self.normalisesym(temp))  # add twice for 'e', etc.
                line = next(inputfile)
            assert len(mosyms) == self.nmo, "mosyms: %d but nmo: %d" % (len(mosyms), self.nmo)
            if self.betamosyms:
                # Only append if beta (otherwise with IPRINT SCF
                # it will add mosyms for every step of a geo opt)
                self.mosyms.append(mosyms)
                self.betamosyms = False
            elif self.scftype == 'gvb':
                # gvb has alpha and beta orbitals but they are identical
                self.mosysms = [mosyms, mosyms]
            else:
                self.mosyms = [mosyms]

        if line[50:62] == "eigenvectors":
        # Mocoeffs...can get evalues from here too
        # (only if using FORMAT HIGH though will they all be present)
            if not hasattr(self, "mocoeffs"):
                self.aonames = []
                aonames = []
            minus = next(inputfile)

            mocoeffs = numpy.zeros((self.nmo, self.nbasis), "d")
            readatombasis = False
            if not hasattr(self, "atombasis"):
                self.atombasis = []
                for i in range(self.natom):
                    self.atombasis.append([])
                readatombasis = True

            self.skip_lines(inputfile, ['b', 'b', 'evalues'])

            p = re.compile(r"\d+\s+(\d+)\s*(\w+) (\w+)")
            oldatomname = "DUMMY VALUE"

            mo = 0
            while mo < self.nmo:
                self.updateprogress(inputfile, "Coefficients")

                self.skip_lines(inputfile, ['b', 'b', 'nums', 'b', 'b'])

                for basis in range(self.nbasis):
                    line = next(inputfile)
                    # Fill atombasis only first time around.
                    if readatombasis:
                        orbno = int(line[1:5])-1
                        atomno = int(line[6:9])-1
                        self.atombasis[atomno].append(orbno)
                    if not self.aonames:
                        pg = p.match(line[:18].strip()).groups()
                        atomname = "%s%s%s" % (pg[1][0].upper(), pg[1][1:], pg[0])
                        if atomname != oldatomname:
                            aonum = 1
                        oldatomname = atomname
                        name = "%s_%d%s" % (atomname, aonum, pg[2].upper())
                        if name in aonames:
                            aonum += 1
                        name = "%s_%d%s" % (atomname, aonum, pg[2].upper())
                        aonames.append(name)
                    temp = list(map(float, line[19:].split()))
                    mocoeffs[mo:(mo+len(temp)), basis] = temp
                # Fill atombasis only first time around.
                readatombasis = False
                if not self.aonames:
                    self.aonames = aonames

                line = next(inputfile)  # blank line
                while not line.strip():
                    line = next(inputfile)
                evalues = line
                if evalues[:17].strip():  # i.e. if these aren't evalues
                    break  # Not all the MOs are present
                mo += len(temp)
            mocoeffs = mocoeffs[0:(mo+len(temp)), :]  # In case some aren't present
            if self.betamocoeffs:
                self.mocoeffs.append(mocoeffs)
            else:
                self.mocoeffs = [mocoeffs]

        if line[7:12] == "irrep":
            ########## eigenvalues ###########
            # This section appears once at the start of a geo-opt and once at the end
            # unless IPRINT SCF is used (when it appears at every step in addition)
            if not hasattr(self, "moenergies"):
                self.moenergies = []

            equals = next(inputfile)
            while equals[1:5] != "====":  # May be one or two lines of title (compare duhf_1.out and mg10.out)
                equals = next(inputfile)

            moenergies = []
            line = next(inputfile)
            if not line.strip():  # May be a blank line here (compare duhf_1.out and mg10.out)
                line = next(inputfile)

            while line.strip() and line != equals:  # May end with a blank or equals
                temp = line.strip().split()
                moenergies.append(utils.convertor(float(temp[2]), "hartree", "eV"))
                line = next(inputfile)
            self.nmo = len(moenergies)
            if self.betamoenergies:
                self.moenergies.append(moenergies)
                self.betamoenergies = False
            elif self.scftype == 'gvb':
                self.moenergies = [moenergies, moenergies]
            else:
                self.moenergies = [moenergies]

        # The dipole moment is printed by default at the beginning of the wavefunction analysis,
        # but the value is in atomic units, so we need to convert to Debye. It seems pretty
        # evident that the reference point is the origin (0,0,0) which is also the center
        # of mass after reorientation at the beginning of the job, although this is not
        # stated anywhere (would be good to check).
        #
        #                                        *********************
        #                                        wavefunction analysis
        #                                        *********************
        #
        # commence analysis at     24.61 seconds
        #
        #                 dipole moments
        #
        #
        #           nuclear      electronic           total
        #
        # x       0.0000000       0.0000000       0.0000000
        # y       0.0000000       0.0000000       0.0000000
        # z       0.0000000       0.0000000       0.0000000
        #
        if line.strip() == "dipole moments":

            # In older version there is only one blank line before the header,
            # and newer version there are two.
            self.skip_line(inputfile, 'blank')
            line = next(inputfile)
            if not line.strip():
                line = next(inputfile)
            self.skip_line(inputfile, 'blank')

            dipole = []
            for i in range(3):
                line = next(inputfile)
                dipole.append(float(line.split()[-1]))

            reference = [0.0, 0.0, 0.0]
            dipole = utils.convertor(numpy.array(dipole), "ebohr", "Debye")

            if not hasattr(self, 'moments'):
                self.moments = [reference, dipole]
            else:
                assert self.moments[1] == dipole

        # Net atomic charges are not printed at all, it seems,
        # but you can get at them from nuclear charges and
        # electron populations, which are printed like so:
        #
        #  ---------------------------------------
        #  mulliken and lowdin population analyses
        #  ---------------------------------------
        #
        # ----- total gross population in aos ------
        #
        # 1  1  c s         1.99066     1.98479
        # 2  1  c s         1.14685     1.04816
        # ...
        #
        #  ----- total gross population on atoms ----
        #
        # 1  c            6.0     6.00446     5.99625
        # 2  c            6.0     6.00446     5.99625
        # 3  c            6.0     6.07671     6.04399
        # ...
        if line[10:49] == "mulliken and lowdin population analyses":

            if not hasattr(self, "atomcharges"):
                self.atomcharges = {}

            while not "total gross population on atoms" in line:
                line = next(inputfile)

            self.skip_line(inputfile, 'blank')

            line = next(inputfile)
            mulliken, lowdin = [], []
            while line.strip():
                nuclear = float(line.split()[2])
                mulliken.append(nuclear - float(line.split()[3]))
                lowdin.append(nuclear - float(line.split()[4]))
                line = next(inputfile)

            self.atomcharges["mulliken"] = mulliken
            self.atomcharges["lowdin"] = lowdin

        #          ----- spinfree UHF natural orbital occupations -----
        #
        #               2.0000000     2.0000000     2.0000000     2.0000000     2.0000000     2.0000000     2.0000000
        #
        #               2.0000000     2.0000000     2.0000000     2.0000000     2.0000000     1.9999997     1.9999997
        # ...
        if "natural orbital occupations" in line:

            occupations = []

            self.skip_line(inputfile, "blank")
            line = inputfile.next()

            while line.strip():
                occupations += map(float, line.split())

                self.skip_line(inputfile, "blank")
                line = inputfile.next()

            self.set_attribute('nooccnos', occupations)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
