# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2007-2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Parser for Molpro output files"""

import itertools
import numpy

from . import logfileparser
from . import utils


def create_atomic_orbital_names(orbitals):
    """Generate all atomic orbital names that could be used by Molpro.

    The names are returned in a dictionary, organized by subshell (S, P, D and so on).
    """

    # We can write out the first two manually, since there are not that many.
    atomic_orbital_names = {
        'S': ['s', '1s'],
        'P': ['x', 'y', 'z', '2px', '2py', '2pz'],
    }

    # Although we could write out all names for the other subshells, it is better
    # to generate them if we need to expand further, since the number of functions quickly
    # grows and there are both Cartesian and spherical variants to consider.
    # For D orbitals, the Cartesian functions are xx, yy, zz, xy, xz and yz, and the
    # spherical ones are called 3d0, 3d1-, 3d1+, 3d2- and 3d2+. For F orbitals, the Cartesians
    # are xxx, xxy, xxz, xyy, ... and the sphericals are 4f0, 4f1-, 4f+ and so on.
    for i, orb in enumerate(orbitals):

        # Cartesian can be generated directly by combinations.
        cartesian = list(map(''.join, list(itertools.combinations_with_replacement(['x', 'y', 'z'], i+2))))

        # For spherical functions, we need to construct the names.
        pre = str(i+3) + orb.lower()
        spherical = [pre + '0'] + [pre + str(j) + s for j in range(1, i+3) for s in ['-', '+']]
        atomic_orbital_names[orb] = cartesian + spherical

    return atomic_orbital_names


class Molpro(logfileparser.Logfile):
    """Molpro file parser"""

    atomic_orbital_names = create_atomic_orbital_names(['D', 'F', 'G'])

    def __init__(self, *args, **kwargs):
        # Call the __init__ method of the superclass
        super(Molpro, self).__init__(logname="Molpro", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "Molpro log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'Molpro("%s")' % (self.filename)

    def normalisesym(self, label):
        """Normalise the symmetries used by Molpro."""
        ans = label.replace("`", "'").replace("``", "''")
        return ans

    def before_parsing(self):

        self.electronorbitals = ""
        self.insidescf = False

    def after_parsing(self):

        # If optimization thresholds are default, they are normally not printed and we need
        # to set them to the default after parsing. Make sure to set them in the same order that
        # they appear in the in the geometry optimization progress printed in the output,
        # namely: energy difference, maximum gradient, maximum step.
        if not hasattr(self, "geotargets"):
            self.geotargets = []
            # Default THRENERG (required accuracy of the optimized energy).
            self.geotargets.append(1E-6)
            # Default THRGRAD (required accuracy of the optimized gradient).
            self.geotargets.append(3E-4)
            # Default THRSTEP (convergence threshold for the geometry optimization step).
            self.geotargets.append(3E-4)

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        if line[1:19] == "ATOMIC COORDINATES":

            if not hasattr(self, "atomcoords"):
                self.atomcoords = []

            atomcoords = []
            atomnos = []

            self.skip_lines(inputfile, ['line', 'line', 'line'])

            line = next(inputfile)
            while line.strip():
                temp = line.strip().split()
                atomcoords.append([utils.convertor(float(x), "bohr", "Angstrom") for x in temp[3:6]])  # bohrs to angs
                atomnos.append(int(round(float(temp[2]))))
                line = next(inputfile)

            self.atomcoords.append(atomcoords)

            self.set_attribute('atomnos', atomnos)
            self.set_attribute('natom', len(self.atomnos))

        # Use BASIS DATA to parse input for gbasis, aonames and atombasis. If symmetry is used,
        # the function number starts from 1 for each irrep (the irrep index comes after the dot).
        #
        # BASIS DATA
        #
        #   Nr Sym  Nuc  Type         Exponents   Contraction coefficients
        #
        #   1.1 A     1  1s           71.616837     0.154329
        #                             13.045096     0.535328
        #                              3.530512     0.444635
        #   2.1 A     1  1s            2.941249    -0.099967
        #                              0.683483     0.399513
        # ...
        #
        if line[1:11] == "BASIS DATA":

            # We can do a sanity check with the header.
            self.skip_line(inputfile, 'blank')
            header = next(inputfile)
            assert header.split() == ["Nr", "Sym", "Nuc", "Type", "Exponents", "Contraction", "coefficients"]
            self.skip_line(inputfile, 'blank')

            aonames = []
            atombasis = [[] for i in range(self.natom)]
            gbasis = [[] for i in range(self.natom)]
            while line.strip():

                # We need to read the line at the start of the loop here, because the last function
                # will be added when a blank line signalling the end of the block is encountered.
                line = next(inputfile)

                # The formatting here can exhibit subtle differences, including the number of spaces
                # or indentation size. However, we will rely on explicit slices since not all components
                # are always available. In fact, components not being there has some meaning (see below).
                line_nr = line[1:6].strip()
                line_sym = line[7:9].strip()
                line_nuc = line[11:15].strip()
                line_type = line[16:22].strip()
                line_exp = line[25:38].strip()
                line_coeffs = line[38:].strip()

                # If a new function type is printed or the BASIS DATA block ends with a blank line,
                # then add the previous function to gbasis, except for the first function since
                # there was no preceeding one. When translating the Molpro function name to gbasis,
                # note that Molpro prints all components, but we want it only once, with the proper
                # shell type (S,P,D,F,G). Molpro names also differ between Cartesian/spherical representations.
                if (line_type and aonames) or line.strip() == "":

                    # All the possible AO names are created with the class. The function should always
                    # find a match in that dictionary, so we can check for that here and will need to
                    # update the dict if something unexpected comes up.
                    funcbasis = None
                    for fb, names in self.atomic_orbital_names.items():
                        if functype in names:
                            funcbasis = fb
                    assert funcbasis

                    # There is a separate basis function for each column of contraction coefficients. Since all
                    # atomic orbitals for a subshell will have the same parameters, we can simply check if
                    # the function tuple is already in gbasis[i] before adding it.
                    for i in range(len(coefficients[0])):

                        func = (funcbasis, [])
                        for j in range(len(exponents)):
                            func[1].append((exponents[j], coefficients[j][i]))
                        if func not in gbasis[funcatom-1]:
                            gbasis[funcatom-1].append(func)

                # If it is a new type, set up the variables for the next shell(s). An exception is symmetry functions,
                # which we want to copy from the previous function and don't have a new number on the line. For them,
                # we just want to update the nuclear index.
                if line_type:
                    if line_nr:
                        exponents = []
                        coefficients = []
                        functype = line_type
                    funcatom = int(line_nuc)

                # Add any exponents and coefficients to lists.
                if line_exp and line_coeffs:
                    funcexp = float(line_exp)
                    funccoeffs = [float(s) for s in line_coeffs.split()]
                    exponents.append(funcexp)
                    coefficients.append(funccoeffs)

                # If the function number is present then add to atombasis and aonames, which is different from
                # adding to gbasis since it enumerates AOs rather than basis functions. The number counts functions
                # in each irrep from 1 and we could add up the functions for each irrep to get the global count,
                # but it is simpler to just see how many aonames we have already parsed. Any symmetry functions
                # are also printed, but they don't get numbers so they are nor parsed.
                if line_nr:
                    element = self.table.element[self.atomnos[funcatom-1]]
                    aoname = "%s%i_%s" % (element, funcatom, functype)
                    aonames.append(aoname)
                    funcnr = len(aonames)
                    atombasis[funcatom-1].append(funcnr-1)

            self.set_attribute('aonames', aonames)
            self.set_attribute('atombasis', atombasis)
            self.set_attribute('gbasis', gbasis)

        if line[1:23] == "NUMBER OF CONTRACTIONS":
            nbasis = int(line.split()[3])
            self.set_attribute('nbasis', nbasis)

        # This is used to signalize whether we are inside an SCF calculation.
        if line[1:8] == "PROGRAM" and line[14:18] == "-SCF":

            self.insidescf = True

        # Use this information instead of 'SETTING ...', in case the defaults are standard.
        # Note that this is sometimes printed in each geometry optimization step.
        if line[1:20] == "NUMBER OF ELECTRONS":

            spinup = int(line.split()[3][:-1])
            spindown = int(line.split()[4][:-1])
            # Nuclear charges (atomnos) should be parsed by now.
            nuclear = numpy.sum(self.atomnos)

            charge = nuclear - spinup - spindown
            self.set_attribute('charge', charge)

            mult = spinup - spindown + 1
            self.set_attribute('mult', mult)

        # Convergenve thresholds for SCF cycle, should be contained in a line such as:
        #   CONVERGENCE THRESHOLDS:    1.00E-05 (Density)    1.40E-07 (Energy)
        if self.insidescf and line[1:24] == "CONVERGENCE THRESHOLDS:":

            if not hasattr(self, "scftargets"):
                self.scftargets = []

            scftargets = list(map(float, line.split()[2::2]))
            self.scftargets.append(scftargets)
            # Usually two criteria, but save the names this just in case.
            self.scftargetnames = line.split()[3::2]

        # Read in the print out of the SCF cycle - for scfvalues. For RHF looks like:
        # ITERATION    DDIFF          GRAD             ENERGY        2-EL.EN.            DIPOLE MOMENTS         DIIS
        #     1      0.000D+00      0.000D+00      -379.71523700   1159.621171   0.000000   0.000000   0.000000    0
        #     2      0.000D+00      0.898D-02      -379.74469736   1162.389787   0.000000   0.000000   0.000000    1
        #     3      0.817D-02      0.144D-02      -379.74635529   1162.041033   0.000000   0.000000   0.000000    2
        #     4      0.213D-02      0.571D-03      -379.74658063   1162.159929   0.000000   0.000000   0.000000    3
        #     5      0.799D-03      0.166D-03      -379.74660889   1162.144256   0.000000   0.000000   0.000000    4
        if self.insidescf and line[1:10] == "ITERATION":

            if not hasattr(self, "scfvalues"):
                self.scfvalues = []

            line = next(inputfile)
            energy = 0.0
            scfvalues = []
            while line.strip() != "":
                chomp = line.split()
                if chomp[0].isdigit():

                    ddiff = float(chomp[1].replace('D', 'E'))
                    grad = float(chomp[2].replace('D', 'E'))
                    newenergy = float(chomp[3])
                    ediff = newenergy - energy
                    energy = newenergy

                    # The convergence thresholds must have been read above.
                    # Presently, we recognize MAX DENSITY and MAX ENERGY thresholds.
                    numtargets = len(self.scftargetnames)
                    values = [numpy.nan]*numtargets
                    for n, name in zip(list(range(numtargets)), self.scftargetnames):
                        if "ENERGY" in name.upper():
                            values[n] = ediff
                        elif "DENSITY" in name.upper():
                            values[n] = ddiff
                    scfvalues.append(values)

                try:
                    line = next(inputfile)
                except StopIteration:
                    self.logger.warning('File terminated before end of last SCF! Last gradient: {}'.format(grad))
                    break
            self.scfvalues.append(numpy.array(scfvalues))

        # SCF result - RHF/UHF and DFT (RKS) energies.
        if (line[1:5] in ["!RHF", "!UHF", "!RKS"] and line[16:22].lower() == "energy"):

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            scfenergy = float(line.split()[4])
            self.scfenergies.append(utils.convertor(scfenergy, "hartree", "eV"))

            # We are now done with SCF cycle (after a few lines).
            self.insidescf = False

        # MP2 energies.
        if line[1:5] == "!MP2":

            if not hasattr(self, 'mpenergies'):
                self.mpenergies = []
            mp2energy = float(line.split()[-1])
            mp2energy = utils.convertor(mp2energy, "hartree", "eV")
            self.mpenergies.append([mp2energy])

        # MP2 energies if MP3 or MP4 is also calculated.
        if line[1:5] == "MP2:":

            if not hasattr(self, 'mpenergies'):
                self.mpenergies = []
            mp2energy = float(line.split()[2])
            mp2energy = utils.convertor(mp2energy, "hartree", "eV")
            self.mpenergies.append([mp2energy])

        # MP3 (D) and MP4 (DQ or SDQ) energies.
        if line[1:8] == "MP3(D):":

            mp3energy = float(line.split()[2])
            mp2energy = utils.convertor(mp3energy, "hartree", "eV")
            line = next(inputfile)
            self.mpenergies[-1].append(mp2energy)
            if line[1:9] == "MP4(DQ):":
                mp4energy = float(line.split()[2])
                line = next(inputfile)
                if line[1:10] == "MP4(SDQ):":
                    mp4energy = float(line.split()[2])
                mp4energy = utils.convertor(mp4energy, "hartree", "eV")
                self.mpenergies[-1].append(mp4energy)

        # The CCSD program operates all closed-shel coupled cluster runs.
        if line[1:15] == "PROGRAM * CCSD":

            if not hasattr(self, "ccenergies"):
                self.ccenergies = []
            while line[1:20] != "Program statistics:":
                # The last energy (most exact) will be read last and thus saved.
                if line[1:5] == "!CCD" or line[1:6] == "!CCSD" or line[1:9] == "!CCSD(T)":
                    ccenergy = float(line.split()[-1])
                    ccenergy = utils.convertor(ccenergy, "hartree", "eV")
                line = next(inputfile)
            self.ccenergies.append(ccenergy)

        # Read the occupancy (index of HOMO s).
        # For restricted calculations, there is one line here. For unrestricted, two:
        #   Final alpha occupancy:  ...
        #   Final beta  occupancy:  ...
        if line[1:17] == "Final occupancy:":
            self.homos = [int(line.split()[-1])-1]
        if line[1:23] == "Final alpha occupancy:":
            self.homos = [int(line.split()[-1])-1]
            line = next(inputfile)
            self.homos.append(int(line.split()[-1])-1)

        # Dipole is always printed on one line after the final RHF energy, and by default
        # it seems Molpro uses the origin as the reference point.
        if line.strip()[:13] == "Dipole moment":

            assert line.split()[2] == "/Debye"

            reference = [0.0, 0.0, 0.0]
            dipole = [float(d) for d in line.split()[-3:]]

            if not hasattr(self, 'moments'):
                self.moments = [reference, dipole]
            else:
                self.moments[1] == dipole

        # From this block aonames, atombasis, moenergies and mocoeffs can be parsed. The data is
        # flipped compared to most programs (GAMESS, Gaussian), since the MOs are in rows. Also, Molpro
        # does not cut the table into parts, rather each MO row has as many lines as it takes ro print
        # all of the MO coefficients. Each row normally has 10 coefficients, although this can be less
        # for the last row and when symmetry is used (each irrep has its own block).
        #
        # ELECTRON ORBITALS
        # =================
        #
        #
        #   Orb  Occ    Energy  Couls-En    Coefficients
        #
        #                                   1 1s      1 1s      1 2px     1 2py     1 2pz     2 1s   (...)
        #                                   3 1s      3 1s      3 2px     3 2py     3 2pz     4 1s   (...)
        # (...)
        #
        #   1.1   2   -11.0351  -43.4915  0.701460  0.025696 -0.000365 -0.000006  0.000000  0.006922 (...)
        #                                -0.006450  0.004742 -0.001028 -0.002955  0.000000 -0.701460 (...)
        # (...)
        #
        if line[1:18] == "ELECTRON ORBITALS" or self.electronorbitals:

            # For unrestricted calcualtions, ELECTRON ORBITALS is followed on the same line
            # by FOR POSITIVE SPIN or FOR NEGATIVE SPIN as appropriate.
            spin = (line[19:36] == "FOR NEGATIVE SPIN") or (self.electronorbitals[19:36] == "FOR NEGATIVE SPIN")

            if not self.electronorbitals:
                self.skip_line(inputfile, 'equals')
            self.skip_lines(inputfile, ['b', 'b', 'headers', 'b'])

            aonames = []
            atombasis = [[] for i in range(self.natom)]
            moenergies = []
            mocoeffs = []
            line = next(inputfile)

            # Besides a double blank line, stop when the next orbitals are encountered for unrestricted jobs
            # or if there are stars on the line which always signifies the end of the block.
            while line.strip() and (not "ORBITALS" in line) and (not set(line.strip()) == {'*'}):

                # The function names are normally printed just once, but if symmetry is used then each irrep
                # has its own mocoeff block with a preceding list of names.
                is_aonames = line[:25].strip() == ""
                if is_aonames:

                    # We need to save this offset for parsing the coefficients later.
                    offset = len(aonames)

                    aonum = len(aonames)
                    while line.strip():
                        for s in line.split():
                            if s.isdigit():
                                atomno = int(s)
                                atombasis[atomno-1].append(aonum)
                                aonum += 1
                            else:
                                functype = s
                                element = self.table.element[self.atomnos[atomno-1]]
                                aoname = "%s%i_%s" % (element, atomno, functype)
                                aonames.append(aoname)
                        line = next(inputfile)

                    # Now there can be one or two blank lines.
                    while not line.strip():
                        line = next(inputfile)

                # Newer versions of Molpro (for example, 2012 test files) will print some
                # more things here, such as HOMO and LUMO, but these have less than 10 columns.
                if "HOMO" in line or "LUMO" in line:
                    break

                # Now parse the MO coefficients, padding the list with an appropriate amount of zeros.
                coeffs = [0.0 for i in range(offset)]
                while line.strip() != "":
                    if line[:31].rstrip():
                        moenergy = float(line.split()[2])
                        moenergy = utils.convertor(moenergy, "hartree", "eV")
                        moenergies.append(moenergy)

                    # Coefficients are in 10.6f format and splitting does not work since there are not
                    # always spaces between them. If the numbers are very large, there will be stars.
                    str_coeffs = line[31:]
                    ncoeffs = len(str_coeffs) // 10
                    coeff = []
                    for ic in range(ncoeffs):
                        p = str_coeffs[ic*10:(ic+1)*10]
                        try:
                            c = float(p)
                        except ValueError as detail:
                            self.logger.warn("setting mocoeff element to zero: %s" % detail)
                            c = 0.0
                        coeff.append(c)
                    coeffs.extend(coeff)
                    line = next(inputfile)
                mocoeffs.append(coeffs)

                # The loop should keep going until there is a double blank line, and there is
                # a single line between each coefficient block.
                line = next(inputfile)
                if not line.strip():
                    line = next(inputfile)

            # If symmetry was used (offset was needed) then we will need to pad all MO vectors
            # up to nbasis for all irreps before the last one.
            if offset > 0:
                for im, m in enumerate(mocoeffs):
                    if len(m) < self.nbasis:
                        mocoeffs[im] = m + [0.0 for i in range(self.nbasis - len(m))]

            self.set_attribute('atombasis', atombasis)
            self.set_attribute('aonames', aonames)

            # Consistent with current cclib conventions, reset moenergies/mocoeffs if they have been
            # previously parsed, since we want to produce only the final values.
            if not hasattr(self, "moenergies") or spin == 0:
                self.mocoeffs = []
                self.moenergies = []
            self.moenergies.append(moenergies)
            self.mocoeffs.append(mocoeffs)

            # Check if last line begins the next ELECTRON ORBITALS section, because we already used
            # this line and need to know when this method is called next time.
            if line[1:18] == "ELECTRON ORBITALS":
                self.electronorbitals = line
            else:
                self.electronorbitals = ""

        # If the MATROP program was called appropriately,
        #   the atomic obital overlap matrix S is printed.
        # The matrix is printed straight-out, ten elements in each row, both halves.
        # Note that is the entire matrix is not printed, then aooverlaps
        #   will not have dimensions nbasis x nbasis.
        if line[1:9] == "MATRIX S":

            if not hasattr(self, "aooverlaps"):
                self.aooverlaps = [[]]

            self.skip_lines(inputfile, ['b', 'symblocklabel'])

            line = next(inputfile)
            while line.strip() != "":
                elements = [float(s) for s in line.split()]
                if len(self.aooverlaps[-1]) + len(elements) <= self.nbasis:
                    self.aooverlaps[-1] += elements
                else:
                    n = len(self.aooverlaps[-1]) + len(elements) - self.nbasis
                    self.aooverlaps[-1] += elements[:-n]
                    self.aooverlaps.append([])
                    self.aooverlaps[-1] += elements[-n:]
                line = next(inputfile)

        # Thresholds are printed only if the defaults are changed with GTHRESH.
        # In that case, we can fill geotargets with non-default values.
        # The block should look like this as of Molpro 2006.1:
        #   THRESHOLDS:

        #   ZERO    =  1.00D-12  ONEINT  =  1.00D-12  TWOINT  =  1.00D-11  PREFAC  =  1.00D-14  LOCALI  =  1.00D-09  EORDER  =  1.00D-04
        #   ENERGY  =  0.00D+00  ETEST   =  0.00D+00  EDENS   =  0.00D+00  THRDEDEF=  1.00D-06  GRADIENT=  1.00D-02  STEP    =  1.00D-03
        #   ORBITAL =  1.00D-05  CIVEC   =  1.00D-05  COEFF   =  1.00D-04  PRINTCI =  5.00D-02  PUNCHCI =  9.90D+01  OPTGRAD =  3.00D-04
        #   OPTENERG=  1.00D-06  OPTSTEP =  3.00D-04  THRGRAD =  2.00D-04  COMPRESS=  1.00D-11  VARMIN  =  1.00D-07  VARMAX  =  1.00D-03
        #   THRDOUB =  0.00D+00  THRDIV  =  1.00D-05  THRRED  =  1.00D-07  THRPSP  =  1.00D+00  THRDC   =  1.00D-10  THRCS   =  1.00D-10
        #   THRNRM  =  1.00D-08  THREQ   =  0.00D+00  THRDE   =  1.00D+00  THRREF  =  1.00D-05  SPARFAC =  1.00D+00  THRDLP  =  1.00D-07
        #   THRDIA  =  1.00D-10  THRDLS  =  1.00D-07  THRGPS  =  0.00D+00  THRKEX  =  0.00D+00  THRDIS  =  2.00D-01  THRVAR  =  1.00D-10
        #   THRLOC  =  1.00D-06  THRGAP  =  1.00D-06  THRLOCT = -1.00D+00  THRGAPT = -1.00D+00  THRORB  =  1.00D-06  THRMLTP =  0.00D+00
        #   THRCPQCI=  1.00D-10  KEXTA   =  0.00D+00  THRCOARS=  0.00D+00  SYMTOL  =  1.00D-06  GRADTOL =  1.00D-06  THROVL  =  1.00D-08
        #   THRORTH =  1.00D-08  GRID    =  1.00D-06  GRIDMAX =  1.00D-03  DTMAX   =  0.00D+00
        if line[1:12] == "THRESHOLDS":

            self.skip_line(input, 'blank')

            line = next(inputfile)
            while line.strip():

                if "OPTENERG" in line:
                    start = line.find("OPTENERG")
                    optenerg = line[start+10:start+20]
                if "OPTGRAD" in line:
                    start = line.find("OPTGRAD")
                    optgrad = line[start+10:start+20]
                if "OPTSTEP" in line:
                    start = line.find("OPTSTEP")
                    optstep = line[start+10:start+20]
                line = next(inputfile)

            self.geotargets = [optenerg, optgrad, optstep]

        # The optimization history is the source for geovlues:
        #
        #   END OF GEOMETRY OPTIMIZATION.    TOTAL CPU:       246.9 SEC
        #
        #     ITER.   ENERGY(OLD)    ENERGY(NEW)      DE          GRADMAX     GRADNORM    GRADRMS     STEPMAX     STEPLEN     STEPRMS
        #      1  -382.02936898  -382.04914450    -0.01977552  0.11354875  0.20127947  0.01183997  0.12972761  0.20171740  0.01186573
        #      2  -382.04914450  -382.05059234    -0.00144784  0.03299860  0.03963339  0.00233138  0.05577169  0.06687650  0.00393391
        #      3  -382.05059234  -382.05069136    -0.00009902  0.00694359  0.01069889  0.00062935  0.01654549  0.02016307  0.00118606
        # ...
        #
        # The above is an exerpt from Molpro 2006, but it is a little bit different
        # for Molpro 2012, namely the 'END OF GEOMETRY OPTIMIZATION occurs after the
        # actual history list. It seems there is a another consistent line before the
        # history, but this might not be always true -- so this is a potential weak link.
        if line[1:30] == "END OF GEOMETRY OPTIMIZATION." or line.strip() == "Quadratic Steepest Descent - Minimum Search":

            # I think this is the trigger for convergence, and it shows up at the top in Molpro 2006.
            geometry_converged = line[1:30] == "END OF GEOMETRY OPTIMIZATION."

            self.skip_line(inputfile, 'blank')

            # Newer version of Molpro (at least for 2012) print and additional column
            # with the timing information for each step. Otherwise, the history looks the same.
            headers = next(inputfile).split()
            if not len(headers) in (10, 11):
                return

            # Although criteria can be changed, the printed format should not change.
            # In case it does, retrieve the columns for each parameter.
            index_ITER = headers.index('ITER.')
            index_THRENERG = headers.index('DE')
            index_THRGRAD = headers.index('GRADMAX')
            index_THRSTEP = headers.index('STEPMAX')

            line = next(inputfile)
            self.geovalues = []
            while line.strip():

                line = line.split()
                istep = int(line[index_ITER])

                geovalues = []
                geovalues.append(float(line[index_THRENERG]))
                geovalues.append(float(line[index_THRGRAD]))
                geovalues.append(float(line[index_THRSTEP]))
                self.geovalues.append(geovalues)
                line = next(inputfile)
                if line.strip() == "Freezing grid":
                    line = next(inputfile)

            # The convergence trigger shows up somewhere at the bottom in Molpro 2012,
            # before the final stars. If convergence is not reached, there is an additional
            # line that can be checked for. This is a little tricky, though, since it is
            # not the last line... so bail out of the loop if convergence failure is detected.
            while "*****" not in line:
                line = next(inputfile)
                if line.strip() == "END OF GEOMETRY OPTIMIZATION.":
                    geometry_converged = True
                if "No convergence" in line:
                    geometry_converged = False
                    break

            # Finally, deal with optdone, append the last step to it only if we had convergence.
            if not hasattr(self, 'optdone'):
                self.optdone = []
            if geometry_converged:
                self.optdone.append(istep-1)

        # This block should look like this:
        #   Normal Modes
        #
        #                                1 Au        2 Bu        3 Ag        4 Bg        5 Ag
        #   Wavenumbers [cm-1]          151.81      190.88      271.17      299.59      407.86
        #   Intensities [km/mol]          0.33        0.28        0.00        0.00        0.00
        #   Intensities [relative]        0.34        0.28        0.00        0.00        0.00
        #             CX1              0.00000    -0.01009     0.02577     0.00000     0.06008
        #             CY1              0.00000    -0.05723    -0.06696     0.00000     0.06349
        #             CZ1             -0.02021     0.00000     0.00000     0.11848     0.00000
        #             CX2              0.00000    -0.01344     0.05582     0.00000    -0.02513
        #             CY2              0.00000    -0.06288    -0.03618     0.00000     0.00349
        #             CZ2             -0.05565     0.00000     0.00000     0.07815     0.00000
        #             ...
        # Molpro prints low frequency modes in a subsequent section with the same format,
        #   which also contains zero frequency modes, with the title:
        #   Normal Modes of low/zero frequencies
        if line[1:13] == "Normal Modes":

            if line[1:37] == "Normal Modes of low/zero frequencies":
                islow = True
            else:
                islow = False

            self.skip_line(inputfile, 'blank')

            # Each portion of five modes is followed by a single blank line.
            # The whole block is followed by an additional blank line.
            line = next(inputfile)
            while line.strip():

                if line[1:25].isspace():
                    if not islow:  # vibsyms not printed for low freq modes
                        numbers = list(map(int, line.split()[::2]))
                        vibsyms = line.split()[1::2]
                    else:
                        # give low freq modes an empty str as vibsym
                        # note there could be other possibilities..
                        numbers = list(map(int, line.split()))
                        vibsyms = ['']*len(numbers)

                if line[1:12] == "Wavenumbers":
                    vibfreqs = list(map(float, line.strip().split()[2:]))

                if line[1:21] == "Intensities [km/mol]":
                    vibirs = list(map(float, line.strip().split()[2:]))

                # There should always by 3xnatom displacement rows.
                if line[1:11].isspace() and line[13:25].strip().isdigit():

                    # There are a maximum of 5 modes per line.
                    nmodes = len(line.split())-1

                    vibdisps = []
                    for i in range(nmodes):
                        vibdisps.append([])
                        for n in range(self.natom):
                            vibdisps[i].append([])
                    for i in range(nmodes):
                        disp = float(line.split()[i+1])
                        vibdisps[i][0].append(disp)
                    for i in range(self.natom*3 - 1):
                        line = next(inputfile)
                        iatom = (i+1)//3
                        for i in range(nmodes):
                            disp = float(line.split()[i+1])
                            vibdisps[i][iatom].append(disp)

                line = next(inputfile)
                if not line.strip():

                    if not hasattr(self, "vibfreqs"):
                        self.vibfreqs = []
                    if not hasattr(self, "vibsyms"):
                        self.vibsyms = []
                    if not hasattr(self, "vibirs") and "vibirs" in dir():
                        self.vibirs = []
                    if not hasattr(self, "vibdisps") and "vibdisps" in dir():
                        self.vibdisps = []

                    if not islow:
                        self.vibfreqs.extend(vibfreqs)
                        self.vibsyms.extend(vibsyms)
                        if "vibirs" in dir():
                            self.vibirs.extend(vibirs)
                        if "vibdisps" in dir():
                            self.vibdisps.extend(vibdisps)
                    else:
                        nonzero = [f > 0 for f in vibfreqs]
                        vibfreqs = [f for f in vibfreqs if f > 0]
                        self.vibfreqs = vibfreqs + self.vibfreqs
                        vibsyms = [vibsyms[i] for i in range(len(vibsyms)) if nonzero[i]]
                        self.vibsyms = vibsyms + self.vibsyms
                        if "vibirs" in dir():
                            vibirs = [vibirs[i] for i in range(len(vibirs)) if nonzero[i]]
                            self.vibirs = vibirs + self.vibirs
                        if "vibdisps" in dir():
                            vibdisps = [vibdisps[i] for i in range(len(vibdisps)) if nonzero[i]]
                            self.vibdisps = vibdisps + self.vibdisps

                    line = next(inputfile)

        if line[1:16] == "Force Constants":

            self.logger.info("Creating attribute hessian")
            self.hessian = []
            line = next(inputfile)
            hess = []
            tmp = []

            while line.strip():
                try:
                    list(map(float, line.strip().split()[2:]))
                except:
                    line = next(inputfile)
                line.strip().split()[1:]
                hess.extend([list(map(float, line.strip().split()[1:]))])
                line = next(inputfile)
            lig = 0

            while (lig == 0) or (len(hess[0]) > 1):
                tmp.append(hess.pop(0))
                lig += 1
            k = 5

            while len(hess) != 0:
                tmp[k] += hess.pop(0)
                k += 1
                if (len(tmp[k-1]) == lig):
                    break
                if k >= lig:
                    k = len(tmp[-1])
            for l in tmp:
                self.hessian += l

        if line[1:14] == "Atomic Masses" and hasattr(self, "hessian"):

            line = next(inputfile)
            self.amass = list(map(float, line.strip().split()[2:]))

            while line.strip():
                line = next(inputfile)
                self.amass += list(map(float, line.strip().split()[2:]))

        #1PROGRAM * POP (Mulliken population analysis)
        #
        #
        # Density matrix read from record         2100.2  Type=RHF/CHARGE (state 1.1)
        #
        # Population analysis by basis function type
        #
        # Unique atom        s        p        d        f        g    Total    Charge
        #   2  C       3.11797  2.88497  0.00000  0.00000  0.00000  6.00294  - 0.00294
        #   3  C       3.14091  2.91892  0.00000  0.00000  0.00000  6.05984  - 0.05984
        # ...
        if line.strip() == "1PROGRAM * POP (Mulliken population analysis)":

            self.skip_lines(inputfile, ['b', 'b', 'density_source', 'b', 'func_type', 'b'])

            header = next(inputfile)
            icharge = header.split().index('Charge')

            charges = []
            line = next(inputfile)
            while line.strip():
                cols = line.split()
                charges.append(float(cols[icharge]+cols[icharge+1]))
                line = next(inputfile)

            if not hasattr(self, "atomcharges"):
                self.atomcharges = {}
            self.atomcharges['mulliken'] = charges


if __name__ == "__main__":
    import doctest, molproparser
    doctest.testmod(molproparser, verbose=False)
