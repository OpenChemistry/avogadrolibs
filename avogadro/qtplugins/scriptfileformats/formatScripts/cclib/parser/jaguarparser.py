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

"""Parser for Jaguar output files"""

import numpy
import re

from . import logfileparser
from . import utils


class Jaguar(logfileparser.Logfile):
    """A Jaguar output file"""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(Jaguar, self).__init__(logname="Jaguar", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "Jaguar output file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'Jaguar("%s")' % (self.filename)

    def normalisesym(self, label):
        """Normalise the symmetries used by Jaguar.

        To normalise, three rules need to be applied:
        (1) To handle orbitals of E symmetry, retain everything before the /
        (2) Replace two p's by "
        (2) Replace any remaining single p's by '

        >>> t = Jaguar("dummyfile").normalisesym
        >>> labels = ['A', 'A1', 'Ag', 'Ap', 'App', "A1p", "A1pp", "E1pp/Ap"]
        >>> answers = map(t, labels)
        >>> print answers
        ['A', 'A1', 'Ag', "A'", 'A"', "A1'", 'A1"', 'E1"']
        """
        ans = label.split("/")[0].replace("pp", '"').replace("p", "'")
        return ans

    def before_parsing(self):

        # We need to track whether we are inside geometry optimization in order
        # to parse SCF targets/values correctly.
        self.geoopt = False

    def after_parsing(self):

        # This is to make sure we always have optdone after geometry optimizations,
        # even if it is to be empty for unconverged runs. We have yet to test this
        # with a regression for Jaguar, though.
        if self.geoopt and not hasattr(self, 'optdone'):
            self.optdone = []

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        # Extract charge and multiplicity
        if line[2:22] == "net molecular charge":
            self.set_attribute('charge', int(line.split()[-1]))
            self.set_attribute('mult', int(next(inputfile).split()[-1]))

        # The Gaussian basis set information is printed before the geometry, and we need
        # to do some indexing to get this into cclib format, because fn increments
        # for each engular momentum, but cclib does not (we have just P instead of
        # all three X/Y/Z with the same parameters. On the other hand, fn enumerates
        # the atomic orbitals correctly, so use it to build atombasis.
        #
        #  Gaussian basis set information
        #
        #                                                        renorm    mfac*renorm
        #   atom    fn   prim  L        z            coef         coef         coef
        # -------- ----- ---- --- -------------  -----------  -----------  -----------
        # C1           1    1   S  7.161684E+01   1.5433E-01   2.7078E+00   2.7078E+00
        # C1           1    2   S  1.304510E+01   5.3533E-01   2.6189E+00   2.6189E+00
        # ...
        # C1           3    6   X  2.941249E+00   2.2135E-01   1.2153E+00   1.2153E+00
        #              4        Y                                           1.2153E+00
        #              5        Z                                           1.2153E+00
        # C1           2    8   S  2.222899E-01   1.0000E+00   2.3073E-01   2.3073E-01
        # C1           3    7   X  6.834831E-01   8.6271E-01   7.6421E-01   7.6421E-01
        # ...
        # C2           6    1   S  7.161684E+01   1.5433E-01   2.7078E+00   2.7078E+00
        # ...
        #
        if line.strip() == "Gaussian basis set information":

            self.skip_lines(inputfile, ['b', 'renorm', 'header', 'd'])

            # This is probably the only place we can get this information from Jaguar.
            self.gbasis = []

            atombasis = []
            line = next(inputfile)
            fn_per_atom = []
            while line.strip():

                if len(line.split()) > 3:

                    aname = line.split()[0]
                    fn = int(line.split()[1])
                    prim = int(line.split()[2])
                    L = line.split()[3]
                    z = float(line.split()[4])
                    coef = float(line.split()[5])

                    # The primitive count is reset for each atom, so use that for adding
                    # new elements to atombasis and gbasis. We could also probably do this
                    # using the atom name, although that perhaps might not always be unique.
                    if prim == 1:
                        atombasis.append([])
                        fn_per_atom = []
                        self.gbasis.append([])

                    # Remember that fn is repeated when functions are contracted.
                    if not fn-1 in atombasis[-1]:
                        atombasis[-1].append(fn-1)

                    # Here we use fn only to know when a new contraction is encountered,
                    # so we don't need to decrement it, and we don't even use all values.
                    # What's more, since we only wish to save the parameters for each subshell
                    # once, we don't even need to consider lines for orbitals other than
                    # those for X*, making things a bit easier.
                    if not fn in fn_per_atom:
                        fn_per_atom.append(fn)
                        label = {'S': 'S', 'X': 'P', 'XX': 'D', 'XXX': 'F'}[L]
                        self.gbasis[-1].append((label, []))
                    igbasis = fn_per_atom.index(fn)
                    self.gbasis[-1][igbasis][1].append([z, coef])

                else:

                    fn = int(line.split()[0])
                    L = line.split()[1]

                    # Some AO indices are only printed in these lines, for L > 0.
                    if not fn-1 in atombasis[-1]:
                        atombasis[-1].append(fn-1)

                line = next(inputfile)

            # The indices for atombasis can also be read later from the molecular orbital output.
            self.set_attribute('atombasis', atombasis)

            # This length of atombasis should always be the number of atoms.
            self.set_attribute('natom', len(self.atombasis))

        #  Effective Core Potential
        #
        #  Atom      Electrons represented by ECP
        # Mo                    36
        #              Maximum angular term         3
        # F Potential      1/r^n   Exponent  Coefficient
        #                  -----   --------  -----------
        #                    0  140.4577691   -0.0469492
        #                    1   89.4739342  -24.9754989
        # ...
        # S-F Potential    1/r^n   Exponent  Coefficient
        #                  -----   --------  -----------
        #                    0   33.7771969    2.9278406
        #                    1   10.0120020   34.3483716
        # ...
        # O                      0
        # Cl                    10
        #              Maximum angular term         2
        # D Potential      1/r^n   Exponent  Coefficient
        #                  -----   --------  -----------
        #                    1   94.8130000  -10.0000000
        # ...
        if line.strip() == "Effective Core Potential":

            self.skip_line(inputfile, 'blank')
            line = next(inputfile)
            assert line.split()[0] == "Atom"
            assert " ".join(line.split()[1:]) == "Electrons represented by ECP"

            self.coreelectrons = []
            line = next(inputfile)
            while line.strip():
                if len(line.split()) == 2:
                    self.coreelectrons.append(int(line.split()[1]))
                line = next(inputfile)

        if line[2:14] == "new geometry" or line[1:21] == "Symmetrized geometry" or line.find("Input geometry") > 0:
        # Get the atom coordinates
            if not hasattr(self, "atomcoords") or line[1:21] == "Symmetrized geometry":
                # Wipe the "Input geometry" if "Symmetrized geometry" present
                self.atomcoords = []
            p = re.compile("(\D+)\d+")  # One/more letters followed by a number
            atomcoords = []
            atomnos = []
            angstrom = next(inputfile)
            title = next(inputfile)
            line = next(inputfile)
            while line.strip():
                temp = line.split()
                element = p.findall(temp[0])[0]
                atomnos.append(self.table.number[element])
                atomcoords.append(list(map(float, temp[1:])))
                line = next(inputfile)
            self.atomcoords.append(atomcoords)
            self.atomnos = numpy.array(atomnos, "i")
            self.set_attribute('natom', len(atomcoords))

        # Hartree-Fock energy after SCF
        if line[1:18] == "SCFE: SCF energy:":
            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            temp = line.strip().split()
            scfenergy = float(temp[temp.index("hartrees") - 1])
            scfenergy = utils.convertor(scfenergy, "hartree", "eV")
            self.scfenergies.append(scfenergy)

        # Energy after LMP2 correction
        if line[1:18] == "Total LMP2 Energy":
            if not hasattr(self, "mpenergies"):
                self.mpenergies = [[]]
            lmp2energy = float(line.split()[-1])
            lmp2energy = utils.convertor(lmp2energy, "hartree", "eV")
            self.mpenergies[-1].append(lmp2energy)

        if line[15:45] == "Geometry optimization complete":
            if not hasattr(self, 'optdone'):
                self.optdone = []
            self.optdone.append(len(self.geovalues) - 1)

        if line.find("number of occupied orbitals") > 0:
        # Get number of MOs
            occs = int(line.split()[-1])
            line = next(inputfile)
            virts = int(line.split()[-1])
            self.nmo = occs + virts
            self.homos = numpy.array([occs-1], "i")

            self.unrestrictedflag = False

        if line[1:28] == "number of occupied orbitals":
            self.homos = numpy.array([float(line.strip().split()[-1])-1], "i")

        if line[2:27] == "number of basis functions":
            nbasis = int(line.strip().split()[-1])
            self.set_attribute('nbasis', nbasis)

        if line.find("number of alpha occupied orb") > 0:
        # Get number of MOs for an unrestricted calc

            aoccs = int(line.split()[-1])
            line = next(inputfile)
            avirts = int(line.split()[-1])
            line = next(inputfile)
            boccs = int(line.split()[-1])
            line = next(inputfile)
            bvirt = int(line.split()[-1])

            self.nmo = aoccs + avirts
            self.homos = numpy.array([aoccs-1, boccs-1], "i")
            self.unrestrictedflag = True

        if line[0:4] == "etot":
        # Get SCF convergence information
            if not hasattr(self, "scfvalues"):
                self.scfvalues = []
                self.scftargets = [[5E-5, 5E-6]]
            values = []
            while line[0:4] == "etot":
        # Jaguar 4.2
        # etot   1  N  N  0  N  -382.08751886450           2.3E-03  1.4E-01
        # etot   2  Y  Y  0  N  -382.27486023153  1.9E-01  1.4E-03  5.7E-02
        # Jaguar 6.5
        # etot   1  N  N  0  N    -382.08751881733           2.3E-03  1.4E-01
        # etot   2  Y  Y  0  N    -382.27486018708  1.9E-01  1.4E-03  5.7E-02
                temp = line.split()[7:]
                if len(temp) == 3:
                    denergy = float(temp[0])
                else:
                    denergy = 0  # Should really be greater than target value
                                 # or should we just ignore the values in this line
                ddensity = float(temp[-2])
                maxdiiserr = float(temp[-1])
                if not self.geoopt:
                    values.append([denergy, ddensity])
                else:
                    values.append([ddensity])
                try:
                    line = next(inputfile)
                except StopIteration:
                    self.logger.warning('File terminated before end of last SCF! Last error: {}'.format(maxdiiserr))
                    break
            self.scfvalues.append(values)

        # MO energies and symmetries.
        # Jaguar 7.0: provides energies and symmetries for both
        #   restricted and unrestricted calculations, like this:
        #     Alpha Orbital energies/symmetry label:
        #     -10.25358 Bu  -10.25353 Ag  -10.21931 Bu  -10.21927 Ag
        #     -10.21792 Bu  -10.21782 Ag  -10.21773 Bu  -10.21772 Ag
        #     ...
        # Jaguar 6.5: prints both only for restricted calculations,
        #   so for unrestricted calculations the output it looks like this:
        #     Alpha Orbital energies:
        #     -10.25358  -10.25353  -10.21931  -10.21927  -10.21792  -10.21782
        #     -10.21773  -10.21772  -10.21537  -10.21537   -1.02078   -0.96193
        #     ...
        # Presence of 'Orbital energies' is enough to catch all versions.
        if "Orbital energies" in line:

            # Parsing results is identical for restricted/unrestricted
            #   calculations, just assert later that alpha/beta order is OK.
            spin = int(line[2:6] == "Beta")

            # Check if symmetries are printed also.
            issyms = "symmetry label" in line

            if not hasattr(self, "moenergies"):
                self.moenergies = []
            if issyms and not hasattr(self, "mosyms"):
                    self.mosyms = []

            # Grow moeneriges/mosyms and make sure they are empty when
            #   parsed multiple times - currently cclib returns only
            #   the final output (ex. in a geomtry optimization).
            if len(self.moenergies) < spin+1:
                self.moenergies.append([])
            self.moenergies[spin] = []
            if issyms:
                if len(self.mosyms) < spin+1:
                    self.mosyms.append([])
                self.mosyms[spin] = []

            line = next(inputfile).split()
            while len(line) > 0:
                if issyms:
                    energies = [float(line[2*i]) for i in range(len(line)//2)]
                    syms = [line[2*i+1] for i in range(len(line)//2)]
                else:
                    energies = [float(e) for e in line]
                energies = [utils.convertor(e, "hartree", "eV") for e in energies]
                self.moenergies[spin].extend(energies)
                if issyms:
                    syms = [self.normalisesym(s) for s in syms]
                    self.mosyms[spin].extend(syms)
                line = next(inputfile).split()

            line = next(inputfile)

        # The second trigger string is in the version 8.3 unit test and the first one was
        # encountered in version 6.x and is followed by a bit different format. In particular,
        # the line with occupations is missing in each block. Here is a fragment of this block
        # from version 8.3:
        #
        # *****************************************
        #
        # occupied + virtual orbitals: final wave function
        #
        # *****************************************
        #
        #
        #                              1         2         3         4         5
        #  eigenvalues-            -11.04064 -11.04058 -11.03196 -11.03196 -11.02881
        #  occupations-              2.00000   2.00000   2.00000   2.00000   2.00000
        #    1 C1               S    0.70148   0.70154  -0.00958  -0.00991   0.00401
        #    2 C1               S    0.02527   0.02518   0.00380   0.00374   0.00371
        # ...
        #
        if line.find("Occupied + virtual Orbitals- final wvfn") > 0 or \
           line.find("occupied + virtual orbitals: final wave function") > 0:

            self.skip_lines(inputfile, ['b', 's', 'b', 'b'])

            if not hasattr(self, "mocoeffs"):
                self.mocoeffs = []

            aonames = []
            lastatom = "X"

            readatombasis = False
            if not hasattr(self, "atombasis"):
                self.atombasis = []
                for i in range(self.natom):
                    self.atombasis.append([])
                readatombasis = True

            offset = 0

            spin = 1 + int(self.unrestrictedflag)
            for s in range(spin):
                mocoeffs = numpy.zeros((len(self.moenergies[s]), self.nbasis), "d")

                if s == 1:  # beta case
                    self.skip_lines(inputfile, ['s', 'b', 'title', 'b', 's', 'b', 'b'])

                for k in range(0, len(self.moenergies[s]), 5):
                    self.updateprogress(inputfile, "Coefficients")

                    # All known version have a line with indices followed by the eigenvalues.
                    self.skip_lines(inputfile, ['numbers', 'eigens'])

                    # Newer version also have a line with occupation numbers here.
                    line = next(inputfile)
                    if "occupations-" in line:
                        line = next(inputfile)

                    for i in range(self.nbasis):

                        info = line.split()

                        # Fill atombasis only first time around.
                        if readatombasis and k == 0:
                            orbno = int(info[0])
                            atom = info[1]
                            if atom[1].isalpha():
                                atomno = int(atom[2:])
                            else:
                                atomno = int(atom[1:])
                            self.atombasis[atomno-1].append(orbno-1)

                        if not hasattr(self, "aonames"):
                            if lastatom != info[1]:
                                scount = 1
                                pcount = 3
                                dcount = 6  # six d orbitals in Jaguar

                            if info[2] == 'S':
                                aonames.append("%s_%i%s" % (info[1], scount, info[2]))
                                scount += 1

                            if info[2] == 'X' or info[2] == 'Y' or info[2] == 'Z':
                                aonames.append("%s_%iP%s" % (info[1], pcount / 3, info[2]))
                                pcount += 1

                            if info[2] == 'XX' or info[2] == 'YY' or info[2] == 'ZZ' or \
                               info[2] == 'XY' or info[2] == 'XZ' or info[2] == 'YZ':

                                aonames.append("%s_%iD%s" % (info[1], dcount / 6, info[2]))
                                dcount += 1

                            lastatom = info[1]

                        for j in range(len(info[3:])):
                            mocoeffs[j+k, i] = float(info[3+j])

                        line = next(inputfile)

                    if not hasattr(self, "aonames"):
                        self.aonames = aonames

                    offset += 5
                self.mocoeffs.append(mocoeffs)

        #  Atomic charges from Mulliken population analysis:
        #
        # Atom       C1           C2           C3           C4           C5
        # Charge    0.00177     -0.06075     -0.05956      0.00177     -0.06075
        #
        # Atom       H6           H7           H8           C9           C10
        # ...
        if line.strip() == "Atomic charges from Mulliken population analysis:":

            if not hasattr(self, 'atomcharges'):
                self.atomcharges = {}

            charges = []
            self.skip_line(inputfile, "blank")
            line = next(inputfile)
            while "sum of atomic charges" not in line:
                assert line.split()[0] == "Atom"
                line = next(inputfile)
                assert line.split()[0] == "Charge"
                charges.extend([float(c) for c in line.split()[1:]])
                self.skip_line(inputfile, "blank")
                line = next(inputfile)

            self.atomcharges['mulliken'] = charges

        if (line[2:6] == "olap") or (line.strip() == "overlap matrix:"):

            if line[6] == "-":
                return
                # This was continue (in loop) before parser refactoring.
                # continue # avoid "olap-dev"
            self.aooverlaps = numpy.zeros((self.nbasis, self.nbasis), "d")

            for i in range(0, self.nbasis, 5):
                self.updateprogress(inputfile, "Overlap")

                self.skip_lines(inputfile, ['b', 'header'])

                for j in range(i, self.nbasis):
                    temp = list(map(float, next(inputfile).split()[1:]))
                    self.aooverlaps[j, i:(i+len(temp))] = temp
                    self.aooverlaps[i:(i+len(temp)), j] = temp

        if line[2:24] == "start of program geopt":
            if not self.geoopt:
                # Need to keep only the RMS density change info
                # if this is a geooptz
                self.scftargets = [[self.scftargets[0][0]]]
                if hasattr(self, "scfvalues"):
                    self.scfvalues[0] = [[x[0]] for x in self.scfvalues[0]]
                self.geoopt = True
            else:
                self.scftargets.append([5E-5])

        # Get Geometry Opt convergence information
        #
        #  geometry optimization step  7
        #  energy:            -382.30219111487 hartrees
        #  [ turning on trust-radius adjustment ]
        #  ** restarting optimization from step    6 **
        #
        #
        #  Level shifts adjusted to satisfy step-size constraints
        #   Step size:    0.0360704
        #   Cos(theta):   0.8789215
        #   Final level shift:  -8.6176299E-02
        #
        #  energy change:           2.5819E-04 .  (  5.0000E-05 )
        #  gradient maximum:        5.0947E-03 .  (  4.5000E-04 )
        #  gradient rms:            1.2996E-03 .  (  3.0000E-04 )
        #  displacement maximum:    1.3954E-02 .  (  1.8000E-03 )
        #  displacement rms:        4.6567E-03 .  (  1.2000E-03 )
        #
        if line[2:28] == "geometry optimization step":

            if not hasattr(self, "geovalues"):
                self.geovalues = []
                self.geotargets = numpy.zeros(5, "d")

            gopt_step = int(line.split()[-1])

            energy = next(inputfile)
            blank = next(inputfile)

            # A quick hack for messages that show up right after the energy
            # at this point, which include:
            #   ** restarting optimization from step    2 **
            #   [ turning on trust-radius adjustment ]
            # as found in regression file ptnh3_2_H2O_2_2plus.out and other logfiles.
            restarting_from_1 = False
            while blank.strip():
                if blank.strip() == "** restarting optimization from step    1 **":
                    restarting_from_1 = True
                blank = next(inputfile)

            # One or more blank lines, depending on content.
            line = next(inputfile)
            while not line.strip():
                line = next(inputfile)

            # Note that the level shift message is followed by a blank, too.
            if "Level shifts adjusted" in line:
                while line.strip():
                    line = next(inputfile)
                line = next(inputfile)

            # The first optimization step does not produce an energy change, and
            # ther is also no energy change when the optimization is restarted
            # from step 1 (since step 1 had no change).
            values = []
            target_index = 0
            if (gopt_step == 1) or restarting_from_1:
                values.append(0.0)
                target_index = 1
            while line.strip():
                if len(line) > 40 and line[41] == "(":
                    # A new geo convergence value
                    values.append(float(line[26:37]))
                    self.geotargets[target_index] = float(line[43:54])
                    target_index += 1
                line = next(inputfile)
            self.geovalues.append(values)

        # IR output looks like this:
        #   frequencies        72.45   113.25   176.88   183.76   267.60   312.06
        #   symmetries       Au       Bg       Au       Bu       Ag       Bg
        #   intensities         0.07     0.00     0.28     0.52     0.00     0.00
        #   reduc. mass         1.90     0.74     1.06     1.42     1.19     0.85
        #   force const         0.01     0.01     0.02     0.03     0.05     0.05
        #   C1       X     0.00000  0.00000  0.00000 -0.05707 -0.06716  0.00000
        #   C1       Y     0.00000  0.00000  0.00000  0.00909 -0.02529  0.00000
        #   C1       Z     0.04792 -0.06032 -0.01192  0.00000  0.00000  0.11613
        #   C2       X     0.00000  0.00000  0.00000 -0.06094 -0.04635  0.00000
        #   ... etc. ...
        # This is a complete ouput, some files will not have intensities,
        #   and older Jaguar versions sometimes skip the symmetries.
        if line[2:23] == "start of program freq":

            self.skip_line(inputfile, 'blank')

            # Version 8.3 has two blank lines here, earlier versions just one.
            line = next(inputfile)
            if not line.strip():
                line = next(inputfile)

            self.vibfreqs = []
            self.vibdisps = []
            forceconstants = False
            intensities = False
            while line.strip():
                if "force const" in line:
                    forceconstants = True
                if "intensities" in line:
                    intensities = True
                line = next(inputfile)

            # In older version, the last block had an extra blank line after it,
            # which could be caught. This is not true in newer version (including 8.3),
            # but in general it would be better to bound this loop more strictly.
            freqs = next(inputfile)
            while freqs.strip() and not "imaginary frequencies" in freqs:

                # Number of modes (columns printed in this block).
                nmodes = len(freqs.split())-1

                # Append the frequencies.
                self.vibfreqs.extend(list(map(float, freqs.split()[1:])))
                line = next(inputfile).split()

                # May skip symmetries (older Jaguar versions).
                if line[0] == "symmetries":
                    if not hasattr(self, "vibsyms"):
                        self.vibsyms = []
                    self.vibsyms.extend(list(map(self.normalisesym, line[1:])))
                    line = next(inputfile).split()
                if intensities:
                    if not hasattr(self, "vibirs"):
                        self.vibirs = []
                    self.vibirs.extend(list(map(float, line[1:])))
                    line = next(inputfile).split()
                if forceconstants:
                    line = next(inputfile)

                # Start parsing the displacements.
                # Variable 'q' holds up to 7 lists of triplets.
                q = [[] for i in range(7)]
                for n in range(self.natom):
                    # Variable 'p' holds up to 7 triplets.
                    p = [[] for i in range(7)]
                    for i in range(3):
                        line = next(inputfile)
                        disps = [float(disp) for disp in line.split()[2:]]
                        for j in range(nmodes):
                            p[j].append(disps[j])
                    for i in range(nmodes):
                        q[i].append(p[i])

                self.vibdisps.extend(q[:nmodes])

                self.skip_line(inputfile, 'blank')
                freqs = next(inputfile)

            # Convert new data to arrays.
            self.vibfreqs = numpy.array(self.vibfreqs, "d")
            self.vibdisps = numpy.array(self.vibdisps, "d")
            if hasattr(self, "vibirs"):
                self.vibirs = numpy.array(self.vibirs, "d")

        # Parse excited state output (for CIS calculations).
        # Jaguar calculates only singlet states.
        if line[2:15] == "Excited State":
            if not hasattr(self, "etenergies"):
                self.etenergies = []
            if not hasattr(self, "etoscs"):
                self.etoscs = []
            if not hasattr(self, "etsecs"):
                self.etsecs = []
                self.etsyms = []
            etenergy = float(line.split()[3])
            etenergy = utils.convertor(etenergy, "eV", "cm-1")
            self.etenergies.append(etenergy)

            self.skip_lines(inputfile, ['line', 'line', 'line', 'line'])

            line = next(inputfile)
            self.etsecs.append([])
            # Jaguar calculates only singlet states.
            self.etsyms.append('Singlet-A')
            while line.strip() != "":
                fromMO = int(line.split()[0])-1
                toMO = int(line.split()[2])-1
                coeff = float(line.split()[-1])
                self.etsecs[-1].append([(fromMO, 0), (toMO, 0), coeff])
                line = next(inputfile)
            # Skip 3 lines
            for i in range(4):
                line = next(inputfile)
            strength = float(line.split()[-1])
            self.etoscs.append(strength)


if __name__ == "__main__":
    import doctest, jaguarparser
    doctest.testmod(jaguarparser, verbose=False)
