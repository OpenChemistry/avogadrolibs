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

"""Parser for ORCA output files"""

from __future__ import print_function

import numpy

from . import logfileparser
from . import utils


class ORCA(logfileparser.Logfile):
    """An ORCA log file."""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(ORCA, self).__init__(logname="ORCA", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "ORCA log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'ORCA("%s")' % (self.filename)

    def normalisesym(self, label):
        """Use standard symmetry labels instead of Gaussian labels.

        To normalise:
        (1) If label is one of [SG, PI, PHI, DLTA], replace by [sigma, pi, phi, delta]
        (2) replace any G or U by their lowercase equivalent

        >>> sym = Gaussian("dummyfile").normalisesym
        >>> labels = ['A1', 'AG', 'A1G', "SG", "PI", "PHI", "DLTA", 'DLTU', 'SGG']
        >>> map(sym, labels)
        ['A1', 'Ag', 'A1g', 'sigma', 'pi', 'phi', 'delta', 'delta.u', 'sigma.g']
        """

    def before_parsing(self):

        # A geometry optimization is started only when
        # we parse a cycle (so it will be larger than zero().
        self.gopt_cycle = 0

        # Keep track of whether this is a relaxed scan calculation
        self.is_relaxed_scan = False

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        if line[0:15] == "Number of atoms":

            natom = int(line.split()[-1])
            self.set_attribute('natom', natom)

        if line[1:13] == "Total Charge":

            charge = int(line.split()[-1])
            self.set_attribute('charge', charge)

            line = next(inputfile)

            mult = int(line.split()[-1])
            self.set_attribute('mult', mult)

        # SCF convergence output begins with:
        #
        # --------------
        # SCF ITERATIONS
        # --------------
        #
        # However, there are two common formats which need to be handled, implemented as separate functions.
        if "SCF ITERATIONS" in line:

            self.skip_line(inputfile, 'dashes')

            line = next(inputfile)
            colums = line.split()
            if colums[1] == "Energy":
                self.parse_scf_condensed_format(inputfile, colums)
            elif colums[1] == "Starting":
                self.parse_scf_expanded_format(inputfile, colums)

        # Information about the final iteration, which also includes the convergence
        # targets and the convergence values, is printed separately, in a section like this:
        #
        #       *****************************************************
        #       *                     SUCCESS                       *
        #       *           SCF CONVERGED AFTER   9 CYCLES          *
        #       *****************************************************
        #
        # ...
        #
        # Total Energy       :         -382.04963064 Eh          -10396.09898 eV
        #
        # ...
        #
        # -------------------------   ----------------
        # FINAL SINGLE POINT ENERGY     -382.049630637
        # -------------------------   ----------------
        #
        # We cannot use this last message as a stop condition in general, because
        # often there is vibrational output before it. So we use the 'Total Energy'
        # line. However, what comes after that is different for single point calculations
        # and in the inner steps of geometry optimizations.
        if "SCF CONVERGED AFTER" in line:

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            if not hasattr(self, "scfvalues"):
                self.scfvalues = []
            if not hasattr(self, "scftargets"):
                self.scftargets = []

            while not "Total Energy       :" in line:
                line = next(inputfile)
            energy = float(line.split()[5])
            self.scfenergies.append(energy)

            self._append_scfvalues_scftargets(inputfile, line)

        # Sometimes the SCF does not converge, but does not halt the
        # the run (like in bug 3184890). In this this case, we should
        # remain consistent and use the energy from the last reported
        # SCF cycle. In this case, ORCA print a banner like this:
        #
        #       *****************************************************
        #       *                     ERROR                         *
        #       *           SCF NOT CONVERGED AFTER   8 CYCLES      *
        #       *****************************************************
        if "SCF NOT CONVERGED AFTER" in line:

            if not hasattr(self, "scfenergies"):
                self.scfenergies = []
            if not hasattr(self, "scfvalues"):
                self.scfvalues = []
            if not hasattr(self, "scftargets"):
                self.scftargets = []

            energy = self.scfvalues[-1][-1][0]
            self.scfenergies.append(energy)

            self._append_scfvalues_scftargets(inputfile, line)

        # The convergence targets for geometry optimizations are printed at the
        # beginning of the output, although the order and their description is
        # different than later on. So, try to standardize the names of the criteria
        # and save them for later so that we can get the order right.
        #
        #                        *****************************
        #                        * Geometry Optimization Run *
        #                        *****************************
        #
        # Geometry optimization settings:
        # Update method            Update   .... BFGS
        # Choice of coordinates    CoordSys .... Redundant Internals
        # Initial Hessian          InHess   .... Almoef's Model
        #
        # Convergence Tolerances:
        # Energy Change            TolE     ....  5.0000e-06 Eh
        # Max. Gradient            TolMAXG  ....  3.0000e-04 Eh/bohr
        # RMS Gradient             TolRMSG  ....  1.0000e-04 Eh/bohr
        # Max. Displacement        TolMAXD  ....  4.0000e-03 bohr
        # RMS Displacement         TolRMSD  ....  2.0000e-03 bohr
        #
        if line[25:50] == "Geometry Optimization Run":

            stars = next(inputfile)
            blank = next(inputfile)

            line = next(inputfile)
            while line[0:23] != "Convergence Tolerances:":
                line = next(inputfile)

            if hasattr(self, 'geotargets'):
                self.logger.warning('The geotargets attribute should not exist yet. There is a problem in the parser.')
            self.geotargets = []
            self.geotargets_names = []

            # There should always be five tolerance values printed here.
            for i in range(5):
                line = next(inputfile)
                name = line[:25].strip().lower().replace('.', '').replace('displacement', 'step')
                target = float(line.split()[-2])
                self.geotargets_names.append(name)
                self.geotargets.append(target)

        # The convergence targets for relaxed surface scan steps are printed at the
        # beginning of the output, although the order and their description is
        # different than later on. So, try to standardize the names of the criteria
        # and save them for later so that we can get the order right.
        #
        #         *************************************************************
        #         *               RELAXED SURFACE SCAN STEP  12               *
        #         *                                                           *
        #         *   Dihedral ( 11,  10,   3,   4)  : 180.00000000           *
        #         *************************************************************
        #
        # Geometry optimization settings:
        # Update method            Update   .... BFGS
        # Choice of coordinates    CoordSys .... Redundant Internals
        # Initial Hessian          InHess   .... Almoef's Model
        #
        # Convergence Tolerances:
        # Energy Change            TolE     ....  5.0000e-06 Eh
        # Max. Gradient            TolMAXG  ....  3.0000e-04 Eh/bohr
        # RMS Gradient             TolRMSG  ....  1.0000e-04 Eh/bohr
        # Max. Displacement        TolMAXD  ....  4.0000e-03 bohr
        # RMS Displacement         TolRMSD  ....  2.0000e-03 bohr
        if line[25:50] == "RELAXED SURFACE SCAN STEP":

            self.is_relaxed_scan = True
            blank = next(inputfile)
            info = next(inputfile)
            stars = next(inputfile)
            blank = next(inputfile)

            line = next(inputfile)
            while line[0:23] != "Convergence Tolerances:":
                line = next(inputfile)

            self.geotargets = []
            self.geotargets_names = []

            # There should always be five tolerance values printed here.
            for i in range(5):
                line = next(inputfile)
                name = line[:25].strip().lower().replace('.', '').replace('displacement', 'step')
                target = float(line.split()[-2])
                self.geotargets_names.append(name)
                self.geotargets.append(target)

        # After each geometry optimization step, ORCA prints the current convergence
        # parameters and the targets (again), so it is a good idea to check that they
        # have not changed. Note that the order of these criteria here are different
        # than at the beginning of the output, so make use of the geotargets_names created
        # before and save the new geovalues in correct order.
        #
        #          ----------------------|Geometry convergence|---------------------
        #          Item                value                 Tolerance   Converged
        #          -----------------------------------------------------------------
        #          Energy change       0.00006021            0.00000500      NO
        #          RMS gradient        0.00031313            0.00010000      NO
        #          RMS step            0.01596159            0.00200000      NO
        #          MAX step            0.04324586            0.00400000      NO
        #          ....................................................
        #          Max(Bonds)      0.0218      Max(Angles)    2.48
        #          Max(Dihed)        0.00      Max(Improp)    0.00
        #          -----------------------------------------------------------------
        #
        if line[33:53] == "Geometry convergence":

            if not hasattr(self, "geovalues"):
                self.geovalues = []

            headers = next(inputfile)
            dashes = next(inputfile)

            names = []
            values = []
            targets = []
            line = next(inputfile)
            while list(set(line.strip())) != ["."]:
                name = line[10:28].strip().lower()
                value = float(line.split()[2])
                target = float(line.split()[3])
                names.append(name)
                values.append(value)
                targets.append(target)
                line = next(inputfile)

            # The energy change is normally not printed in the first iteration, because
            # there was no previous energy -- in that case assume zero. There are also some
            # edge cases where the energy change is not printed, for example when internal
            # angles become improper and internal coordinates are rebuilt as in regression
            # CuI-MePY2-CH3CN_optxes, and in such cases use NaN.
            newvalues = []
            for i, n in enumerate(self.geotargets_names):
                if (n == "energy change") and (n not in names):
                    if self.is_relaxed_scan:
                      newvalues.append(0.0)
                    else:
                      newvalues.append(numpy.nan)
                else:
                    newvalues.append(values[names.index(n)])
                    assert targets[names.index(n)] == self.geotargets[i]

            self.geovalues.append(newvalues)

        #if not an optimization, determine structure used
        if line[0:21] == "CARTESIAN COORDINATES" and not hasattr(self, "atomcoords"):

            self.skip_line(inputfile, 'dashes')

            atomnos = []
            atomcoords = []
            line = next(inputfile)
            while len(line) > 1:
                broken = line.split()
                atomnos.append(self.table.number[broken[0]])
                atomcoords.append(list(map(float, broken[1:4])))
                line = next(inputfile)

            self.set_attribute('natom', len(atomnos))
            self.set_attribute('atomnos', atomnos)

            self.atomcoords = [atomcoords]

        # There's always a banner announcing the next geometry optimization cycle,
        # which looks something like this:
        #
        #    *************************************************************
        #    *                GEOMETRY OPTIMIZATION CYCLE   2            *
        #    *************************************************************
        if "GEOMETRY OPTIMIZATION CYCLE" in line:

            # Keep track of the current cycle jsut in case, because some things
            # are printed differently inside the first/last and other cycles.
            self.gopt_cycle = int(line.split()[4])

            self.skip_lines(inputfile, ['s', 'd', 'text', 'd'])

            if not hasattr(self, "atomcoords"):
                self.atomcoords = []

            atomnos = []
            atomcoords = []
            for i in range(self.natom):
                line = next(inputfile)
                broken = line.split()
                atomnos.append(self.table.number[broken[0]])
                atomcoords.append(list(map(float, broken[1:4])))

            self.atomcoords.append(atomcoords)

            self.set_attribute('atomnos', atomnos)

        if line[21:68] == "FINAL ENERGY EVALUATION AT THE STATIONARY POINT":

            if not hasattr(self, 'optdone'):
                self.optdone = []
            self.optdone.append(len(self.atomcoords))

            self.skip_lines(inputfile, ['text', 's', 'd', 'text', 'd'])

            atomcoords = []
            for i in range(self.natom):
                line = next(inputfile)
                broken = line.split()
                atomcoords.append(list(map(float, broken[1:4])))

            self.atomcoords.append(atomcoords)

        if "The optimization did not converge" in line:
            if not hasattr(self, 'optdone'):
                self.optdone = []

        if line[0:16] == "ORBITAL ENERGIES":

            self.skip_lines(inputfile, ['d', 'text', 'text'])

            self.moenergies = [[]]
            self.homos = [[0]]

            line = next(inputfile)
            while len(line) > 20:  # restricted calcs are terminated by ------
                info = line.split()
                self.moenergies[0].append(float(info[3]))
                if float(info[1]) > 0.00:  # might be 1 or 2, depending on restricted-ness
                    self.homos[0] = int(info[0])
                line = next(inputfile)

            line = next(inputfile)

            #handle beta orbitals
            if line[17:35] == "SPIN DOWN ORBITALS":
                text = next(inputfile)

                self.moenergies.append([])
                self.homos.append(0)

                line = next(inputfile)
                while len(line) > 20:  # actually terminated by ------
                    info = line.split()
                    self.moenergies[1].append(float(info[3]))
                    if float(info[1]) == 1.00:
                        self.homos[1] = int(info[0])
                    line = next(inputfile)

        # So nbasis was parsed at first with the first pattern, but it turns out that
        # semiempirical methods (at least AM1 as reported by Julien Idé) do not use this.
        # For this reason, also check for the second patterns, and use it as an assert
        # if nbasis was already parsed. Regression PCB_1_122.out covers this test case.
        if line[1:32] == "# of contracted basis functions":
            self.set_attribute('nbasis', int(line.split()[-1]))
        if line[1:27] == "Basis Dimension        Dim":
            self.set_attribute('nbasis', int(line.split()[-1]))

        if line[0:14] == "OVERLAP MATRIX":

            self.skip_line(inputfile, 'dashes')

            self.aooverlaps = numpy.zeros((self.nbasis, self.nbasis), "d")
            for i in range(0, self.nbasis, 6):
                self.updateprogress(inputfile, "Overlap")

                header = next(inputfile)
                size = len(header.split())

                for j in range(self.nbasis):
                    line = next(inputfile)
                    broken = line.split()
                    self.aooverlaps[j, i:i+size] = list(map(float, broken[1:size+1]))

        # Molecular orbital coefficients.
        # This is also where atombasis is parsed.
        if line[0:18] == "MOLECULAR ORBITALS":

            self.skip_line(inputfile, 'dashes')

            mocoeffs = [numpy.zeros((self.nbasis, self.nbasis), "d")]
            self.aonames = []
            self.atombasis = []
            for n in range(self.natom):
                self.atombasis.append([])

            for spin in range(len(self.moenergies)):

                if spin == 1:
                    self.skip_line(inputfile, 'blank')
                    mocoeffs.append(numpy.zeros((self.nbasis, self.nbasis), "d"))

                for i in range(0, self.nbasis, 6):

                    self.updateprogress(inputfile, "Coefficients")

                    self.skip_lines(inputfile, ['numbers', 'energies', 'occs'])

                    dashes = next(inputfile)
                    broken = dashes.split()
                    size = len(broken)

                    for j in range(self.nbasis):
                        line = next(inputfile)
                        broken = line.split()

                        #only need this on the first time through
                        if spin == 0 and i == 0:
                            atomname = line[3:5].split()[0]
                            num = int(line[0:3])
                            orbital = broken[1].upper()

                            self.aonames.append("%s%i_%s" % (atomname, num+1, orbital))
                            self.atombasis[num].append(j)

                        temp = []
                        vals = line[16:-1]  # -1 to remove the last blank space
                        for k in range(0, len(vals), 10):
                            temp.append(float(vals[k:k+10]))
                        mocoeffs[spin][i:i+size, j] = temp

            self.mocoeffs = mocoeffs

        # Basis set information
        # ORCA prints this out in a somewhat indirect fashion.
        # Therefore, parsing occurs in several steps:
        # 1. read which atom belongs to which basis set group
        if line[0:21] == "BASIS SET INFORMATION":
            line = next(inputfile)
            line = next(inputfile)

            self.tmp_atnames = [] # temporary attribute, needed later
            while(not line[0:5] == '-----'):
                if line[0:4] == "Atom":
                    self.tmp_atnames.append(line[8:12].strip())
                line = next(inputfile)

        # 2. Read information for the basis set groups
        if line[0:25] == "BASIS SET IN INPUT FORMAT":
            line = next(inputfile)
            line = next(inputfile)

            # loop over basis set groups
            gbasis_tmp = {}
            while(not line[0:5] == '-----'):
                if line[1:7] == 'NewGTO':
                    bas_atname = line.split()[1]
                    gbasis_tmp[bas_atname] = []

                    line = next(inputfile)
                    # loop over contracted GTOs
                    while(not line[0:6] == '  end;'):
                        words = line.split()
                        ang = words[0]
                        nprim = int(words[1])

                        # loop over primitives
                        coeff = []
                        for iprim in range(nprim):
                            words = next(inputfile).split()
                            coeff.append( (float(words[1]), float(words[2])) )
                        gbasis_tmp[bas_atname].append((ang, coeff))

                        line = next(inputfile)
                line = next(inputfile)

            # 3. Assign the basis sets to gbasis
            self.gbasis = []
            for bas_atname in self.tmp_atnames:
                self.gbasis.append(gbasis_tmp[bas_atname])
            del self.tmp_atnames

        # Read TDDFT information
        if line[0:18] == "TD-DFT/TDA EXCITED":
            # Could be singlets or triplets
            if line.find("SINGLETS") >= 0:
                sym = "Singlet"
            elif line.find("TRIPLETS") >= 0:
                sym = "Triplet"
            else:
                sym = "Not specified"

            if not hasattr(self, "etenergies"):
                self.etsecs = []
                self.etenergies = []
                self.etsyms = []

            lookup = {'a': 0, 'b': 1}
            line = next(inputfile)
            while line.find("STATE") < 0:
                line = next(inputfile)
            # Contains STATE or is blank
            while line.find("STATE") >= 0:
                broken = line.split()
                self.etenergies.append(float(broken[-2]))
                self.etsyms.append(sym)
                line = next(inputfile)
                sec = []
                # Contains SEC or is blank
                while line.strip():
                    start = line[0:8].strip()
                    start = (int(start[:-1]), lookup[start[-1]])
                    end = line[10:17].strip()
                    end = (int(end[:-1]), lookup[end[-1]])
                    contrib = float(line[35:47].strip())
                    sec.append([start, end, contrib])
                    line = next(inputfile)
                self.etsecs.append(sec)
                line = next(inputfile)

        # This will parse etoscs for TD calculations, but note that ORCA generally
        # prints two sets, one based on the length form of transition dipole moments,
        # the other based on the velocity form. Although these should be identical
        # in the basis set limit, in practice they are rarely the same. Here we will
        # effectively parse just the spectrum based on the length-form.
        if (line[25:44] == "ABSORPTION SPECTRUM" or line[9:28] == "ABSORPTION SPECTRUM") and not hasattr(self, "etoscs"):

            self.skip_lines(inputfile, ['d', 'header', 'header', 'd'])

            self.etoscs = []
            for x in self.etsyms:
                osc = next(inputfile).split()[3]
                if osc == "spin":  # "spin forbidden"
                    osc = 0
                else:
                    osc = float(osc)
                self.etoscs.append(osc)

        if line[0:23] == "VIBRATIONAL FREQUENCIES":

            self.skip_lines(inputfile, ['d', 'b'])

            self.vibfreqs = numpy.zeros((3 * self.natom,), "d")

            for i in range(3 * self.natom):
                line = next(inputfile)
                self.vibfreqs[i] = float(line.split()[1])

            if numpy.any(self.vibfreqs[0:6] != 0):
                msg = "Modes corresponding to rotations/translations "
                msg += "may be non-zero."
                self.logger.warning(msg)

            self.vibfreqs = self.vibfreqs[6:]

        if line[0:12] == "NORMAL MODES":
            """ Format:
            NORMAL MODES
            ------------

            These modes are the cartesian displacements weighted by the diagonal matrix
            M(i,i)=1/sqrt(m[i]) where m[i] is the mass of the displaced atom
            Thus, these vectors are normalized but *not* orthogonal

                              0          1          2          3          4          5
                  0       0.000000   0.000000   0.000000   0.000000   0.000000   0.000000
                  1       0.000000   0.000000   0.000000   0.000000   0.000000   0.000000
                  2       0.000000   0.000000   0.000000   0.000000   0.000000   0.000000
            ...
            """

            self.vibdisps = numpy.zeros((3 * self.natom, self.natom, 3), "d")

            self.skip_lines(inputfile, ['d', 'b', 'text', 'text', 'text', 'b'])

            for mode in range(0, 3 * self.natom, 6):
                header = next(inputfile)
                for atom in range(self.natom):
                    x = next(inputfile).split()[1:]
                    y = next(inputfile).split()[1:]
                    z = next(inputfile).split()[1:]

                    self.vibdisps[mode:mode + 6, atom, 0] = x
                    self.vibdisps[mode:mode + 6, atom, 1] = y
                    self.vibdisps[mode:mode + 6, atom, 2] = z

            self.vibdisps = self.vibdisps[6:]

        if line[0:11] == "IR SPECTRUM":

            self.skip_lines(inputfile, ['d', 'b', 'header', 'd'])

            self.vibirs = numpy.zeros((3 * self.natom,), "d")

            line = next(inputfile)
            while len(line) > 2:
                num = int(line[0:4])
                self.vibirs[num] = float(line.split()[2])
                line = next(inputfile)

            self.vibirs = self.vibirs[6:]

        if line[0:14] == "RAMAN SPECTRUM":

            self.skip_lines(inputfile, ['d', 'b', 'header', 'd'])

            self.vibramans = numpy.zeros((3 * self.natom,), "d")

            line = next(inputfile)
            while len(line) > 2:
                num = int(line[0:4])
                self.vibramans[num] = float(line.split()[2])
                line = next(inputfile)

            self.vibramans = self.vibramans[6:]

        # ORCA will print atomic charges along with the spin populations,
        #   so care must be taken about choosing the proper column.
        # Population analyses are performed usually only at the end
        #   of a geometry optimization or other run, so we want to
        #   leave just the final atom charges.
        # Here is an example for Mulliken charges:
        # --------------------------------------------
        # MULLIKEN ATOMIC CHARGES AND SPIN POPULATIONS
        # --------------------------------------------
        #    0 H :    0.126447    0.002622
        #    1 C :   -0.613018   -0.029484
        #    2 H :    0.189146    0.015452
        #    3 H :    0.320041    0.037434
        # ...
        # Sum of atomic charges         :   -0.0000000
        # Sum of atomic spin populations:    1.0000000
        if line[:23] == "MULLIKEN ATOMIC CHARGES":

            has_spins = "AND SPIN POPULATIONS" in line

            if not hasattr(self, "atomcharges"):
                self.atomcharges = {}
            if has_spins and not hasattr(self, "atomspins"):
                self.atomspins = {}

            self.skip_line(inputfile, 'dashes')

            charges = []
            if has_spins:
                spins = []
            line = next(inputfile)
            while line[:21] != "Sum of atomic charges":
                charges.append(float(line[8:20]))
                if has_spins:
                    spins.append(float(line[20:]))
                line = next(inputfile)
            self.atomcharges["mulliken"] = charges
            if has_spins:
                self.atomspins["mulliken"] = spins

        # Things are the same for Lowdin populations, except that the sums
        #   are not printed (there is a blank line at the end).
        if line[:22] == "LOEWDIN ATOMIC CHARGES":

            has_spins = "AND SPIN POPULATIONS" in line

            if not hasattr(self, "atomcharges"):
                self.atomcharges = {}
            if has_spins and not hasattr(self, "atomspins"):
                self.atomspins = {}

            self.skip_line(inputfile, 'dashes')

            charges = []
            if has_spins:
                spins = []
            line = next(inputfile)
            while line.strip():
                charges.append(float(line[8:20]))
                if has_spins:
                    spins.append(float(line[20:]))
                line = next(inputfile)
            self.atomcharges["lowdin"] = charges
            if has_spins:
                self.atomspins["lowdin"] = spins

        # It is not stated explicitely, but the dipole moment components printed by ORCA
        # seem to be in atomic units, so they will need to be converted. Also, they
        # are most probably calculated with respect to the origin .
        #
        # -------------
        # DIPOLE MOMENT
        # -------------
        #                                 X             Y             Z
        # Electronic contribution:      0.00000      -0.00000      -0.00000
        # Nuclear contribution   :      0.00000       0.00000       0.00000
        #                         -----------------------------------------
        # Total Dipole Moment    :      0.00000      -0.00000      -0.00000
        #                         -----------------------------------------
        # Magnitude (a.u.)       :      0.00000
        # Magnitude (Debye)      :      0.00000
        #
        if line.strip() == "DIPOLE MOMENT":

            self.skip_lines(inputfile, ['d', 'XYZ', 'electronic', 'nuclear', 'd'])
            total = next(inputfile)
            assert "Total Dipole Moment" in total

            reference = [0.0, 0.0, 0.0]
            dipole = numpy.array([float(d) for d in total.split()[-3:]])
            dipole = utils.convertor(dipole, "ebohr", "Debye")

            if not hasattr(self, 'moments'):
                self.moments = [reference, dipole]
            else:
                try:
                    assert numpy.all(self.moments[1] == dipole)
                except AssertionError:
                    self.logger.warning('Overwriting previous multipole moments with new values')
                    self.moments = [reference, dipole]

    def parse_scf_condensed_format(self, inputfile, line):
        """ Parse the SCF convergence information in condensed format """

        # This is what it looks like
        # ITER       Energy         Delta-E        Max-DP      RMS-DP      [F,P]     Damp
        #                ***  Starting incremental Fock matrix formation  ***
        #   0   -384.5203638934   0.000000000000 0.03375012  0.00223249  0.1351565 0.7000
        #   1   -384.5792776162  -0.058913722842 0.02841696  0.00175952  0.0734529 0.7000
        #                                ***Turning on DIIS***
        #   2   -384.6074211837  -0.028143567475 0.04968025  0.00326114  0.0310435 0.0000
        #   3   -384.6479682063  -0.040547022616 0.02097477  0.00121132  0.0361982 0.0000
        #   4   -384.6571124353  -0.009144228947 0.00576471  0.00035160  0.0061205 0.0000
        #   5   -384.6574659959  -0.000353560584 0.00191156  0.00010160  0.0025838 0.0000
        #   6   -384.6574990782  -0.000033082375 0.00052492  0.00003800  0.0002061 0.0000
        #   7   -384.6575005762  -0.000001497987 0.00020257  0.00001146  0.0001652 0.0000
        #   8   -384.6575007321  -0.000000155848 0.00008572  0.00000435  0.0000745 0.0000
        #          **** Energy Check signals convergence ****

        assert line[2] == "Delta-E"
        assert line[3] == "Max-DP"

        if not hasattr(self, "scfvalues"):
            self.scfvalues = []

        self.scfvalues.append([])

        # Try to keep track of the converger (NR, DIIS, SOSCF, etc.).
        diis_active = True
        while not line == []:

            if 'Newton-Raphson' in line:
                diis_active = False
            elif 'SOSCF' in line:
                diis_active = False
            elif line[0].isdigit() and diis_active:
                energy = float(line[1])
                deltaE = float(line[2])
                maxDP = float(line[3])
                rmsDP = float(line[4])
                self.scfvalues[-1].append([deltaE, maxDP, rmsDP])
            elif line[0].isdigit() and not diis_active:
                energy = float(line[1])
                deltaE = float(line[2])
                maxDP = float(line[5])
                rmsDP = float(line[6])
                self.scfvalues[-1].append([deltaE, maxDP, rmsDP])
            try:
                line = next(inputfile).split()
            except StopIteration:
                self.logger.warning('File terminated before end of last SCF! Last Max-DP: {}'.format(maxDP))
                break

    def parse_scf_expanded_format(self, inputfile, line):
        """ Parse SCF convergence when in expanded format. """

        # The following is an example of the format
        # -----------------------------------------
        #
        #               ***  Starting incremental Fock matrix formation  ***
        #
        #                         ----------------------------
        #                         !        ITERATION     0   !
        #                         ----------------------------
        #   Total Energy        :    -377.960836651297 Eh
        #   Energy Change       :    -377.960836651297 Eh
        #   MAX-DP              :       0.100175793695
        #   RMS-DP              :       0.004437973661
        #   Actual Damping      :       0.7000
        #   Actual Level Shift  :       0.2500 Eh
        #   Int. Num. El.       :    43.99982197 (UP=   21.99991099 DN=   21.99991099)
        #   Exchange            :   -34.27550826
        #   Correlation         :    -2.02540957
        #
        #
        #                         ----------------------------
        #                         !        ITERATION     1   !
        #                         ----------------------------
        #   Total Energy        :    -378.118458080109 Eh
        #   Energy Change       :      -0.157621428812 Eh
        #   MAX-DP              :       0.053240648588
        #   RMS-DP              :       0.002375092508
        #   Actual Damping      :       0.7000
        #   Actual Level Shift  :       0.2500 Eh
        #   Int. Num. El.       :    43.99994143 (UP=   21.99997071 DN=   21.99997071)
        #   Exchange            :   -34.00291075
        #   Correlation         :    -2.01607243
        #
        #                               ***Turning on DIIS***
        #
        #                         ----------------------------
        #                         !        ITERATION     2   !
        #                         ----------------------------
        # ....
        #
        if not hasattr(self, "scfvalues"):
            self.scfvalues = []

        self.scfvalues.append([])

        line = "Foo"  # dummy argument to enter loop
        while line.find("******") < 0:
            try:
                line = next(inputfile)
            except StopIteration:
                self.logger.warning('File terminated before end of last SCF!')
                break
            info = line.split()
            if len(info) > 1 and info[1] == "ITERATION":
                dashes = next(inputfile)
                energy_line = next(inputfile).split()
                energy = float(energy_line[3])
                deltaE_line = next(inputfile).split()
                deltaE = float(deltaE_line[3])
                if energy == deltaE:
                    deltaE = 0
                maxDP_line = next(inputfile).split()
                maxDP = float(maxDP_line[2])
                rmsDP_line = next(inputfile).split()
                rmsDP = float(rmsDP_line[2])
                self.scfvalues[-1].append([deltaE, maxDP, rmsDP])

        return

    # end of parse_scf_expanded_format

    def _append_scfvalues_scftargets(self, inputfile, line):
        # The SCF convergence targets are always printed after this, but apparently
        # not all of them always -- for example the RMS Density is missing for geometry
        # optimization steps. So, assume the previous value is still valid if it is
        # not found. For additional certainty, assert that the other targets are unchanged.
        while not "Last Energy change" in line:
            line = next(inputfile)
        deltaE_value = float(line.split()[4])
        deltaE_target = float(line.split()[7])
        line = next(inputfile)
        if "Last MAX-Density change" in line:
            maxDP_value = float(line.split()[4])
            maxDP_target = float(line.split()[7])
            line = next(inputfile)
            if "Last RMS-Density change" in line:
                rmsDP_value = float(line.split()[4])
                rmsDP_target = float(line.split()[7])
            else:
                rmsDP_value = self.scfvalues[-1][-1][2]
                rmsDP_target = self.scftargets[-1][2]
                assert deltaE_target == self.scftargets[-1][0]
                assert maxDP_target == self.scftargets[-1][1]
            self.scfvalues[-1].append([deltaE_value, maxDP_value, rmsDP_value])
            self.scftargets.append([deltaE_target, maxDP_target, rmsDP_target])


if __name__ == "__main__":
    import sys
    import doctest, orcaparser

    if len(sys.argv) == 1:
        doctest.testmod(orcaparser, verbose=False)

    if len(sys.argv) == 2:
        parser = orcaparser.ORCA(sys.argv[1])
        data = parser.parse()

    if len(sys.argv) > 2:
        for i in range(len(sys.argv[2:])):
            if hasattr(data, sys.argv[2 + i]):
                print(getattr(data, sys.argv[2 + i]))
