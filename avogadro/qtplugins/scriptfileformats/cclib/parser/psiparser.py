# -*- coding: utf-8 -*-
#
# This file is part of cclib (http://cclib.github.io), a library for parsing
# and interpreting the results of computational chemistry packages.
#
# Copyright (C) 2008-2014, the cclib development team
#
# The library is free software, distributed under the terms of
# the GNU Lesser General Public version 2.1 or later. You should have
# received a copy of the license along with cclib. You can also access
# the full license online at http://www.gnu.org/copyleft/lgpl.html.

"""Parser for Psi3 and Psi4 output files"""

import numpy

from . import logfileparser
from . import utils


class Psi(logfileparser.Logfile):
    """A Psi log file."""

    def __init__(self, *args, **kwargs):

        # Call the __init__ method of the superclass
        super(Psi, self).__init__(logname="Psi", *args, **kwargs)

    def __str__(self):
        """Return a string representation of the object."""
        return "Psi log file %s" % (self.filename)

    def __repr__(self):
        """Return a representation of the object."""
        return 'Psi("%s")' % (self.filename)

    def before_parsing(self):

        # There are some major differences between the output of Psi3 and Psi4,
        # so it will be useful to register which one we are dealing with.
        self.version = None

        # This is just used to track which part of the output we are in for Psi4,
        # with changes triggered by ==> things like this <== (Psi3 does not have this)
        self.section = None

    def normalisesym(self, label):
        """Use standard symmetry labels instead of NWChem labels.

        To normalise:
        (1) If label is one of [SG, PI, PHI, DLTA], replace by [sigma, pi, phi, delta]
        (2) replace any G or U by their lowercase equivalent

        >>> sym = NWChem("dummyfile").normalisesym
        >>> labels = ['A1', 'AG', 'A1G', "SG", "PI", "PHI", "DLTA", 'DLTU', 'SGG']
        >>> map(sym, labels)
        ['A1', 'Ag', 'A1g', 'sigma', 'pi', 'phi', 'delta', 'delta.u', 'sigma.g']
        """
        # FIXME if necessary
        return label

    def extract(self, inputfile, line):
        """Extract information from the file object inputfile."""

        # The version should always be detected.
        if "PSI3: An Open-Source Ab Initio" in line:
            self.version = 3
        if "PSI4: An Open-Source Ab Initio".lower() in line.lower():
            self.version = 4

        # This will automatically change the section attribute for Psi4, when encountering
        # a line that <== looks like this ==>, to whatever is in between.
        if (line.strip()[:3] == "==>") and (line.strip()[-3:] == "<=="):
            self.section = line.strip()[4:-4]

        # Psi3 print the coordinates in several configurations, and we will parse the
        # the canonical coordinates system in Angstroms as the first coordinate set,
        # although ir is actually somewhere later in the input, after basis set, etc.
        # We can also get or verify he number of atoms and atomic numbers from this block.
        if (self.version == 3) and (line.strip() == "-Geometry in the canonical coordinate system (Angstrom):"):

            self.skip_lines(inputfile, ['header', 'd'])

            coords = []
            numbers = []
            line = next(inputfile)
            while line.strip():

                element = line.split()[0]
                numbers.append(self.table.number[element])

                x = float(line.split()[1])
                y = float(line.split()[2])
                z = float(line.split()[3])
                coords.append([x, y, z])

                line = next(inputfile)

            self.set_attribute('natom', len(coords))
            self.set_attribute('atomnos', numbers)

            if not hasattr(self, 'atomcoords'):
                self.atomcoords = []
            self.atomcoords.append(coords)

        #  ==> Geometry <==
        #
        #    Molecular point group: c2h
        #    Full point group: C2h
        #
        #    Geometry (in Angstrom), charge = 0, multiplicity = 1:
        #
        #       Center              X                  Y                   Z
        #    ------------   -----------------  -----------------  -----------------
        #           C         -1.415253322400     0.230221785400     0.000000000000
        #           C          1.415253322400    -0.230221785400     0.000000000000
        # ...
        #
        if (self.section == "Geometry") and ("Geometry (in Angstrom), charge" in line):

            assert line.split()[3] == "charge"
            charge = int(line.split()[5].strip(','))
            self.set_attribute('charge', charge)

            assert line.split()[6] == "multiplicity"
            mult = int(line.split()[8].strip(':'))
            self.set_attribute('mult', mult)

            self.skip_line(inputfile, "blank")
            line = next(inputfile)

            # Usually there is the header and dashes, but, for example, the coordinates
            # printed when a geometry optimization finishes do not have it.
            if line.split()[0] == "Center":
                self.skip_line(inputfile, "dashes")
                line = next(inputfile)

            elements = []
            coords = []
            while line.strip():
                el, x, y, z = line.split()[:4]
                elements.append(el)
                coords.append([float(x), float(y), float(z)])
                line = next(inputfile)

            self.set_attribute('atomnos', [self.table.number[el] for el in elements])

            if not hasattr(self, 'atomcoords'):
                self.atomcoords = []

            # This condition discards any repeated coordinates that Psi print. For example,
            # geometry optimizations will print the coordinates at the beginning of and SCF
            # section and also at the start of the gradient calculation.
            if len(self.atomcoords) == 0 or self.atomcoords[-1] != coords:
                self.atomcoords.append(coords)

        # In Psi3 there are these two helpful sections.
        if (self.version == 3) and (line.strip() == '-SYMMETRY INFORMATION:'):
            line = next(inputfile)
            while line.strip():
                if "Number of atoms" in line:
                    self.set_attribute('natom', int(line.split()[-1]))
                line = next(inputfile)
        if (self.version == 3) and (line.strip() == "-BASIS SET INFORMATION:"):
            line = next(inputfile)
            while line.strip():
                if "Number of AO" in line:
                    self.set_attribute('nbasis', int(line.split()[-1]))
                line = next(inputfile)

        # Psi4 repeats the charge and multiplicity after the geometry.
        if (self.section == "Geometry") and (line[2:16].lower() == "charge       ="):
            charge = int(line.split()[-1])
            self.set_attribute('charge', charge)
        if (self.section == "Geometry") and (line[2:16].lower() == "multiplicity ="):
            mult = int(line.split()[-1])
            self.set_attribute('mult', mult)

        # In Psi3, the section with the contraction scheme can be used to infer atombasis.
        if (self.version == 3) and line.strip() == "-Contraction Scheme:":

            self.skip_lines(inputfile, ['header', 'd'])

            indices = []
            line = next(inputfile)
            while line.strip():
                shells = line.split('//')[-1]
                expression = shells.strip().replace(' ', '+')
                expression = expression.replace('s', '*1')
                expression = expression.replace('p', '*3')
                expression = expression.replace('d', '*6')
                nfuncs = eval(expression)
                if len(indices) == 0:
                    indices.append(range(nfuncs))
                else:
                    start = indices[-1][-1] + 1
                    indices.append(range(start, start+nfuncs))
                line = next(inputfile)

            self.set_attribute('atombasis', indices)

        # In Psi3, the integrals program prints useful information when invoked.
        if (self.version == 3) and (line.strip() == "CINTS: An integrals program written in C"):

            self.skip_lines(inputfile, ['authors', 'd', 'b', 'b'])

            line = next(inputfile)
            assert line.strip() == "-OPTIONS:"
            while line.strip():
                line = next(inputfile)

            line = next(inputfile)
            assert line.strip() == "-CALCULATION CONSTANTS:"
            while line.strip():
                if "Number of atoms" in line:
                    natom = int(line.split()[-1])
                    self.set_attribute('natom', natom)
                if "Number of atomic orbitals" in line:
                    nbasis = int(line.split()[-1])
                    self.set_attribute('nbasis', nbasis)
                line = next(inputfile)

        # In Psi3, this part contains alot of important data pertaining to the SCF, but not only:
        if (self.version == 3) and (line.strip() == "CSCF3.0: An SCF program written in C"):

            self.skip_lines(inputfile, ['b', 'authors', 'b', 'd', 'b', 'mult', 'mult_comment', 'b'])

            line = next(inputfile)
            while line.strip():
                if line.split()[0] == "multiplicity":
                    mult = int(line.split()[-1])
                    self.set_attribute('mult', mult)
                if line.split()[0] == "charge":
                    charge = int(line.split()[-1])
                    self.set_attribute('charge', charge)
                if line.split()[0] == "convergence":
                    conv = float(line.split()[-1])
                line = next(inputfile)

            if not hasattr(self, 'scftargets'):
                self.scftargets = []
            self.scftargets.append([conv])

        # The printout for Psi4 has a more obvious trigger for the SCF parameter printout.
        if (self.section == "Algorithm") and (line.strip() == "==> Algorithm <=="):

            self.skip_line(inputfile, 'blank')

            line = next(inputfile)
            while line.strip():
                if "Energy threshold" in line:
                    etarget = float(line.split()[-1])
                if "Density threshold" in line:
                    dtarget = float(line.split()[-1])
                line = next(inputfile)

            if not hasattr(self, "scftargets"):
                self.scftargets = []
            self.scftargets.append([etarget, dtarget])

        # This section prints contraction information before the atomic basis set functions and
        # is a good place to parse atombasis indices as well as atomnos. However, the section this line
        # is in differs between HF and DFT outputs.
        #
        #  -Contraction Scheme:
        #    Atom   Type   All Primitives // Shells:
        #   ------ ------ --------------------------
        #       1     C     6s 3p // 2s 1p
        #       2     C     6s 3p // 2s 1p
        #       3     C     6s 3p // 2s 1p
        # ...
        if (self.section == "Primary Basis" or self.section == "DFT Potential") and line.strip() == "-Contraction Scheme:":

            self.skip_lines(inputfile, ['headers', 'd'])

            atomnos = []
            atombasis = []
            atombasis_pos = 0
            line = next(inputfile)
            while line.strip():

                element = line.split()[1]
                atomnos.append(self.table.number[element])

                # To count the number of atomic orbitals for the atom, sum up the orbitals
                # in each type of shell, times the numbers of shells. Currently, we assume
                # the multiplier is a single digit and that there are only s and p shells,
                # which will need to be extended later when considering larger basis sets,
                # with corrections for the cartesian/spherical cases.
                ao_count = 0
                shells = line.split('//')[1].split()
                for s in shells:
                    count, type = s
                    multiplier = 3*(type == 'p') or 1
                    ao_count += multiplier*int(count)

                if len(atombasis) > 0:
                    atombasis_pos = atombasis[-1][-1] + 1
                atombasis.append(list(range(atombasis_pos, atombasis_pos+ao_count)))

                line = next(inputfile)

            self.set_attribute('natom', len(atomnos))
            self.set_attribute('atomnos', atomnos)
            self.set_attribute('atombasis', atombasis)

        # The atomic basis set is straightforward to parse, but there are some complications
        # when symmetry is used, because in that case Psi4 only print the symmetry-unique atoms,
        # and the list of symmetry-equivalent ones is not printed. Therefore, for simplicity here
        # when an atomic is missing (atom indices are printed) assume the atomic orbitals of the
        # last atom of the same element before it. This might not work if a mixture of basis sets
        # is used somehow... but it should cover almost all cases for now.
        #
        # Note that Psi also print normalized coefficients (details below).
        #
        #  ==> AO Basis Functions <==
        #
        #    [ STO-3G ]
        #    spherical
        #    ****
        #    C   1
        #    S   3 1.00
        #                        71.61683700           2.70781445
        #                        13.04509600           2.61888016
        # ...
        if (self.section == "AO Basis Functions") and (line.strip() == "==> AO Basis Functions <=="):

            def get_symmetry_atom_basis(gbasis):
                """Get symmetry atom by replicating the last atom in gbasis of the same element."""

                missing_index = len(gbasis)
                missing_atomno = self.atomnos[missing_index]

                ngbasis = len(gbasis)
                last_same = ngbasis - self.atomnos[:ngbasis][::-1].index(missing_atomno) - 1
                return gbasis[last_same]

            dfact = lambda n: (n <= 0) or n * dfact(n-2)

            def get_normalization_factor(exp, lx, ly, lz):
                norm_s = (2*exp/numpy.pi)**0.75
                if lx + ly + lz > 0:
                    nom = (4*exp)**((lx+ly+lz)/2.0)
                    den = numpy.sqrt(dfact(2*lx-1) * dfact(2*ly-1) * dfact(2*lz-1))
                    return norm_s * nom / den
                else:
                    return norm_s

            self.skip_lines(inputfile, ['b', 'basisname'])

            line = next(inputfile)
            spherical = line.strip() == "spherical"
            if hasattr(self, 'spherical_basis'):
                assert self.spherical_basis == spherical
            else:
                self.spherical_basis = spherical

            gbasis = []
            self.skip_line(inputfile, 'stars')
            line = next(inputfile)
            while line.strip():

                element, index = line.split()
                atomno = self.table.number[element]
                index = int(index)

                # This is the code that adds missing atoms when symmetry atoms are excluded
                # from the basis set printout. Again, this will work only if all atoms of
                # the same element use the same basis set.
                while index > len(gbasis) + 1:
                    gbasis.append(get_symmetry_atom_basis(gbasis))

                gbasis.append([])
                line = next(inputfile)
                while line.find("*") == -1:

                    # The shell type and primitive count is in the first line.
                    shell_type, nprimitives, smthg = line.split()
                    nprimitives = int(nprimitives)

                    # Get the angular momentum for this shell type.
                    momentum = {'S': 0, 'P': 1, 'D': 2, 'F': 3, 'G': 4}[shell_type.upper()]

                    # Read in the primitives.
                    primitives_lines = [next(inputfile) for i in range(nprimitives)]
                    primitives = [list(map(float, pl.split())) for pl in primitives_lines]

                    # Un-normalize the coefficients. Psi prints the normalized coefficient
                    # of the highest polynomial, namely XX for D orbitals, XXX for F, and so on.
                    for iprim, prim in enumerate(primitives):
                        exp, coef = prim
                        coef = coef / get_normalization_factor(exp, momentum, 0, 0)
                        primitives[iprim] = [exp, coef]

                    primitives = [tuple(p) for p in primitives]
                    shell = [shell_type, primitives]
                    gbasis[-1].append(shell)

                    line = next(inputfile)

                line = next(inputfile)

            # We will also need to add symmetry atoms that are missing from the input
            # at the end of this block, if the symmetry atoms are last.
            while len(gbasis) < self.natom:
                gbasis.append(get_symmetry_atom_basis(gbasis))

            self.gbasis = gbasis

        # A block called 'Calculation Information' prints these before starting the SCF.
        if (self.section == "Pre-Iterations") and ("Number of atoms" in line):
            natom = int(line.split()[-1])
            self.set_attribute('natom', natom)
        if (self.section == "Pre-Iterations") and ("Number of atomic orbitals" in line):
            nbasis = int(line.split()[-1])
            self.set_attribute('nbasis', nbasis)

        #  ==> Iterations <==

        # Psi3 converges just the density elements, although it reports in the iterations
        # changes in the energy as well as the DIIS error.
        psi3_iterations_header = "iter       total energy        delta E         delta P          diiser"
        if (self.version == 3) and (line.strip() == psi3_iterations_header):

            if not hasattr(self, 'scfvalues'):
                self.scfvalues = []
            self.scfvalues.append([])

            line = next(inputfile)
            while line.strip():
                ddensity = float(line.split()[-2])
                self.scfvalues[-1].append([ddensity])
                line = next(inputfile)

        # Psi4 converges both the SCF energy and density elements and reports both in the
        # iterations printout. However, the default convergence scheme involves a density-fitted
        # algorithm for efficiency, and this is often followed by a something with exact electron
        # repulsion integrals. In that case, there are actually two convergence cycles performed,
        # one for the density-fitted algorithm and one for the exact one, and the iterations are
        # printed in two blocks separated by some set-up information.
        if (self.section == "Iterations") and (line.strip() == "==> Iterations <=="):

            if not hasattr(self, 'scfvalues'):
                self.scfvalues = []

            self.skip_line(inputfile, 'blank')
            header = next(inputfile)
            assert header.strip() == "Total Energy        Delta E     RMS |[F,P]|"

            scfvals = []
            self.skip_line(inputfile, 'blank')
            line = next(inputfile)
            while line.strip() != "==> Post-Iterations <==":
                if line.strip() and line.split()[0] in ["@DF-RHF", "@RHF", "@DF-RKS", "@RKS"]:
                    denergy = float(line.split()[4])
                    ddensity = float(line.split()[5])
                    scfvals.append([denergy, ddensity])
                try:
                    line = next(inputfile)
                except StopIteration:
                    self.logger.warning('File terminated before end of last SCF! Last density err: {}'.format(ddensity))
                    break
            self.section = "Post-Iterations"
            self.scfvalues.append(scfvals)

        # This section, from which we parse molecular orbital symmetries and
        # orbital energies, is quite similar for both Psi3 and Psi4, and in fact
        # the format for orbtials is the same, although the headers and spacers
        # are a bit different. Let's try to get both parsed with one code block.
        #
        # Here is how the block looks like for Psi4:
        #
        #	Orbital Energies (a.u.)
        #	-----------------------
        #
        #	Doubly Occupied:
        #
        #	   1Bu   -11.040586     1Ag   -11.040524     2Bu   -11.031589
        #	   2Ag   -11.031589     3Bu   -11.028950     3Ag   -11.028820
        # (...)
        #	  15Ag    -0.415620     1Bg    -0.376962     2Au    -0.315126
        #	   2Bg    -0.278361     3Bg    -0.222189
        #
        #	Virtual:
        #
        #	   3Au     0.198995     4Au     0.268517     4Bg     0.308826
        #	   5Au     0.397078     5Bg     0.521759    16Ag     0.565017
        # (...)
        #	  24Ag     0.990287    24Bu     1.027266    25Ag     1.107702
        #	  25Bu     1.124938
        #
        # The case is different in the trigger string.
        if "orbital energies (a.u.)" in line.lower():

            # If this is Psi4, we will be in the appropriate section.
            assert (self.version == 3) or (self.section == "Post-Iterations")

            self.moenergies = [[]]
            self.mosyms = [[]]

            # Psi4 has dashes under the trigger line, but Psi3 did not.
            if self.version == 4:
                self.skip_line(inputfile, 'dashes')
            self.skip_line(inputfile, 'blank')

            # Both versions have this case insensisitive substring.
            doubly = next(inputfile)
            assert "doubly occupied" in doubly.lower()

            # Psi4 now has a blank line, Psi3 does not.
            if self.version == 4:
                self.skip_line(inputfile, 'blank')

            line = next(inputfile)
            while line.strip():
                for i in range(len(line.split())//2):
                    self.mosyms[0].append(line.split()[i*2][-2:])
                    self.moenergies[0].append(line.split()[i*2+1])
                line = next(inputfile)

            # The last orbital energy here represented the HOMO.
            self.homos = [len(self.moenergies[0])-1]

            # Different numbers of blank lines in Psi3 and Psi4.
            if self.version == 3:
                self.skip_line(inputfile, 'blank')

            # The header for virtual orbitals is different for the two versions.
            unoccupied = next(inputfile)
            if self.version == 3:
                assert unoccupied.strip() == "Unoccupied orbitals"
            else:
                assert unoccupied.strip() == "Virtual:"

            # Psi4 now has a blank line, Psi3 does not.
            if self.version == 4:
                self.skip_line(inputfile, 'blank')

            line = next(inputfile)
            while line.strip():
                for i in range(len(line.split())//2):
                    self.mosyms[0].append(line.split()[i*2][-2:])
                    self.moenergies[0].append(line.split()[i*2+1])
                line = next(inputfile)

        # Both Psi3 and Psi4 print the final SCF energy right after the orbital energies,
        # but the label is different. Psi4 also does DFT, and the label is also different in that case.
        if (self.version == 3 and "* SCF total energy" in line) or \
           (self.section == "Post-Iterations" and ("@RHF Final Energy:" in line or "@RKS Final Energy" in line)):
            e = float(line.split()[-1])
            if not hasattr(self, 'scfenergies'):
                self.scfenergies = []
            self.scfenergies.append(utils.convertor(e, 'hartree', 'eV'))

        #  ==> Molecular Orbitals <==
        #
        #                 1            2            3            4            5
        #
        #    1    0.7014827    0.7015412    0.0096801    0.0100168    0.0016438
        #    2    0.0252630    0.0251793   -0.0037890   -0.0037346    0.0016447
        # ...
        #   59    0.0000133   -0.0000067    0.0000005   -0.0047455   -0.0047455
        #   60    0.0000133    0.0000067    0.0000005    0.0047455   -0.0047455
        #
        # Ene   -11.0288198  -11.0286067  -11.0285837  -11.0174766  -11.0174764
        # Sym            Ag           Bu           Ag           Bu           Ag
        # Occ             2            2            2            2            2
        #
        #
        #                11           12           13           14           15
        #
        #    1    0.1066946    0.1012709    0.0029709    0.0120562    0.1002765
        #    2   -0.2753689   -0.2708037   -0.0102079   -0.0329973   -0.2790813
        # ...
        #
        if (self.section == "Molecular Orbitals") and (line.strip() == "==> Molecular Orbitals <=="):

            self.skip_line(inputfile, 'blank')

            mocoeffs = []
            indices = next(inputfile)
            while indices.strip():

                indices = [int(i) for i in indices.split()]

                if len(mocoeffs) < indices[-1]:
                    for i in range(len(indices)):
                        mocoeffs.append([])
                else:
                    assert len(mocoeffs) == indices[-1]

                self.skip_line(inputfile, 'blank')

                line = next(inputfile)
                while line.strip():
                    iao = int(line.split()[0])
                    coeffs = [float(c) for c in line.split()[1:]]
                    for i, c in enumerate(coeffs):
                        mocoeffs[indices[i]-1].append(c)
                    line = next(inputfile)

                energies = next(inputfile)
                symmetries = next(inputfile)
                occupancies = next(inputfile)

                self.skip_lines(inputfile, ['b', 'b'])
                indices = next(inputfile)

            if not hasattr(self, 'mocoeffs'):
                self.mocoeffs = []
            self.mocoeffs.append(mocoeffs)

        # The formats for Mulliken and Lowdin atomic charges are the same, just with
        # the name changes, so use the same code for both.
        #
        # Properties computed using the SCF density density matrix
        #   Mulliken Charges: (a.u.)
        #    Center  Symbol    Alpha    Beta     Spin     Total
        #        1     C     2.99909  2.99909  0.00000  0.00182
        #        2     C     2.99909  2.99909  0.00000  0.00182
        # ...
        for pop_type in ["Mulliken", "Lowdin"]:
            if line.strip() == "%s Charges: (a.u.)" % pop_type:
                if not hasattr(self, 'atomcharges'):
                    self.atomcharges = {}
                header = next(inputfile)

                line = next(inputfile)
                while not line.strip():
                    line = next(inputfile)

                charges = []
                while line.strip():
                    ch = float(line.split()[-1])
                    charges.append(ch)
                    line = next(inputfile)
                self.atomcharges[pop_type.lower()] = charges

        mp_trigger = "MP2 Total Energy (a.u.)"
        if line.strip()[:len(mp_trigger)] == mp_trigger:
            mpenergy = utils.convertor(float(line.split()[-1]), 'hartree', 'eV')
            if not hasattr(self, 'mpenergies'):
                self.mpenergies = []
            self.mpenergies.append([mpenergy])

        # Note this is just a start and needs to be modified for CCSD(T), etc.
        ccsd_trigger = "* CCSD total energy"
        if line.strip()[:len(ccsd_trigger)] == ccsd_trigger:
            ccsd_energy = utils.convertor(float(line.split()[-1]), 'hartree', 'eV')
            if not hasattr(self, "ccenergis"):
                self.ccenergies = []
            self.ccenergies.append(ccsd_energy)

        # The geometry convergence targets and values are printed in a table, with the legends
        # describing the convergence annotation. Probably exact slicing of the line needs
        # to be done in order to extract the numbers correctly. If there are no values for
        # a paritcular target it means they are not used (marked also with an 'o'), and in this case
        # we will set a value of numpy.inf so that any value will be smaller.
        #
        #  ==> Convergence Check <==
        #
        #  Measures of convergence in internal coordinates in au.
        #  Criteria marked as inactive (o), active & met (*), and active & unmet ( ).
        #  ---------------------------------------------------------------------------------------------
        #   Step     Total Energy     Delta E     MAX Force     RMS Force      MAX Disp      RMS Disp
        #  ---------------------------------------------------------------------------------------------
        #    Convergence Criteria    1.00e-06 *    3.00e-04 *             o    1.20e-03 *             o
        #  ---------------------------------------------------------------------------------------------
        #      2    -379.77675264   -7.79e-03      1.88e-02      4.37e-03 o    2.29e-02      6.76e-03 o  ~
        #  ---------------------------------------------------------------------------------------------
        #
        if (self.section == "Convergence Check") and line.strip() == "==> Convergence Check <==":

            self.skip_lines(inputfile, ['b', 'units', 'comment', 'dash+tilde', 'header', 'dash+tilde'])

            # These are the position in the line at which numbers should start.
            starts = [27, 41, 55, 69, 83]

            criteria = next(inputfile)
            geotargets = []
            for istart in starts:
                if criteria[istart:istart+9].strip():
                    geotargets.append(float(criteria[istart:istart+9]))
                else:
                    geotargets.append(numpy.inf)

            self.skip_line(inputfile, 'dashes')

            values = next(inputfile)
            geovalues = []
            for istart in starts:
                if values[istart:istart+9].strip():
                    geovalues.append(float(values[istart:istart+9]))

            # This assertion may be too restrictive, but we haven't seen the geotargets change.
            # If such an example comes up, update the value since we're interested in the last ones.
            if not hasattr(self, 'geotargets'):
                self.geotargets = geotargets
            else:
                assert self.geotargets == geotargets

            if not hasattr(self, 'geovalues'):
                self.geovalues = []
            self.geovalues.append(geovalues)

        # This message signals a converged optimization, in which case we want
        # to append the index for this step to optdone, which should be equal
        # to the number of geovalues gathered so far.
        if line.strip() == "**** Optimization is complete! ****":
            if not hasattr(self, 'optdone'):
                self.optdone = []
            self.optdone.append(len(self.geovalues))

        # This message means that optimization has stopped for some reason, but we
        # still want optdone to exist in this case, although it will be an empty list.
        if line.strip() == "Optimizer: Did not converge!":
            if not hasattr(self, 'optdone'):
                self.optdone = []

        # The reference point at which properties are evaluated in Psi4 is explicitely stated,
        # so we can save it for later. It is not, however, a part of the Properties section,
        # but it appears before it and also in other places where properies that might depend
        # on it are printed.
        #
        # Properties will be evaluated at   0.000000,   0.000000,   0.000000 Bohr
        #
        if (self.version == 4) and ("Properties will be evaluated at" in line.strip()):
            self.reference = numpy.array([float(x.strip(',')) for x in line.split()[-4:-1]])
            assert line.split()[-1] == "Bohr"
            self.reference = utils.convertor(self.reference, 'bohr', 'Angstrom')

        # The properties section print the molecular dipole moment:
        #
        #  ==> Properties <==
        #
        #
        #Properties computed using the SCF density density matrix
        #  Nuclear Dipole Moment: (a.u.)
        #     X:     0.0000      Y:     0.0000      Z:     0.0000
        #
        #  Electronic Dipole Moment: (a.u.)
        #     X:     0.0000      Y:     0.0000      Z:     0.0000
        #
        #  Dipole Moment: (a.u.)
        #     X:     0.0000      Y:     0.0000      Z:     0.0000     Total:     0.0000
        #
        if (self.section == "Properties") and line.strip() == "Dipole Moment: (a.u.)":

            line = next(inputfile)
            dipole = numpy.array([float(line.split()[1]), float(line.split()[3]), float(line.split()[5])])
            dipole = utils.convertor(dipole, "ebohr", "Debye")

            if not hasattr(self, 'moments'):
                self.moments = [self.reference, dipole]
            else:
                try:
                    assert numpy.all(self.moments[1] == dipole)
                except AssertionError:
                    self.logger.warning('Overwriting previous multipole moments with new values')
                    self.logger.warning('This could be from post-HF properties or geometry optimization')
                    self.moments = [self.reference, dipole]

        # Higher multipole moments are printed separately, on demand, in lexicographical order.
        #
        # Multipole Moments:
        #
        # ------------------------------------------------------------------------------------
        #     Multipole             Electric (a.u.)       Nuclear  (a.u.)        Total (a.u.)
        # ------------------------------------------------------------------------------------
        #
        # L = 1.  Multiply by 2.5417462300 to convert to Debye
        # Dipole X            :          0.0000000            0.0000000            0.0000000
        # Dipole Y            :          0.0000000            0.0000000            0.0000000
        # Dipole Z            :          0.0000000            0.0000000            0.0000000
        #
        # L = 2.  Multiply by 1.3450341749 to convert to Debye.ang
        # Quadrupole XX       :      -1535.8888701         1496.8839996          -39.0048704
        # Quadrupole XY       :        -11.5262958           11.4580038           -0.0682920
        # ...
        #
        if line.strip() == "Multipole Moments:":

            self.skip_lines(inputfile, ['b', 'd', 'header', 'd', 'b'])

            # The reference used here should have been printed somewhere
            # before the properties and parsed above.
            moments = [self.reference]

            line = next(inputfile)
            while "----------" not in line.strip():

                rank = int(line.split()[2].strip('.'))

                multipole = []
                line = next(inputfile)
                while line.strip():

                    value = float(line.split()[-1])
                    fromunits = "ebohr" + (rank > 1)*("%i" % rank)
                    tounits = "Debye" + (rank > 1)*".ang" + (rank > 2)*("%i" % (rank-1))
                    value = utils.convertor(value, fromunits, tounits)
                    multipole.append(value)

                    line = next(inputfile)

                multipole = numpy.array(multipole)
                moments.append(multipole)
                line = next(inputfile)

            if not hasattr(self, 'moments'):
                self.moments = moments
            else:
                for im, m in enumerate(moments):
                    if len(self.moments) <= im:
                        self.moments.append(m)
                    else:
                        assert numpy.all(self.moments[im] == m)

        # We can also get some higher moments in Psi3, although here the dipole is not printed
        # separately and the order is not lexicographical. However, the numbers seem
        # kind of strange -- the quadrupole seems to be traceless, although I'm not sure
        # whether the standard transformation has been used. So, until we know what kind
        # of moment these are and how to make them raw again, we will only parse the dipole.
        #
        # --------------------------------------------------------------
        #                *** Electric multipole moments ***
        # --------------------------------------------------------------
        #
        #  CAUTION : The system has non-vanishing dipole moment, therefore
        #    quadrupole and higher moments depend on the reference point.
        #
        # -Coordinates of the reference point (a.u.) :
        #           x                     y                     z
        #  --------------------  --------------------  --------------------
        #          0.0000000000          0.0000000000          0.0000000000
        #
        # -Electric dipole moment (expectation values) :
        #
        #    mu(X)  =  -0.00000 D  =  -1.26132433e-43 C*m  =  -0.00000000 a.u.
        #    mu(Y)  =   0.00000 D  =   3.97987832e-44 C*m  =   0.00000000 a.u.
        #    mu(Z)  =   0.00000 D  =   0.00000000e+00 C*m  =   0.00000000 a.u.
        #    |mu|   =   0.00000 D  =   1.32262368e-43 C*m  =   0.00000000 a.u.
        #
        # -Components of electric quadrupole moment (expectation values) (a.u.) :
        #
        #     Q(XX) =   10.62340220   Q(YY) =    1.11816843   Q(ZZ) =  -11.74157063
        #     Q(XY) =    3.64633112   Q(XZ) =    0.00000000   Q(YZ) =    0.00000000
        #
        if (self.version == 3) and line.strip() == "*** Electric multipole moments ***":

            self.skip_lines(inputfile, ['d', 'b', 'caution1', 'caution2', 'b'])

            coordinates = next(inputfile)
            assert coordinates.split()[-2] == "(a.u.)"
            self.skip_lines(inputfile, ['xyz', 'd'])
            line = next(inputfile)
            self.reference = numpy.array([float(x) for x in line.split()])
            self.reference = utils.convertor(self.reference, 'bohr', 'Angstrom')

            self.skip_line(inputfile, "blank")
            line = next(inputfile)
            assert "Electric dipole moment" in line
            self.skip_line(inputfile, "blank")

            # Make sure to use the column that has the value in Debyes.
            dipole = []
            for i in range(3):
                line = next(inputfile)
                dipole.append(float(line.split()[2]))

            if not hasattr(self, 'moments'):
                self.moments = [self.reference, dipole]
            else:
                assert self.moments[1] == dipole


if __name__ == "__main__":
    import doctest, psiparser
    doctest.testmod(psiparser, verbose=False)
