"""
/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
"""

import argparse
import json
import sys

# Some globals:
debug = False
warnings = []
extension = 'dal'

# element lookups
symbols = [
    "Xx", "H",  "He", "Li", "Be", "B",  "C",  "N",  "O",  "F",  "Ne", "Na",
    "Mg", "Al", "Si", "P",  "S",  "Cl", "Ar", "K",  "Ca", "Sc", "Ti", "V",
    "Cr", "Mn", "Fe", "Co", "Ni", "Cu", "Zn", "Ga", "Ge", "As", "Se", "Br",
    "Kr", "Rb", "Sr", "Y",  "Zr", "Nb", "Mo", "Tc", "Ru", "Rh", "Pd", "Ag",
    "Cd", "In", "Sn", "Sb", "Te", "I",  "Xe", "Cs", "Ba", "La", "Ce", "Pr",
    "Nd", "Pm", "Sm", "Eu", "Gd", "Tb", "Dy", "Ho", "Er", "Tm", "Yb", "Lu",
    "Hf", "Ta", "W",  "Re", "Os", "Ir", "Pt", "Au", "Hg", "Tl", "Pb", "Bi",
    "Po", "At", "Rn", "Fr", "Ra", "Ac", "Th", "Pa", "U",  "Np", "Pu", "Am",
    "Cm", "Bk", "Cf", "Es", "Fm", "Md", "No", "Lr", "Rf", "Db", "Sg", "Bh",
    "Hs", "Mt", "Ds", "Rg", "Cn", "Nh", "Fl", "Mc", "Lv", "Ts", "Og"]


def getOptions():
    userOptions = {}

    userOptions['Title'] = {}
    userOptions['Title']['type'] = 'string'
    userOptions['Title']['default'] = 'job'

    userOptions['Calculation Type'] = {}
    userOptions['Calculation Type']['type'] = "stringList"
    userOptions['Calculation Type']['default'] = 1
    userOptions['Calculation Type']['values'] = \
        ['Single Point', 'Optimize + Frequencies', 'Frequencies', 'Optimize']

    userOptions['Theory'] = {}
    userOptions['Theory']['type'] = "stringList"
    userOptions['Theory']['default'] = 1
    userOptions['Theory']['values'] = \
        ['SCF', 'DFT', 'MP2', 'CCSD', 'CCS', 'CC2']

    userOptions['Basis'] = {}
    userOptions['Basis']['type'] = "stringList"
    userOptions['Basis']['default'] = 4
    userOptions['Basis']['values'] = \
        ['STO-3G', '3-21 G', '6-31 G(d)', '6-31 G(d,p)',
         'cc-pVDZ', 'cc-pVTZ', 'aug-cc-pVDZ', 'aug-cc-pVTZ']

    userOptions['Filename Base'] = {}
    userOptions['Filename Base']['type'] = 'string'
    userOptions['Filename Base']['default'] = 'job'

    userOptions['Functional'] = {}
    userOptions['Functional']['type'] = "stringList"
    userOptions['Functional']['default'] = 0
    userOptions['Functional']['values'] = \
        ['B3LYP', 'CAMB3LYP', 'BP86', 'KT3', 'PBE']

    opts = {'userOptions': userOptions}
    opts['inputMoleculeFormat'] = 'cjson'

    return opts


def generateInputFile(cjson, opts):
    # Extract options:
    title = opts['Title']
    calculate = opts['Calculation Type']
    theory = opts['Theory']
    basis = opts['Basis']
    functional = opts['Functional']

    output = ''
    coordfile = ''

    # Basis
    coordfile += 'BASIS\n'
    coordfile += '%s\n' % basis
    # Title
    coordfile += ' %s\n' % title
    coordfile += ' %s Generated with Avogadro 2\n' % theory
    # Coordinates

    # roll up the atoms for each element type
    atoms = [[] for i in range(118)]
    start = 0  # index into the coordinate array
    atom_types = 0
    coords3d = cjson['atoms']['coords']['3d']
    for z in cjson['atoms']['elements']['number']:
        coords = coords3d[start:start + 3]
        if len(atoms[z]) == 0:
            atom_types += 1  # a new atom type
        atoms[z].append(coords)
        start += 3
    coordfile += 'Atomtypes=%d Angstrom\n' % atom_types

    for z in range(len(atoms)):
        if len(atoms[z]) > 0:
            coordfile += 'Charge=%d.0 Atoms=%d\n' % (z, len(atoms[z]))
            for atom in atoms[z]:
                coordfile += '%s%15.5f%15.5f%15.5f\n' % (
                    symbols[z], atom[0], atom[1], atom[2])

    coordfile += ''
    coordfile += '\n\n'

    output += '**DALTON INPUT\n'

    if calculate == 'Single Point':
        if theory == 'SCF':
            output += '.RUN WAVE FUNCTIONS\n**WAVE FUNCTIONS\n.HF\n**END OF DALTON INPUT\n'
        elif theory == 'DFT':
            output += '.RUN WAVE FUNCTIONS\n**WAVE FUNCTIONS\n' + \
                '.DFT\n ' + functional + '\n**END OF DALTON INPUT\n'
        elif theory == 'MP2':
            output += '.RUN WAVE FUNCTIONS\n**WAVE FUNCTIONS\n.HF\n.MP2\n**END OF DALTON INPUT\n'
        else:
            output += '.RUN WAVE FUNCTIONS\n**WAVE FUNCTIONS\n.CC\n*CC INPUT\n.' + \
                theory + '\n**END OF DALTON INPUT\n'
    if calculate == 'Optimize':
        output += '.OPTIMIZE\n**WAVE FUNCTIONS\n.HF\n**END OF DALTON INPUT\n'
    if calculate == 'Optimize + Frequencies':
        output += '.OPTIMIZE\n**WAVE FUNCTIONS\n.HF\n**PROPERTIES\n.VIBANA\n**END OF DALTON INPUT\n'
    if calculate == 'Frequencies':
        output += '.RUN PROPERTIES\n**WAVE FUNCTIONS\n.HF\n**PROPERTIES\n.VIBANA\n**END OF DALTON INPUT\n'

    output += '\n'

    return coordfile, output


def generateInput():
    # Read options from stdin
    stdinStr = sys.stdin.read()

    # Parse the JSON strings
    opts = json.loads(stdinStr)

    # Generate the input file
    inp = generateInputFile(opts['cjson'], opts['options'])

    # Basename for input files:
    baseName = opts['options']['Filename Base']

    # Prepare the result
    result = {}
    # Input file text -- will appear in the same order in the GUI as they are
    # listed in the array:
    files = []
    # files.append({'filename': '%s.com'%baseName, 'contents': inp})
    files.append({'filename': '%s.%s' % (
        baseName, extension), 'contents': inp[0]})
    files.append({'filename': '%s.mol' % baseName, 'contents': inp[1]})
    if debug:
        files.append({'filename': 'debug_info', 'contents': stdinStr})
    result['files'] = files
    # Specify the main input file. This will be used by MoleQueue to determine
    # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
    result['mainFile'] = '%s.%s' % (baseName, extension)

    if len(warnings) > 0:
        result['warnings'] = warnings

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser('Generate a DALTON input file.')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--print-options', action='store_true')
    parser.add_argument('--generate-input', action='store_true')
    parser.add_argument('--display-name', action='store_true')
    args = vars(parser.parse_args())

    debug = args['debug']

    if args['display_name']:
        print("DALTON")
    if args['print_options']:
        print(json.dumps(getOptions()))
    elif args['generate_input']:
        print(json.dumps(generateInput()))
