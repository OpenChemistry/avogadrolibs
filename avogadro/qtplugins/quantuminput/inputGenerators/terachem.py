@QUANTUMINPUT_PYTHON2_SHEBANG@

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
targetName = 'TeraChem'
extension = 'tcin'
debug = False

def getOptions():
  userOptions = {}

  userOptions['Title'] = {}
  userOptions['Title']['type'] = 'string'
  userOptions['Title']['default'] = ''

  userOptions['Calculation Type'] = {}
  userOptions['Calculation Type']['type'] = 'stringList'
  userOptions['Calculation Type']['default'] = 2
  userOptions['Calculation Type']['values'] = \
    ['Single Point', 'Gradient', 'Equilibrium Geometry']

  userOptions['Theory'] = {}
  userOptions['Theory']['type'] = 'stringList'
  userOptions['Theory']['default'] = 2
  userOptions['Theory']['values'] = \
    ['HF', 'BLYP', 'B3LYP', 'B3LYP1', 'B3LYP5', 'PBE', 'REVPBE']

  userOptions['Filename Base'] = {}
  userOptions['Filename Base']['type'] = 'string'
  userOptions['Filename Base']['default'] = 'job'

  userOptions['Unrestricted'] = {}
  userOptions['Unrestricted']['type'] = 'boolean'
  userOptions['Unrestricted']['default'] = False

  userOptions['Basis'] = {}
  userOptions['Basis']['type'] = 'stringList'
  userOptions['Basis']['default'] = 2
  userOptions['Basis']['values'] = \
    ['STO-3G', '3-21G', '6-31G(d)', '6-31G(d,p)', '6-31+G(d)', '6-311G(d)', \
     'cc-pVDZ']

  userOptions['Dispersion'] = {}
  userOptions['Dispersion']['type'] = 'stringList'
  userOptions['Dispersion']['default'] = 0
  userOptions['Dispersion']['values'] = ['Off', 'On', 'D2', 'D3']

  userOptions['Charge'] = {}
  userOptions['Charge']['type'] = 'integer'
  userOptions['Charge']['default'] = 0
  userOptions['Charge']['minimum'] = -9
  userOptions['Charge']['maximum'] = 9

  userOptions['Multiplicity'] = {}
  userOptions['Multiplicity']['type'] = 'integer'
  userOptions['Multiplicity']['default'] = 1
  userOptions['Multiplicity']['minimum'] = 1
  userOptions['Multiplicity']['maximum'] = 6

  # TODO Coordinate format (can do pdb, not sure it's necessary though)

  opts = {'userOptions' : userOptions}

  return opts

def generateInputFile(opts):
  # Extract options:
  title = opts['Title']
  calculate = opts['Calculation Type']
  theory = opts['Theory']
  unrestricted = opts['Unrestricted']
  basis = opts['Basis']
  dispersion = opts['Dispersion']
  charge = opts['Charge']
  multiplicity = opts['Multiplicity']
  baseName = opts['Filename Base']

  # Convert to code-specific strings
  basisStr = ''
  if basis == 'STO-3G':
    basisStr = basis.lower()
  else:
    basisStr = basis

  calcStr = ''
  if calculate == 'Single Point':
    calcStr = 'energy'
  elif calculate == 'Gradient':
    calcStr = 'gradient'
  elif calculate == 'Equilibrium Geometry':
    calcStr = 'minimize'
  else:
    raise Exception('Unhandled calculation type: %s'%calculate)

  theoryStr = ''
  if unrestricted:
    theoryStr += 'u'
  elif theory == 'HF':
    theoryStr += 'r'
  theoryStr += theory.lower()

  dispStr = ''
  if dispersion == 'Off':
    dispStr = 'no'
  elif dispersion == 'On':
    dispStr = 'yes'
  else:
    dispStr = dispersion.lower()

  # Create input file
  output = ''

  output += '#\n# %s\n#\n\n'%title

  output += '%-15s%s\n\n'%('run', calcStr)

  output += '%-15s%s\n'%('method', theoryStr)
  if dispersion != 'Off':
    output += '%-15s%s\n'%('dispersion', dispStr)
  output += '%-15s%s\n'%('basis', basisStr)
  output += '%-15s%s\n'%('charge', charge)
  output += '%-15s%s\n\n'%('spinmult', multiplicity)

  output += '%-15s%s\n\n'%('coordinates', '%s.xyz'%baseName)

  output += 'end\n'

  # Create XYZ file
  coordFile = '$$atomCount$$\n%s\n$$coords:Sxyz$$\n'%title

  return output,coordFile

def generateInput():
  # Read options from stdin
  stdinStr = sys.stdin.read()

  # Parse the JSON strings
  opts = json.loads(stdinStr)

  # Generate the input file
  inp = generateInputFile(opts['options'])

  # Basename for input files:
  baseName = opts['options']['Filename Base']

  # Prepare the result
  result = {}
  # Input file text -- will appear in the same order in the GUI as they are
  # listed in the array:
  files = []
  files.append({'filename': '%s.%s'%(baseName, extension), 'contents': inp[0]})
  files.append({'filename': '%s.xyz'%baseName, 'contents': inp[1]})
  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  # Specify the main input file. This will be used by MoleQueue to determine
  # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
  result['mainFile'] = '%s.%s'%(baseName, extension)
  return result

if __name__ == "__main__":
  parser = argparse.ArgumentParser('Generate a %s input file.'%targetName)
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--print-options', action='store_true')
  parser.add_argument('--generate-input', action='store_true')
  parser.add_argument('--display-name', action='store_true')
  args = vars(parser.parse_args())

  debug = args['debug']

  if args['display_name']:
    print(targetName)
  if args['print_options']:
    print(json.dumps(getOptions()))
  elif args['generate_input']:
    print(json.dumps(generateInput()))
