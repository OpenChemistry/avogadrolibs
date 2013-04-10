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
targetName = 'Q-Chem'
debug = False

def getOptions():
  userOptions = {}

  userOptions['Title'] = {}
  userOptions['Title']['type'] = 'string'
  userOptions['Title']['default'] = ''

  userOptions['Calculation Type'] = {}
  userOptions['Calculation Type']['type'] = "stringList"
  userOptions['Calculation Type']['default'] = 1
  userOptions['Calculation Type']['values'] = \
    ['Single Point', 'Equilibrium Geometry', 'Frequencies']

  userOptions['Theory'] = {}
  userOptions['Theory']['type'] = "stringList"
  userOptions['Theory']['default'] = 2
  userOptions['Theory']['values'] = \
    ['RHF', 'MP2', 'B3LYP', 'B3LYP5', 'EDF1', 'M062X', 'CCSD']

  userOptions['Basis'] = {}
  userOptions['Basis']['type'] = "stringList"
  userOptions['Basis']['default'] = 2
  userOptions['Basis']['values'] = \
    ['STO-3G', '3-21G', '6-31G(d)', '6-31G(d,p)', '6-31+G(d)', '6-311G(d)', \
     'cc-pVDZ', 'cc-pVTZ', 'LANL2DZ', 'LACVP']

  userOptions['Charge'] = {}
  userOptions['Charge']['type'] = "integer"
  userOptions['Charge']['default'] = 0
  userOptions['Charge']['minimum'] = -9
  userOptions['Charge']['maximum'] = 9

  userOptions['Multiplicity'] = {}
  userOptions['Multiplicity']['type'] = "integer"
  userOptions['Multiplicity']['default'] = 1
  userOptions['Multiplicity']['minimum'] = 1
  userOptions['Multiplicity']['maximum'] = 6

  # TODO Coordinate format (need zmatrix)

  opts = {'userOptions' : userOptions}

  return opts

def generateInputFile(opts, settings):
  # Extract options:
  title = opts['Title']
  calculate = opts['Calculation Type']
  theory = opts['Theory']
  basis = opts['Basis']
  charge = opts['Charge']
  multiplicity = opts['Multiplicity']

  # Convert to code-specific strings
  calcStr = ''
  if calculate == 'Single Point':
    calcStr = 'SP'
  elif calculate == 'Equilibrium Geometry':
    calcStr = 'Opt'
  elif calculate == 'Frequencies':
    calcStr = 'Freq'
  else:
    raise Exception('Unhandled calculation type: %s'%calculate)

  theoryStr = ''
  if theory in ['RHF', 'B3LYP', 'B3LYP5', 'EDF1', 'M062X']:
    theoryStr = theory
  elif theory in ['MP2', 'CCSD']:
    theoryStr = 'HF\n   CORRELATION %s'%theory
  else:
    raise Exception('Unhandled theory type: %s'%theory)

  basisStr = ''
  if basis in ['STO-3G', '3-21G', '6-31G(d)', '6-31G(d,p)', '6-31+G(d)', \
               '6-311G(d)', 'cc-pVDZ', 'cc-pVTZ']:
    basisStr = 'BASIS %s'%basis
  elif basis in ['LANL2DZ', 'LACVP']:
    basisStr = 'ECP %s'%basis
  else:
    raise Exception('Unhandled basis type: %s'%basis)

  output = ''

  output += '$rem\n'
  output += '   JOBTYPE %s\n'%calcStr
  output += '   EXCHANGE %s\n'%theoryStr
  output += '   %s\n'%basisStr
  output += '   GUI=2\n'
  output += '$end\n\n'

  output += '$comment\n   %s\n$end\n\n'%title

  output += '$molecule\n'
  output += '   %s %s\n'%(charge, multiplicity)
  output += '$$coords:___Sxyz$$\n'
  output += '$end\n'

  return output

def generateInput():
  # Read options from stdin
  stdinStr = sys.stdin.read()

  # Parse the JSON strings
  opts = json.loads(stdinStr)

  # Generate the input file
  inp = generateInputFile(opts['options'], opts['settings'])

  # Prepare the result
  result = {}
  # Input file text -- will appear in the same order in the GUI as they are
  # listed in the array:
  files = []
  files.append({'filename': 'job.qcin', 'contents': inp})
  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  # Specify the main input file. This will be used by MoleQueue to determine
  # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
  result['mainFile'] = 'job.qcin'
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
