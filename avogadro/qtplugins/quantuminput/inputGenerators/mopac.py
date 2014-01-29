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
    ['AM1', 'PM3', 'PM6', 'RM1', 'MNDO', 'MNDOD']

  userOptions['Filename Base'] = {}
  userOptions['Filename Base']['type'] = 'string'
  userOptions['Filename Base']['default'] = 'job'

  userOptions['Multiplicity'] = {}
  userOptions['Multiplicity']['type'] = "integer"
  userOptions['Multiplicity']['default'] = 1
  userOptions['Multiplicity']['minimum'] = 1
  userOptions['Multiplicity']['maximum'] = 6

  userOptions['Charge'] = {}
  userOptions['Charge']['type'] = "integer"
  userOptions['Charge']['default'] = 0
  userOptions['Charge']['minimum'] = -9
  userOptions['Charge']['maximum'] = 9

  # TODO Coordinate format (need zmatrix)

  opts = {'userOptions' : userOptions}

  return opts

def generateInputFile(opts):
  # Extract options:
  title = opts['Title']
  calculate = opts['Calculation Type']
  theory = opts['Theory']
  multiplicity = opts['Multiplicity']
  charge = opts['Charge']

  output = ''

  # Multiplicity
  multStr = ''
  if multiplicity == 1:
    multStr = 'SINGLET'
  elif multiplicity == 2:
    multStr = 'DOUBLET'
  elif multiplicity == 3:
    multStr = 'TRIPLET'
  elif multiplicity == 4:
    multStr = 'QUARTET'
  elif multiplicity == 5:
    multStr = 'QUINTET'
  elif multiplicity == 6:
    multStr = 'SEXTET'
  else:
    raise Exception('Unhandled multiplicty: %d'%multiplicity)

  # Calculation type:
  calcStr = ''
  if calculate == 'Single Point':
    calcStr = 'NOOPT'
  elif calculate == 'Equilibrium Geometry':
    pass
  elif calculate == 'Frequencies':
    calcStr = 'FORCE'
  else:
    raise Exception('Unhandled calculation type: %s'%calculate)

  # Charge, mult, calc type, theory:
  output += ' AUX LARGE CHARGE=%d %s %s %s\n'%\
    (charge, multStr, calcStr, theory)

  # Title
  output += '%s\n\n'%title

  # Coordinates
  if calculate == 'Single Point':
    output += '$$coords:Sx0y0z0$$\n'
  else:
    output += '$$coords:Sx1y1z1$$\n'

  return output

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
  files.append({'filename': '%s.mop'%baseName, 'contents': inp})
  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  # Specify the main input file. This will be used by MoleQueue to determine
  # the value of the $$inputFileName$$ and $$inputFileBaseName$$ keywords.
  result['mainFile'] = '%s.mop'%baseName
  return result

if __name__ == "__main__":
  parser = argparse.ArgumentParser('Generate a MOPAC input file.')
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--print-options', action='store_true')
  parser.add_argument('--generate-input', action='store_true')
  parser.add_argument('--display-name', action='store_true')
  args = vars(parser.parse_args())

  debug = args['debug']

  if args['display_name']:
    print("MOPAC")
  if args['print_options']:
    print(json.dumps(getOptions()))
  elif args['generate_input']:
    print(json.dumps(generateInput()))
