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
targetName = 'MOLPRO'
extension = 'inp'
debug = False

def getOptions():
  userOptions = {}

  userOptions['Title'] = {}
  userOptions['Title']['type'] = 'string'
  userOptions['Title']['default'] = ''

  userOptions['Calculation Type'] = {}
  userOptions['Calculation Type']['type'] = 'stringList'
  userOptions['Calculation Type']['default'] = 1
  userOptions['Calculation Type']['values'] = \
    ['Single Point', 'Equilibrium Geometry', 'Frequencies']

  userOptions['Theory'] = {}
  userOptions['Theory']['type'] = 'stringList'
  userOptions['Theory']['default'] = 2
  userOptions['Theory']['values'] = ['RHF', 'MP2', 'B3LYP', 'CCSD', 'CCSD(T)']

  userOptions['Basis'] = {}
  userOptions['Basis']['type'] = 'stringList'
  userOptions['Basis']['default'] = 2
  userOptions['Basis']['values'] = \
    ['STO-3G', '3-21G', '6-31G', '6-31G(d)', '6-31G(d,p)', '6-31+G(d)', \
     '6-311G(d)', 'cc-pVDZ', 'cc-pVTZ', 'AUG-cc-pVDZ', 'AUG-cc-pVTZ']

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

  # TODO Coordinate format (need zmatrix)

  userOptions['Use Pre-2009.1 Format'] = {}
  userOptions['Use Pre-2009.1 Format']['type'] = 'boolean'
  userOptions['Use Pre-2009.1 Format']['default'] = False

  opts = {'userOptions' : userOptions}
  opts['inputMoleculeFormat'] = 'cjson'
  opts['allowCustomBaseName'] = True

  return opts

def generateInputFile(cjson, opts, settings):
  # Extract options:
  title = opts['Title']
  calculate = opts['Calculation Type']
  theory = opts['Theory']
  basis = opts['Basis']
  charge = opts['Charge']
  multiplicity = opts['Multiplicity']
  oldVersion = opts['Use Pre-2009.1 Format']

  # Convert to code-specific strings
  basisStr = ''
  if basis in ['STO-3G', '3-21G', '6-31G', '6-31G(d)', '6-31G(d,p)', \
               '6-31+G(d)', '6-311G(d)']:
    basisStr = basis
  elif basis == 'cc-pVDZ':
    basisStr = 'vdz'
  elif basis == 'cc-pVTZ':
    basisStr = 'vtz'
  elif basis == 'AUG-cc-pVDZ':
    basisStr = 'avdz'
  elif basis == 'AUG-cc-pVTZ':
    basisStr = 'avtz'
  else:
    raise Exception('Unhandled basis type: %s'%basis)

  # MOLPRO needs us to calculate some rough wavefunction parameters:
  numElectrons = -charge
  try:
    for z in cjson['atoms']['elements']['number']:
      numElectrons += z
  except KeyError:
    numElectrons = 0
  wavefnStr = 'wf,%d,1,%d'%(numElectrons, multiplicity - 1)

  theoryStr = ''
  if theory != 'B3LYP':
    theoryStr += '{rhf\n%s}\n'%wavefnStr
  # Intentionally not using elif here:
  if theory != 'RHF':
    theoryKey = ''
    if theory in ['MP2', 'CCSD', 'CCSD(T)']:
      theoryKey = theory.lower()
    elif theory == 'B3LYP':
      theoryKey = 'uks,b3lyp'
    else:
      raise Exception('Unhandled theory type: %s'%theory)
    theoryStr += '{%s\n%s}\n'%(theoryKey, wavefnStr)

  calcStr = ''
  if calculate == 'Single Point':
    pass
  elif calculate == 'Equilibrium Geometry':
    calcStr = '{optg}\n\n'
  elif calculate == 'Frequencies':
    calcStr = '{optg}\n{frequencies}\n\n'
  else:
    raise Exception('Unhandled calculation type: %s'%calculate)

  # Create input file
  output = ''

  output += '*** %s\n\n'%title
  output += 'gprint,basis\n'
  output += 'gprint,orbital\n\n'

  output += 'basis, %s\n\n'%basisStr

  if oldVersion:
    output += 'geomtyp=xyz\n'
  output += 'geometry={\n'
  if oldVersion:
    numAtoms = 0
    try:
      numAtoms = len(cjson['atoms']['elements']['number'])
    except KeyError:
      numAtoms = 0
    output += '%d\n\n'%numAtoms

  output += '$$coords:Sxyz$$\n'
  output += '}\n\n'

  output += '%s\n'%theoryStr

  output += '%s'%calcStr

  output += "---\n"

  return output

def generateInput():
  # Read options from stdin
  stdinStr = sys.stdin.read()

  # Parse the JSON strings
  opts = json.loads(stdinStr)

  # Generate the input file
  inp = generateInputFile(opts['cjson'], opts['options'], opts['settings'])

  # Basename for input files:
  baseName = opts['settings']['baseName']

  # Prepare the result
  result = {}
  # Input file text -- will appear in the same order in the GUI as they are
  # listed in the array:
  files = []
  files.append({'filename': '%s.%s'%(baseName, extension), 'contents': inp})
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
