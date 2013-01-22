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
debug = False

def getOptions():
  userOptions = {}

  userOptions['Calculation Type'] = {}
  userOptions['Calculation Type']['default'] = 1
  userOptions['Calculation Type']['values'] = []
  userOptions['Calculation Type']['values'].append('Single Point')
  userOptions['Calculation Type']['values'].append('Equilibrium Geometry')
  userOptions['Calculation Type']['values'].append('Frequencies')

  userOptions['Theory'] = {}
  userOptions['Theory']['default'] = 1
  userOptions['Theory']['values'] = []
  userOptions['Theory']['values'].append('RHF')
  userOptions['Theory']['values'].append('B3LYP')
  userOptions['Theory']['values'].append('MP2')
  userOptions['Theory']['values'].append('CCSD')

  userOptions['Basis'] = {}
  userOptions['Basis']['default'] = 2
  userOptions['Basis']['values'] = []
  userOptions['Basis']['values'].append('STO-3G')
  userOptions['Basis']['values'].append('3-21 G')
  userOptions['Basis']['values'].append('6-31 G(d)')
  userOptions['Basis']['values'].append('6-31 G(d,p)')
  userOptions['Basis']['values'].append('6-31+ G(d)')
  userOptions['Basis']['values'].append('6-311 G(d)')
  userOptions['Basis']['values'].append('cc-pVDZ')
  userOptions['Basis']['values'].append('cc-pVTZ')
  userOptions['Basis']['values'].append('LANL2DZ')

  userOptions['Multiplicity'] = {}
  userOptions['Multiplicity']['default'] = 0
  userOptions['Multiplicity']['values'] = []
  userOptions['Multiplicity']['values'].append('Singlet')
  userOptions['Multiplicity']['values'].append('Doublet')
  userOptions['Multiplicity']['values'].append('Triplet')

  userOptions['Charge'] = {}
  userOptions['Charge']['default'] = 2
  userOptions['Charge']['values'] = []
  userOptions['Charge']['values'].append('Dication')
  userOptions['Charge']['values'].append('Cation')
  userOptions['Charge']['values'].append('Neutral')
  userOptions['Charge']['values'].append('Anion')
  userOptions['Charge']['values'].append('Dianion')

  opts = {'userOptions' : userOptions}

  return opts

def generateInputFile(opts):
  # Extract options:
  calculate = opts['Calculation Type']
  theory = opts['Theory']
  basis = opts['Basis']
  multiplicity = opts['Multiplicity']
  charge = opts['Charge']

  # Preamble
  nwfile = ""
  nwfile += "echo\n\n"
  nwfile += "start molecule\n\n"
  nwfile += "title \"Title\"\n"

  # Charge
  nwfile += "charge "
  if charge == 'Dication':
    nwfile += "2"
  elif charge == 'Cation':
    nwfile += "1"
  elif charge == 'Neutral':
    nwfile += "0"
  elif charge == 'Anion':
    nwfile += "-1"
  elif charge == 'Dianion':
    nwfile += "-2"
  else:
    raise Exception("Invalid Multiplicity: %s"%state)
  nwfile += "\n\n"

  # Coordinates
  nwfile += "geometry units angstroms print xyz autosym\n"
  nwfile += "$$coords:Sxyz$$\n"
  nwfile += "end\n\n"

  # Basis
  nwfile += "basis"
  if basis == "cc-pVDZ" or basis == "cc-pVTZ":
    nwfile += " spherical"
  nwfile += "\n"
  nwfile += "  * library "
  if basis == 'STO-3G':
    nwfile += "STO-3G"
  elif basis == '3-21 G':
    nwfile += "3-21G"
  elif basis == '6-31 G(d)':
    nwfile += "6-31G*"
  elif basis == '6-31 G(d,p)':
    nwfile += "6-31G**"
  elif basis == '6-31+ G(d)':
    nwfile += "6-31+G*"
  elif basis == '6-311 G(d)':
    nwfile += "6-311G*"
  elif basis == 'cc-pVDZ':
    nwfile += "cc-pVDZ"
  elif basis == 'cc-pVTZ':
    nwfile += "cc-pVTZ"
  elif basis == 'LANL2DZ':
    nwfile += "LANL2DZ ECP"
  else:
    raise Exception("Invalid Basis: %s"%basis)
  nwfile += "\n"
  nwfile += "end\n\n"

  # Theory
  task = ""
  if theory == "RHF":
    task = "scf"
  elif theory == "B3LYP":
    task = "dft"
    nwfile += "dft\n"
    nwfile += "  xc b3lyp\n"
    nwfile += "  mult "
    if multiplicity == "Singlet":
      nwfile += "1"
    elif multiplicity == "Doublet":
      nwfile += "2"
    elif multiplicity == "Triplet":
      nwfile += "3"
    else:
      raise Exception("Invalid Multiplicity: %s"%multiplicity)
    nwfile += "\n"
    nwfile += "end\n\n"
  elif theory == "MP2":
    task = "mp2"
    nwfile += "mp2\n"
    nwfile += "  # Exclude core electrons from MP2 treatment:\n"
    nwfile += "  freeze atomic\n"
    nwfile += "end\n\n"
  elif theory == "CCSD":
    task = "ccsd"
    nwfile += "ccsd\n"
    nwfile += "  # Exclude core electrons from MP2 treatment:\n"
    nwfile += "  freeze atomic\n"
    nwfile += "end\n\n"
  else:
    raise Exception("Invalid Theory: %s"%theory)

  # Task
  nwfile += "task %s "%task
  if calculate == 'Single Point':
    nwfile += "energy"
  elif calculate == 'Equilibrium Geometry':
    nwfile += "optimize"
  elif calculate == 'Frequencies':
    nwfile += "freq"
  else:
    raise Exception("Invalid calculation type: %s"%calculate)
  nwfile += "\n"

  return nwfile

def generateInput():
  # Read options from stdin
  stdinStr = sys.stdin.read()

  # Parse the JSON strings
  opts = json.loads(stdinStr)

  # Generate the input file
  inp = generateInputFile(opts['options'])

  # Prepare the result
  result = {}
  files = []
  files.append({'filename': 'job.nw', 'contents': inp})
  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  return result

if __name__ == "__main__":
  parser = argparse.ArgumentParser('Generate a NWChem input file.')
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--print-options', action='store_true')
  parser.add_argument('--generate-input', action='store_true')
  parser.add_argument('--display-name', action='store_true')
  args = vars(parser.parse_args())

  debug = args['debug']

  if args['display_name']:
    print("NWChem")
  if args['print_options']:
    print(json.dumps(getOptions()))
  elif args['generate_input']:
    print(json.dumps(generateInput()))
