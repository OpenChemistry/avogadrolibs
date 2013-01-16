#!/usr/bin/python2

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
  userOptions['Calculation Type']['default'] = 0
  userOptions['Calculation Type']['values'] = []
  userOptions['Calculation Type']['values'].append('Single Point')
  userOptions['Calculation Type']['values'].append('Equilibrium Geometry')
  userOptions['Calculation Type']['values'].append('Transition State')
  userOptions['Calculation Type']['values'].append('Frequencies')

  userOptions['Theory'] = {}
  userOptions['Theory']['default'] = 3
  userOptions['Theory']['values'] = []
  userOptions['Theory']['values'].append('AM1')
  userOptions['Theory']['values'].append('PM3')
  userOptions['Theory']['values'].append('RHF')
  userOptions['Theory']['values'].append('B3LYP')
  userOptions['Theory']['values'].append('MP2')
  userOptions['Theory']['values'].append('CCSD(T)')

  userOptions['Basis'] = {}
  userOptions['Basis']['default'] = 2
  userOptions['Basis']['values'] = []
  userOptions['Basis']['values'].append('STO-3G')
  userOptions['Basis']['values'].append('MINI')
  userOptions['Basis']['values'].append('3-21 G')
  userOptions['Basis']['values'].append('6-31 G(d)')
  userOptions['Basis']['values'].append('6-31 G(d,p)')
  userOptions['Basis']['values'].append('6-31+G(d,p)')
  userOptions['Basis']['values'].append('6-31+G(2d,p)')
  userOptions['Basis']['values'].append('6-311++G(2d,p)')
  userOptions['Basis']['values'].append('Core Potential')

  userOptions['In'] = {}
  userOptions['In']['default'] = 0
  userOptions['In']['values'] = []
  userOptions['In']['values'].append('Gas')
  userOptions['In']['values'].append('Water')

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
  state = opts['In']
  multiplicity = opts['Multiplicity']
  charge = opts['Charge']

  # Temporary variables used to build portions of the file:
  runType = ""
  scfTyp = ""
  gBasis = ""
  mult = ""
  iCharg = ""

  # Extra options for lines
  extraBasis = ""
  extraContrl = ""

  # Optional lines
  statPt = None
  force = None
  pcm = None

  # Calculation type
  if calculate == 'Single Point':
    runTyp = "ENERGY"
  elif calculate == 'Equilibrium Geometry':
    runTyp = "OPTIMIZE"
    statPt = " $STATPT OPTTOL=0.0001 NSTEP=20 $END\n"
  elif calculate == 'Transition State':
    runTyp = "SADPOINT"
    statPt = " $STATPT OPTTOL=0.0001 NSTEP=20 $END\n"
  elif calculate == 'Frequencies':
    runTyp = "HESSIAN"
    force = " $FORCE METHOD=ANALYTIC VIBANL=.TRUE. $END\n"
  else:
    raise Exception("Invalid calculation type: %s"%calculate)

  # Theory
  if theory == 'AM1':
    gBasis = "AM1"
  elif theory == 'PM3':
    gBasis = "PM3"
  elif theory == 'RHF':
    pass
  elif theory == 'B3LYP':
    extraContrl += " DFTTYP=B3LYP"
  elif theory == 'MP2':
    extraContrl += " MPLEVL=2"
  elif theory == 'CCSD(T)':
    extraContrl += " CCTYP=CCSD(T)"
  else:
    raise Exception("Invalid theory: %s"%calculate)

  # Basis (only if theory is appropriate)
  if theory != 'AM1' and theory != 'PM3':
    if basis == 'STO-3G':
      gBasis = "STO"
      extraBasis += " NGAUSS=3"
    elif basis == 'MINI':
      gBasis = "MINI"
    elif basis == '3-21 G':
      gBasis = "N21"
      extraBasis += " NGAUSS=3"
    elif basis == '6-31 G(d)':
      gBasis = "N31"
      extraBasis += " NGAUSS=6 NDFUNC=1"
    elif basis == '6-31 G(d,p)':
      gBasis = "N31"
      extraBasis += " NGAUSS=6 NDFUNC=1 NPFUNC=1"
    elif basis == '6-31+G(d,p)':
      gBasis = "N31"
      extraBasis += " NGAUSS=6 NDFUNC=1 NPFUNC=1 DIFFSP=.TRUE."
    elif basis == '6-31+G(2d,p)':
      gBasis = "N31"
      extraBasis += " NGAUSS=6 NDFUNC=2 NPFUNC=1 DIFFSP=.TRUE."
    elif basis == '6-311++G(2d,p)':
      gBasis = "N311"
      extraBasis += " NGAUSS=6 NDFUNC=2 NPFUNC=1 DIFFSP=.TRUE. DIFFS=.TRUE."
    elif basis == 'Core Potential':
      gBasis = "SBK"
      extraBasis += " NGAUSS=3 NDFUNC=1"
      extraContrl += " ECP=SBK"
    else:
      raise Exception("Invalid basis: %s"%basis)

  # State/phase/solvent
  if state == 'Gas':
    pass
  elif state == 'Water':
    pcm = " $PCM SOLVNT=WATER $END\n"
  else:
    raise Exception("Invalid 'In' option: %s"%state)

  # Multiplicity
  if multiplicity == 'Singlet':
    scfTyp = "RHF"
    mult = "1"
  elif multiplicity == 'Doublet':
    scfTyp = "ROHF"
    mult = "2"
  elif multiplicity == 'Triplet':
    scfTyp = "ROHF"
    mult = "3"
  else:
    raise Exception("Invalid Multiplicity: %s"%state)

  # Charge
  if charge == 'Dication':
    iCharg = "2"
  elif charge == 'Cation':
    iCharg = "1"
  elif charge == 'Neutral':
    iCharg = "0"
  elif charge == 'Anion':
    iCharg = "-1"
  elif charge == 'Dianion':
    iCharg = "-2"
  else:
    raise Exception("Invalid Multiplicity: %s"%state)

  # Build up the input file:
  result = ""
  result += "! File created by the GAMESS Input Deck Generator Plugin for "
  result += "Avogadro 2.0\n"
  result += " $BASIS GBASIS=%s%s $END\n"%(gBasis, extraBasis)
  if pcm: result += pcm
  result += " $CONTRL SCFTYP=%s RUNTYP=%s ICHARG=%s MULT=%s%s $END\n"%(
      scfTyp, runTyp, iCharg, mult, extraContrl)
  if statPt: result += statPt
  if force: result += force
  result += "\n"
  result += " $DATA\n"
  result += "Title\n"
  result += "C1\n"

  result += "$$coords:SZxyz$$\n"

  result += " $END\n"
  return result

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
  files.append({'filename': 'job.inp', 'contents': inp})
  if debug:
    files.append({'filename': 'debug_info', 'contents': stdinStr})
  result['files'] = files
  return result

if __name__ == "__main__":
  parser = argparse.ArgumentParser('Generate a GAMESS input file.')
  parser.add_argument('--debug', action='store_true')
  parser.add_argument('--print-options', action='store_true')
  parser.add_argument('--generate-input', action='store_true')
  parser.add_argument('--display-name', action='store_true')
  args = vars(parser.parse_args())

  debug = args['debug']

  if args['display_name']:
    print "GAMESS"
  if args['print_options']:
    print json.dumps(getOptions())
  elif args['generate_input']:
    print json.dumps(generateInput())
