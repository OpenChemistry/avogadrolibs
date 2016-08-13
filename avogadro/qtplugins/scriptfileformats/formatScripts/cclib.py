"""
/******************************************************************************

    License information

******************************************************************************/
"""

import argparse
import json
import sys

from ..cclib.parser import ccopen
from ..cclib.writer import CJSON


def getMetaData():
  metaData = {}
  metaData['inputFormat'] = 'cjson'
  metaData['outputFormat'] = 'cjson'
  metaData['operations'] = ['read']
  metaData['identifier'] = 'CJSON writer'
  metaData['name'] = 'CJSON Format'
  metaData['description'] = "The cclib script provided by the cclib repository is used to " +\
                            "write the CJSON format using the input file provided " +\
                            "to Avogadro2."
  metaData['fileExtensions'] = ['cjson']
  metaData['mimeTypes'] = ['To be filled']
  return metaData

def read():
  # Pass the standard input to ccopen:
  log = ccopen(sys.stdin)

  ccdata = log.parse()

  output_obj = CJSON(ccdata, terse=True)
  output = output_obj.generate_repr()

  return output


if __name__ == "__main__":
  parser = argparse.ArgumentParser('Testing file format script.')
  parser.add_argument('--metadata', action='store_true')
  parser.add_argument('--read', action='store_true')
  parser.add_argument('--write', action='store_true')
  args = vars(parser.parse_args())

  if args['metadata']:
    print(json.dumps(getMetaData()))
  elif args['read']:
    print(read())
  elif args['write']:
    pass

