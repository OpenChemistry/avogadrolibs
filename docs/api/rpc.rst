.. _RPC:

Avogadro Remote Procedure Call (RPC)
====================================

Avogadro 2 supports communication between programs using the RPC
protocol and standard JSON messages (i.e., `JSON-RPC
2.0 <https://en.wikipedia.org/wiki/JSON-RPC>`__). Programs like
MoleQueue and XtalOpt set up socket connections to the "avogadro" server
and then can send messages to Avogadro (e.g., to open files or load
molecular data for visualization).

RPC Protocol
------------

As part of JSON-RPC the basic syntax is like so:

::

   {
     "jsonrpc" : "2.0" },
     "id" : *idNum*
   }

where *idNum* is some unique id number (e.g. 32768) for that particular
request. Currently, Avogadro's RPC implementation supports two
additional keys, "method" and "params".

Methods
-------

Current options for "method":

-  "openFile" - tells Avogadro2 to open a file from a path on disk
-  "loadMolecule" - send molecule data using any supported Avogadro2
   format as a new molecule

If the method is "openFile", then "params" needs to be set like this:

::

   {
    "jsonrpc" : "2.0",
    "id" : *idNum*,
    "method" : "openFile",
    "params" :
       {
         { "fileName" : "rutile.POSCAR" }
       }
   }

Note that the file format is inferred from the extension (e.g, POSCAR
here).

If the method is "loadMolecule", then "params" needs to be set like
this:

::

   {
     "jsonrpc" : "2.0",
     "id" : idNum,
     "method" : "loadMolecule",
     "params" :
       {
         { "format" : "POSCAR" },
         { "content" : "TiO2 rutile\n1.00000000\n2.95812000   0.00000000   0.00000000\n0.00000000   4.59373000   0.00000000\n0.00000000   0.00000000   4.59373000\nO   Ti\n4   2\nDirect\n0.00000000  0.30530000  0.30530000\n0.00000000  0.69470000  0.69470000\n0.50000000  0.19470000  0.80530000\n0.50000000  0.80530000  0.19470000\n0.00000000  0.00000000  0.00000000\n0.50000000  0.50000000  0.50000000" }
       }
   }

Note that in this case, the format can be set explicitly, and the
content is passed as a string, rather than a file on-disk.
