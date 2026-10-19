Avogadro rendering benchmark
============================

This runs Avogadro's offscreen rendering benchmark on a few standard
molecules (two boxes of water, the 2MS2 virus capsid and, if you have at
least 8 GB of RAM, the large 9MB0 structure). Nothing is installed and no
window of molecules opens; it only measures how fast your computer draws.

How long: usually 2 to 10 minutes. Please leave the computer alone while
it runs, so the timings are not disturbed. Plug laptops in (battery power
roughly halves the speed) and close other heavy programs before running.

How to run
  Windows: double-click run-benchmark.bat (keep it in the same folder as
           AvogadroRenderBenchmark.exe, and extract the ZIP file first).
  macOS / Linux: open a terminal in this folder and run ./run-benchmark.sh
           (in many Linux file managers: right-click, "Run as a Program").

The 2MS2 and 9MB0 structures are downloaded from rcsb.org the first time
(a couple of MB, so an internet connection is needed).

How to share the results
  When it finishes, the results are copied to the clipboard and opened in a
  text window (they are also saved in avogadro-benchmark-results.txt). Start
  a reply in the benchmark thread at https://discuss.avogadro.cc/ and paste
  (Ctrl+V). If the clipboard copy did not work, copy the whole text from the
  file yourself.

Laptops with two GPUs
  The results list every installed GPU and which one OpenGL actually used.
  To run a second time on the discrete (faster) GPU:
    Windows: Settings > System > Display > Graphics > add
             AvogadroRenderBenchmark.exe > Options > High performance.
    Linux (PRIME): DRI_PRIME=1 ./run-benchmark.sh
             or, for NVIDIA: __NV_PRIME_RENDER_OFFLOAD=1 \
             __GLX_VENDOR_LIBRARY_NAME=nvidia ./run-benchmark.sh

Privacy
  The results contain only your operating system, CPU, RAM, graphics card
  names and driver versions, and the timings. No user name, computer name,
  file names or personal data are included.
