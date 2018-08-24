gif-h
=====

This one-header library offers a simple, very limited way to create animated GIFs directly in code.
Those looking for particular cleverness are likely to be disappointed; it's pretty much a straight-ahead
implementation of the GIF format with optional Floyd-Steinberg dithering. (It does at least use delta
encoding - only the changed portions of each frame are saved.) 

So resulting files are often quite large. The hope is that it will be handy nonetheless as a quick and easily-integrated way for programs to spit out animations.

Only RGBA8 is currently supported as an input format. (The alpha is ignored.) 

Email me : ctangora -at- gmail -dot- com

Usage:
-------------------
Create a GifWriter struct. 

Pass the struct to GifBegin() to initialize values and write the file header.

Pass frames of the animation to GifWriteFrame().

Finally, call GifEnd() to close the file handle and free memory.
