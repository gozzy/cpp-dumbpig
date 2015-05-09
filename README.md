# cpp-dumbpig
Simplified C++ version of dumbpig, automated snort rules checker.
Written on the knee, but it works :)

It does not support blacklists or writing good rules to a separate
file, like original dumbpig does. Only basic checks are provided.

A part of this project can be easily used like a library. There is
one 'entry' function here, named process_rule().