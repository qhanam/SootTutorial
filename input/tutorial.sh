#!/bin/bash

# There is a bug in Soot, so we can't parse source code. We need to pre-compile.
javac LeakyApp.java

# Create Jimple IR (./sootOutput/LeakyApp.jimple)
java -jar ../../lib/soot-trunk.jar -cp ./:/Library/Java/JavaVirtualMachines/jdk1.8.0_45.jdk/Contents/Home/jre/lib/rt.jar -f J -p jb use-original-names:true LeakyApp
