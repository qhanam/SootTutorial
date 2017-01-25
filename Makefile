all: analysis sample run

# This is our intra-procedural analysis
analysis: 
	mkdir -p bin
	javac -cp lib/soot-trunk.jar \
		-d bin/ \
		src/taint/intraproc/TaintAnalysis.java

# There is a bug in Soot, so we can't parse source code. We need to pre-compile
sample: 
	javac -cp input/ input/LeakyApp.java

# Create Jimple IR (./sootOutput/LeakyApp.jimple)
run: analysis sample
	java -cp bin/:lib/soot-trunk.jar taint.intraproc.TaintAnalysis \
		-cp input/:/Library/Java/JavaVirtualMachines/jdk1.8.0_45.jdk/Contents/Home/jre/lib/rt.jar \
		-O \
		-f J \
		-p jb use-original-names:true \
		-keep-line-number \
		-main-class LeakyApp \
		LeakyApp
