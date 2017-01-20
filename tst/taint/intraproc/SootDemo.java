package taint.intraproc;

import java.util.Map;

import org.junit.Test;

import soot.Body;
import soot.BodyTransformer;
import soot.PackManager;
import soot.Transform;
import soot.toolkits.graph.ExceptionalUnitGraph;

public class SootDemo {

	@Test
	public void testTaintAnalysis() {
		
		/* We are going to run an intra-procedural taint analysis on each 
		 * method body in our sample application. */
		
		String[] args = new String[]{ 
			"-cp", "tst/input/:/Library/Java/JavaVirtualMachines/jdk1.8.0_45.jdk/Contents/Home/jre/lib/rt.jar:/Library/Java/JavaVirtualMachines/jdk1.8.0_45.jdk/Contents/Home/jre/lib/jce.jar",
			"-f", "J",
			"-O",
			"-p", "jb", "use-original-names:true",
			"-keep-line-number",
			"LeakyApp"
		}; 
		
		/* Add our taint analysis to Soot's Jimple Transformation Pack. Soot
		 * will run the transformation on each method body in the Scene (which
		 * classes are included depend on the command line options). */
		
		PackManager.v().getPack("jtp").add(
			new Transform("jtp.aliasTransform", new BodyTransformer() {
				@Override
				protected void internalTransform(Body body, String phaseName,
						Map<String, String> options) {
					new TaintAnalysis(new ExceptionalUnitGraph(body));
				}
			}));
		
		soot.Main.main(args);
		
	}

}
