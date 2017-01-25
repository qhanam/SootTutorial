package taint.intraproc;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import soot.Body;
import soot.BodyTransformer;
import soot.PackManager;
import soot.Scene;
import soot.Transform;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.internal.AbstractDefinitionStmt;
import soot.jimple.internal.AbstractInvokeExpr;
import soot.jimple.internal.InvokeExprBox;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

/**
 * Performs an intra-procedural taint analysis.
 */
public class TaintAnalysis extends ForwardFlowAnalysis<Unit, Set<String>> {
	
	public static void main(String[] args) {

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
		
		/* Run the analysis. */

		soot.Main.main(args);
		
	}
	
	private static final List<String> SOURCES = Arrays.asList(
			new String[] {"<LeakyApp: java.lang.String source()>"});

	private static final List<String> SINKS = Arrays.asList(
			new String[] {"<LeakyApp: void sink(java.lang.String)>"});

	/**
	 * 
	 * @param graph a {@code UnitGraph} is a directed graph. Each statement in
	 * 			 	the graph is represented as a {@code Unit}.
	 */
	public TaintAnalysis(UnitGraph graph) {
		super(graph);
		doAnalysis();
	}
	
	@Override
	protected void flowThrough(Set<String> in, Unit d, Set<String> out) {
		
		/* Copy the taint information into the output set. */

		/* Taint the variable/field if it is assigned a tainted value. */
		
		/* Look for sink invocations with tainted values. */
	
	}

	@Override
	protected Set<String> newInitialFlow() {
		/* Initialize the lattice elements. */
	}

	@Override
	protected void merge(Set<String> in1, Set<String> in2, Set<String> out) {
		/* Union lattice elements. */
	}

	@Override
	protected void copy(Set<String> source, Set<String> dest) {
		/* Make a copy of the lattice elements. */
	}

	/**
	 * Taint the variable/field if it is assigned a tainted value.
	 */
	private void genOrKill (Set<String> out, Unit d) {

		/* Is this an assignment? If it is, check if the RHS is a source. 
		 * Because Soot is polymorphic, we do this by checking class type. */
		if(d instanceof AbstractDefinitionStmt) {
			
			AbstractDefinitionStmt assignment = (AbstractDefinitionStmt) d;
			Value lhs = assignment.leftBox.getValue();

			if(isTainted(out, assignment)) {

				/* Generate a taint label for this identifier. */
				out.add(lhs.toString());

			}
			else {

				/* Kill the taint label for this identifier. */
				out.remove(lhs.toString());

			}
			
		}
		
	}
	
	/**
	 * Look at all var/field uses for tainted values.
	 */
	private void searchSinkValues(Set<String> in, Unit d) {
		
		for(ValueBox use : d.getUseBoxes())
			genTaintedSinkAlert(in, use, d.getJavaSourceStartLineNumber());

	}

	/**
	 * @param expression The RHS of an assignment.
	 * @return true if one of the value uses in the expression are tainted.
	 */
	private boolean isTainted(Set<String> in, AbstractDefinitionStmt assignment) {

		/* Check if we are getting a new source. */
		Value expression = assignment.rightBox.getValue();
		if(expression instanceof AbstractInvokeExpr) {
			AbstractInvokeExpr invoke = (AbstractInvokeExpr)expression;
			if(SOURCES.contains(invoke.getMethod().toString())) return true;
		}
		
		/* Check if we are using a tainted value. */
		for(ValueBox use : assignment.getUseBoxes()) {
			if(in.contains(use.getValue().toString())) return true;
		}
		
		return false;

	}
	

	/**
	 * Generate an alert if we are using a tainted value in a sink.
	 */
	private void genTaintedSinkAlert(Set<String> in, ValueBox use, int line) {
		
		if(!(use instanceof InvokeExprBox)) return;

		AbstractInvokeExpr invoke = (AbstractInvokeExpr)use.getValue();

		if(SINKS.contains(invoke.getMethod().toString())) {
		
			for(Value arg : invoke.getArgs()) {
				if(in.contains(arg.toString())) System.out.println("ALERT: Leak detected for " + arg + " at line " + line + "!");
			}
			
		}

	}
	
}
