package taint.intraproc;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.internal.AbstractDefinitionStmt;
import soot.jimple.internal.AbstractInvokeExpr;
import soot.jimple.internal.InvokeExprBox;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

/**
 * Performs an intra-procedural taint analysis.
 */
public class TaintAnalysis extends ForwardFlowAnalysis<Unit, Set<String>> {
	
	private static final List<String> SOURCES = Arrays.asList(new String[] {"<LeakyApp: java.lang.String source()>"});

	/**
	 * 
	 * @param graph a {@code UnitGraph} is a directed graph. Each statement in
	 * 			 	the graph is represented as a {@code Unit}.
	 */
	public TaintAnalysis(UnitGraph graph) {
		super(graph);

		/* Before we perform our taint analysis, we can do an alias analysis 
		 * and cache the results. */
//		LocalMayAliasAnalysis lmaa;

		/* Run the analysis. */
		doAnalysis();
	}
	
	@Override
	protected void flowThrough(Set<String> in, Unit d, Set<String> out) {
		
		/* Copy the taint information into the output set. */
		out.addAll(in);

		/* Taint the variable/field if it is assigned a tainted value. */
		taint(out, d);
		
		/* Look for sink invocations with tainted values. */
		searchSinkValues(in, d);
	
	}

	@Override
	protected Set<String> newInitialFlow() {
		return new HashSet<String>();
	}

	@Override
	protected void merge(Set<String> in1, Set<String> in2, Set<String> out) {
		/* We use union as our confluence operator. */
		out.addAll(in1);
		out.addAll(in2);
	}

	@Override
	protected void copy(Set<String> source, Set<String> dest) {
		dest.addAll(source);
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
	 * Taint the variable/field if it is assigned a tainted value.
	 */
	private void taint (Set<String> out, Unit d) {

		/* Is this an assignment? If it is, check if the RHS is a source. 
		 * Because Soot is polymorphic, we do this by checking class type. */
		if(d instanceof AbstractDefinitionStmt) {
			
			AbstractDefinitionStmt assignment = (AbstractDefinitionStmt) d;

			if(isTainted(out, assignment)) {

				/* Generate a taint label for this variable. */
				Value lhs = assignment.leftBox.getValue();
				System.out.println("Tainting " + lhs + " at line " + d.getJavaSourceStartLineNumber() + ".");
				out.add(lhs.toString());

			}
			
		}
		
	}
	
	/**
	 * Generate an alert if we are using a tainted value in a sink.
	 */
	private void searchSinkValues(Set<String> in, Unit d) {
		
		for(ValueBox use : d.getUseBoxes()) {

			if(use instanceof InvokeExprBox) {
				AbstractInvokeExpr invoke = (AbstractInvokeExpr)use.getValue();

				if(invoke.getMethod().toString().equals("<LeakyApp: void sink(java.lang.String)>")) {
					System.out.println("Searching sink " + invoke.getMethod() + " for tainted arguments.");
					
					for(Value arg : invoke.getArgs()) {
						if(in.contains(arg.toString())) System.out.println("ALERT: Leak detected for " + arg + " at line " + d.getJavaSourceStartLineNumber() + "!");
					}
					
				}

			}
	
		}

	}
	
}
