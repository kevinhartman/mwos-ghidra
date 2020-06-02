package mwos9mips;

import java.math.BigInteger;

import ghidra.app.plugin.core.analysis.MipsAddressAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MWOS9MipsAnalyzer extends MipsAddressAnalyzer {
    private static final String OPTION_NAME_CONST_CP = "(Microware OS9) Assume CP value";
	private static final String OPTION_DESCRIPTION_CONST_CP =
		"Assume CP ($s8) is biased code pointer (use for MWOS9 program modules).";

	private boolean discoverGlobalCPSetting = false;

	private Register cp;
	private Address cp_assumption_value = null;

	public MWOS9MipsAnalyzer() {
		super();
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canHandle = super.canAnalyze(program);
		
		if (canHandle) {
			cp = program.getRegister("s8");
		}
		
		return canHandle;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		cp_assumption_value = null;

		// get MWOS9 CP value if it's present in the special global label "_mips_cp_value"
		checkForGlobalCP(program, set, monitor);

		return super.added(program, set, monitor, log);
	}
	
	/**
	 * Check for a global CP register symbol or discovered symbol
	 * @param set
	 */
	private void checkForGlobalCP(Program program, AddressSetView set, TaskMonitor monitor) {
		// don't want to check for it
		if (!discoverGlobalCPSetting) {
			return;
		}
		
		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, "_mips_cp_value",
				err -> Msg.error(this, err));
		if (symbol != null) {
			cp_assumption_value = symbol.getAddress();
		}
		return;
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		// get the function body
		final Function func = program.getFunctionManager().getFunctionContaining(flowStart);

		if (func != null) {
			flowStart = func.getEntryPoint();
			
			if (cp_assumption_value != null) {
				ProgramContext programContext = program.getProgramContext();
				RegisterValue cpVal = programContext.getRegisterValue(cp, flowStart);
				if (cpVal == null || !cpVal.hasValue()) {
					cpVal = new RegisterValue(cp,
						BigInteger.valueOf(cp_assumption_value.getOffset()));
					try {
						program.getProgramContext().setRegisterValue(func.getEntryPoint(),
							func.getEntryPoint(), cpVal);
					}
					catch (ContextChangeException e) {
						throw new AssertException("unexpected", e); // only happens for context register
					}
				}
			}
		}
		
		return super.flowConstants(program, flowStart, flowSet, symEval, monitor);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		
		Symbol cpVal = SymbolUtilities.getLabelOrFunctionSymbol(program, "_mips_cp_value",
				err -> Msg.error(this, err));

		boolean detected = cpVal != null;
		
		options.registerOption(OPTION_NAME_CONST_CP, detected, null,
			OPTION_DESCRIPTION_CONST_CP);

		discoverGlobalCPSetting =
			options.getBoolean(OPTION_NAME_CONST_CP, detected);
	}

}