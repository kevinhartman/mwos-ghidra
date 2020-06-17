package mwos9mips;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;

public class OS9MipsProgModLoader extends OS9MipsModLoader {
	static OS9MipsLoaderConfig config = new OS9MipsLoaderConfig();
	
	{
		config.addExecutionEntry = true;
		config.addUninitializedTrapEntry = true;
		config.codeBias = 0x7ff0;
		config.dataBias = 0x7ff0;
	}
	
	public OS9MipsProgModLoader() {
		super(config);
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		var specs = super.findSupportedLoadSpecs(provider);
		
		if (!specs.isEmpty()) {
			// superclass says this is an OS9 module (had sync bytes), so we can read header.
			BinaryReader reader = new BinaryReader(provider, false);			
			var head = new OS9Header(reader);
			if (head.getType() == OS9Header.MT_PROGRAM) {
				// ok!
				return specs;
			}
		}
		
        return new ArrayList<>();
	}
	
	@Override
	public String getName() {
		return "Microware OS9 Prog Module (MIPS)";
	}	
}
