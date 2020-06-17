package mwos9mips;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.IntStream;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OS9MipsDrvrModLoader extends OS9MipsModLoader {
	public static final String OPTION_NAME_DEV_DESC_FILE = "Device descriptor file";

	static OS9MipsLoaderConfig config = new OS9MipsLoaderConfig();
	
	{
		config.addExecutionEntry = false;
		config.addUninitializedTrapEntry = false;
		config.codeBias = 0;
		config.dataBias = 0;
	}
	
	public OS9MipsDrvrModLoader() {
		super(config);
	}
	
	@Override
	public String getName() {
		return "Microware OS9 Dev Driver Module (MIPS)";
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		var specs = super.findSupportedLoadSpecs(provider);
		
		if (!specs.isEmpty()) {
			// superclass says this is an OS9 module (had sync bytes), so we can read header.
			BinaryReader reader = new BinaryReader(provider, false);			
			var head = new OS9Header(reader);
			if (head.getType() == OS9Header.MT_DEVDRVR) {
				// ok!
				return specs;
			}
		}
		
        return new ArrayList<>();
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		
		// Load OS9 module
		super.load(provider, loadSpec, options, program, monitor, log);
		
		// Add special entry-points for Device driver
		var deviceDescriptor = getDeviceDescriptor(options);
		if (deviceDescriptor == null) {
			Msg.warn(this, "No device desciptor selected. Entrypoints will not be added!");
			return;
		}
		
        FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		var byteProvider = new RandomAccessByteProvider(deviceDescriptor);
		var reader = new BinaryReader(byteProvider, false);
		
		var descriptor = new OS9DeviceDescriptor(reader);
		
		switch (descriptor.type) {
		case 3: {
			Msg.info(this, "SBF device desciptor detected!");
			var iDataBlock = api.getMemoryBlock(".idata");
			if (iDataBlock == null) {
				Msg.error(this, "SBF device driver does not have initialized data. It's probably malformed.");
				break;
			}
			
			// Add entry-points for all functions in the static storage definition
			var iDataStart = iDataBlock.getStart();
			var addressSpace = iDataStart.getAddressSpace();
			var sbfStatAddr = iDataStart.getOffset() + header.m_share;
			
			try {
				var funcCount = api.getInt(addressSpace.getAddress(sbfStatAddr));
				var funcNames = new String[] {
					"init",
					"read",
					"write",
					"getstat",
					"setstat",
					"term"
				};
				
				var funcsStartAddr = sbfStatAddr + 4;
				IntStream.range(0, Math.min(funcCount, 6)).forEach(n -> {
					var name = funcNames[n];
				    createEntryFunction(api, addressSpace, name, funcsStartAddr + 4 * n);
		        });
				
			} catch (MemoryAccessException | AddressOutOfBoundsException e) {
				Msg.error(this, "Failed to read SBF static storage definition.");
				break;
			}
			break;
		}
		default: {
			Msg.warn(this, "Unsupported device descriptor type. Entrypoints will not be added!");
		}
		}
	}
	
	private void createEntryFunction(FlatProgramAPI api, AddressSpace addressSpace, String name, long offset) {
		try {
			int funcAddress = api.getInt(addressSpace.getAddress(offset));
			api.addEntryPoint(addressSpace.getAddress(funcAddress));
	        api.createFunction(addressSpace.getAddress(funcAddress), name);
		} catch (MemoryAccessException | AddressOutOfBoundsException e) {
			Msg.error(this, "Failed to add entry point for function address in table memory address " + offset);
		}
	}
	
	private File getDeviceDescriptor(List<Option> options) {
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_DEV_DESC_FILE)) {
					var fileName = (String)option.getValue();
					
					if (fileName != null) {
						return new File(fileName);
					}
				}
			}
		}
		
		return null;
	}
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option(OPTION_NAME_DEV_DESC_FILE, "", String.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-devDescFile"));

		return list;
	}
	
	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		var deviceDescriptor = getDeviceDescriptor(options);
		
		if (deviceDescriptor != null && !deviceDescriptor.getPath().isBlank()) {
			if (!deviceDescriptor.exists()) {
				return "Path is invalid.";
			}
			
			if (!deviceDescriptor.isFile()) {
				return "Path does not specify a file.";
			}
			
			try {
				var byteProvider = new RandomAccessByteProvider(deviceDescriptor);
				var reader = new BinaryReader(byteProvider, false);
			
				// Make sure we can read successfully
				new OS9DeviceDescriptor(reader);
			} catch (IOException ex) {
				return "Failed to read from device descriptor while validating loader options: " + ex.getMessage();
			}
		}
		
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
