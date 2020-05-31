/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mwos9mips;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class MWOS9MipsLoader extends AbstractLibrarySupportLoader {
	public static final String MIPS_GP_VALUE_SYMBOL = "_mips_gp_value";
	
	public static final String OPTION_NAME_CODE_BASE_ADDR = "Code Base Address";
	public static final String OPTION_NAME_DATA_BASE_ADDR = "Data Base Address";
	
	public MWOS9Header header;
	
	@Override
	public String getName() {
		return "Microware OS9 for MIPS";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);
        if (reader.readByteArray(0, 4).equals(new byte[] { 0x4D, (byte)0xAD }))
            return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:BE:32:default", "default"), true));
        return new ArrayList<>();
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();

		BinaryReader reader = new BinaryReader(provider, false);
        FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		header = new MWOS9Header(reader);
		var codeStart = getCodeBaseAddr(options, addressSpace.getAddress(0));
		
		// Create module segment 
		createSegment(api,
				provider.getInputStream(0),
				".text",
				codeStart,
				header.m_size,
				true, false);
		
		// Default: round up to next 4-byte boundary and create data segment
		var dataStart = getDataBaseAddr(options, addressSpace.getAddress((codeStart.getOffset() + header.m_size + 4 - 1) / 4 * 4));
		createSegment(api,
				null, 
				".data", 
				dataStart, 
				header.m_data_sz, 
				false, false);
		
		// Get offset into data segment to place initialized data
		reader.setPointerIndex(header.m_idata);
		var offset_to_idata = reader.readNextUnsignedInt();
		var idata_start = dataStart.getOffset() + offset_to_idata;
		var idata_size = reader.readNextUnsignedInt();
		
		createSegment(api, 
				provider.getInputStream(header.m_idata), 
				".idata", 
				addressSpace.getAddress(idata_start), 
				idata_size,
				false, true);
		
		// Fix initialized data references
		reader.setPointerIndex(header.m_idref);
		
		try {
			applyRelocationTable(api, reader, dataStart, codeStart.getOffset());
			applyRelocationTable(api, reader, dataStart, dataStart.getOffset());
		} catch (MemoryAccessException ex) {
			Msg.error(this, "Failed to patch idata references. They will not work.", ex);
		}
		
		// Set GP :)
		// This allows the analyzer to find references to data through the static GP.
		// TODO: implement this for FP as well (OS9 stores biased code start here)
		var gpVal = addressSpace.getAddress(dataStart.getOffset() + 0x7ff0 /* bias */);
		try {
			program.getSymbolTable().createLabel(gpVal, MIPS_GP_VALUE_SYMBOL, SourceType.IMPORTED);
		} catch (Exception ex) {
			Msg.error(this, "Failed to initialize GP! Data references by code will be missing!", ex);
		}
	}
	
	private void applyRelocationTable(FlatProgramAPI api, BinaryReader reader, Address dataStart, long adjustBy) throws IOException, MemoryAccessException {
		var addressSpace = dataStart.getAddressSpace();
		var groupOffset = reader.readNextUnsignedShort();
		var count = reader.readNextUnsignedShort();
		
		while (!(groupOffset == 0 && count == 0)) {
			// shifted since it forms the upper word of each address
	        var base = dataStart.getOffset() + (groupOffset << 16);
	        
	        while (count != 0) {
	        	var offset = reader.readNextUnsignedShort();
	        	var refAddress = addressSpace.getAddress(base + offset);
	        	var ref = api.getInt(refAddress);
	        	var fixedRef = ref + (int)adjustBy;
	        	
	        	api.setInt(refAddress, fixedRef);
	        	count--;
	        }
	        
        	groupOffset = reader.readNextUnsignedShort();
        	count = reader.readNextUnsignedShort();
		}
	}
	
	private void createSegment(FlatProgramAPI api, InputStream input, String name, Address start, long length, boolean isCode, boolean overlay) {
        try {
            MemoryBlock text = api.createMemoryBlock(name, start, input, length, overlay);
            text.setRead(true);
            text.setWrite(isCode ? false : true);
            text.setExecute(isCode ? true : false);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }
    }

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option(OPTION_NAME_CODE_BASE_ADDR, 0x0));
		list.add(new Option(OPTION_NAME_DATA_BASE_ADDR, Integer.class));

		return list;
	}
	
	private Address getCodeBaseAddr(List<Option> options, Address defaultVal) {
		Address baseAddr = defaultVal;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_CODE_BASE_ADDR)) {
					baseAddr = (Address) option.getValue();
				}
			}
		}
		return baseAddr;
	}
	
	private Address getDataBaseAddr(List<Option> options, Address defaultVal) {
		Address baseAddr = defaultVal;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(OPTION_NAME_DATA_BASE_ADDR)) {
					baseAddr = (Address) option.getValue();
				}
			}
		}
		return baseAddr;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		var codeBase = getCodeBaseAddr(options, null);
		if (codeBase != null) {
			var dataBase = getDataBaseAddr(options, null);
			
			if (dataBase != null) {
				BinaryReader reader = new BinaryReader(provider, false);
				MWOS9Header header;
				
				try {
					header = new MWOS9Header(reader);	
				} catch (IOException ex) {
					return "Failed to read from header while validating loader options: " + ex.getMessage();
				}
				
				if (dataBase.getOffset() >= codeBase.getOffset() && dataBase.getOffset() < codeBase.getOffset() + header.m_size) {
					return "Data start overlaps with code!";
				}
				
				if (codeBase.getOffset() >= dataBase.getOffset() && codeBase.getOffset() < dataBase.getOffset() + header.m_data_sz) {
					return "Code start overlaps with data!";
				}
			}
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
