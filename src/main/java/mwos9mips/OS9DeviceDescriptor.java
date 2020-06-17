package mwos9mips;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class OS9DeviceDescriptor implements StructConverter {
	public OS9Header header;
	
    public long portAddress;
    
    public int logicalUnitNumber;
    public int pathDescriptorSize;
    public int type;
    public int mode;
    
    public long fileManagerNamePathOffset;
    public long deviceDriverNameOffset;
    
    public int deviceClass;
    
    public OS9DeviceDescriptor(BinaryReader reader) throws IOException {
    	header = new OS9Header(reader);
    	
        reader.setPointerIndex(header.m_exec);
        portAddress = reader.readNextUnsignedInt();
        
        logicalUnitNumber = reader.readNextUnsignedShort();
        pathDescriptorSize = reader.readNextUnsignedShort();
        type = reader.readNextUnsignedShort();
        mode = reader.readNextUnsignedShort();
        
        fileManagerNamePathOffset = reader.readNextUnsignedInt();
        deviceDriverNameOffset = reader.readNextUnsignedInt();
        
        deviceClass = reader.readNextUnsignedShort();
    }

    @Override
    public DataType toDataType() {
        var struct = new StructureDataType("dd_com", 0);
        struct.add(DWORD, 4, "dd_port", null);
        
        struct.add(WORD, 2, "dd_lu_num", null);
        struct.add(WORD, 2, "dd_pd_size", null);
        struct.add(WORD, 2, "dd_type", null);
        struct.add(WORD, 2, "dd_mode", null);
        
        struct.add(IBO32, 4, "dd_fmgr", null);
        struct.add(IBO32, 4, "dd_drvr", null);
        
        struct.add(WORD, 2, "dd_class", null);
        struct.add(WORD, 2, "dd_dscres", null);

        return struct;
    }
}
