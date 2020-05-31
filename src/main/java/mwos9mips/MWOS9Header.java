package mwos9mips;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class MWOS9Header implements StructConverter {
    public byte[] m_sync;  // sync bytes for module identification
    public int m_sysrev;   // system revision check value
    
    public long m_size;    // module size
    public long m_owner;   // group/user ID
    public long m_name;    // offset to module name
    
    public int m_access;   // access permissions
    public int m_tylan;    // module type and language
    public int m_attrev;   // module attributes and revision
    public int m_edit;     // module edition number
    
    public long m_needs;   // module hardware requirements flags
    public long m_share;   // offset of shared data in statics
    public long m_symbol;  // offset to symbol table
    public long m_exec;	   // offset to execution entry point
    public long m_excpt;   // offset to exception entry point
    public long m_data_sz; // data storage requirement
    public long m_stack;   // stack size
    public long m_idata;   // offset to initialized data
    public long m_idref;   // offset to data reference lists
    public long m_init;    // offset to initialization routine
    public long m_term;    // offset to termination routine
    public long m_dbias;   // data area pointer bias
    public long m_cbias;   // code area pointer bias
    
    public int m_ident;    // linkage locale identifier
    public byte[] m_pad;
    public int m_parity;   // header parity
    
    public MWOS9Header(BinaryReader reader) throws IOException {
        reader.setPointerIndex(0);
        m_sync = reader.readNextByteArray(2);
        m_sysrev = reader.readNextUnsignedShort();
        
        m_size = reader.readNextUnsignedInt();
        m_owner = reader.readNextUnsignedInt();
        m_name = reader.readNextUnsignedInt();
        
        m_access = reader.readNextUnsignedShort();
        m_tylan = reader.readNextUnsignedShort();
        m_attrev = reader.readNextUnsignedShort();
        m_edit = reader.readNextUnsignedShort();
        
        m_needs = reader.readNextUnsignedInt();
        m_share = reader.readNextUnsignedInt();
        m_symbol = reader.readNextUnsignedInt();
        m_exec = reader.readNextUnsignedInt();
        m_excpt = reader.readNextUnsignedInt();
        m_data_sz = reader.readNextUnsignedInt();
        m_stack = reader.readNextUnsignedInt();
        m_idata = reader.readNextUnsignedInt();
        m_idref = reader.readNextUnsignedInt();
        m_init = reader.readNextUnsignedInt();
        m_term = reader.readNextUnsignedInt();
        m_dbias = reader.readNextUnsignedInt();
        m_cbias = reader.readNextUnsignedInt();
        
        m_ident = reader.readNextUnsignedShort();
        m_pad = reader.readNextByteArray(8);
        m_parity = reader.readNextUnsignedShort();
    }

    @Override
    public DataType toDataType() {
        Structure struct = new StructureDataType("mwos9Header_t", 0);
        struct.add(new ArrayDataType(BYTE, 2, 1), "m_sync", null);
        struct.add(WORD, 2, "m_sysrev", null);
        
        struct.add(DWORD, 4, "m_size", null);
        struct.add(DWORD, 4, "m_owner", null);
        struct.add(IBO32, 4, "m_name", null);
        
        struct.add(WORD, 2, "m_access", null);
        struct.add(WORD, 2, "m_tylan", null);
        struct.add(WORD, 2, "m_attrev", null);
        struct.add(WORD, 2, "m_edit", null);

        struct.add(DWORD, 4, "m_needs", null);
        struct.add(DWORD, 4, "m_share", null);
        struct.add(DWORD, 4, "m_symbol", null);
        struct.add(IBO32, 4, "m_exec", null);
        struct.add(IBO32, 4, "m_excpt", null);
        struct.add(DWORD, 4, "m_data_sz", null);
        struct.add(DWORD, 4, "m_stack", null);
        struct.add(IBO32, 4, "m_idata", null);
        struct.add(IBO32, 4, "m_idref", null);
        struct.add(DWORD, 4, "m_init", null);
        struct.add(DWORD, 4, "m_term", null);
        struct.add(DWORD, 4, "m_dbias", null);
        struct.add(DWORD, 4, "m_cbias", null);
        
        struct.add(WORD, 2, "m_ident", null);
        struct.add(new ArrayDataType(BYTE, 8, 1), "m_pad", null);
        struct.add(WORD, 2, "m_parity", null);

        return struct;
    }
}