package antivirus.scanner;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PEAnalyzer {

    private static final Set<String> PACKER_SECTIONS = new HashSet<>(Arrays.asList(
        ".upx", ".aspack", ".petite", ".upack", ".themida", ".vmprotect"
    ));

    public PEAnalysis analyze(byte[] data) {
        if (data.length < 64) {
            return new PEAnalysis(false, false, false);
        }

        boolean validPE = isValidPE(data);
        boolean hasPackerSections = false;
        boolean writeAndExecute = false;

        if (validPE) {
            hasPackerSections = checkPackerSections(data);
            writeAndExecute = checkWriteAndExecute(data);
        }

        return new PEAnalysis(validPE, hasPackerSections, writeAndExecute);
    }

    private boolean isValidPE(byte[] data) {
        if (data.length < 2) return false;
        
        if (data[0] != 0x4D || data[1] != 0x5A) {
            return false;
        }

        if (data.length < 64) return false;
        
        int peOffset = readInt32LE(data, 60);
        if (peOffset + 4 > data.length) return false;
        
        return data[peOffset] == 0x50 && data[peOffset + 1] == 0x45;
    }

    private boolean checkPackerSections(byte[] data) {
        int peOffset = readInt32LE(data, 60);
        if (peOffset + 24 > data.length) return false;

        int numSections = readInt16LE(data, peOffset + 6);
        int sizeOfOptionalHeader = readInt16LE(data, peOffset + 20);
        int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

        for (int i = 0; i < numSections; i++) {
            int sectionOffset = sectionTableOffset + (i * 40);
            if (sectionOffset + 8 > data.length) break;

            String sectionName = readSectionName(data, sectionOffset);
            if (PACKER_SECTIONS.contains(sectionName.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean checkWriteAndExecute(byte[] data) {
        int peOffset = readInt32LE(data, 60);
        int numSections = readInt16LE(data, peOffset + 6);
        int sizeOfOptionalHeader = readInt16LE(data, peOffset + 20);
        int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

        boolean hasWrite = false;
        boolean hasExecute = false;

        for (int i = 0; i < numSections; i++) {
            int sectionOffset = sectionTableOffset + (i * 40);
            if (sectionOffset + 40 > data.length) break;

            int characteristics = readInt32LE(data, sectionOffset + 36);
            if ((characteristics & 0x40000000) != 0) hasWrite = true;
            if ((characteristics & 0x20000000) != 0) hasExecute = true;
        }

        return hasWrite && hasExecute;
    }

    private String readSectionName(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            char c = (char) data[offset + i];
            if (c == 0) break;
            sb.append(c);
        }
        return sb.toString();
    }

    private int readInt32LE(byte[] data, int offset) {
        if (offset + 4 > data.length) return 0;
        return (data[offset] & 0xFF) |
               ((data[offset + 1] & 0xFF) << 8) |
               ((data[offset + 2] & 0xFF) << 16) |
               ((data[offset + 3] & 0xFF) << 24);
    }

    private int readInt16LE(byte[] data, int offset) {
        if (offset + 2 > data.length) return 0;
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }
}

