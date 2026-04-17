package antivirus.scanner;

public class PEAnalysis {
    private final boolean validPE;
    private final boolean hasPackerSections;
    private final boolean writeAndExecute;

    public PEAnalysis(boolean validPE, boolean hasPackerSections, boolean writeAndExecute) {
        this.validPE = validPE;
        this.hasPackerSections = hasPackerSections;
        this.writeAndExecute = writeAndExecute;
    }

    public boolean isValidPE() { return validPE; }
    public boolean hasPackerSections() { return hasPackerSections; }
    public boolean hasWriteAndExecute() { return writeAndExecute; }
}