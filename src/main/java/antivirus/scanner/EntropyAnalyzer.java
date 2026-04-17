package antivirus.scanner;

public class EntropyAnalyzer {

    private static final int SAMPLE_SIZE = 512 * 1024;
    private static final int CHUNK_SIZE = 64 * 1024;

    public double calculateEntropy(byte[] data) {
        int len = data.length;
        if (len == 0) return 0;

        int[] freq = new int[256];
        int count = 0;

        if (len <= SAMPLE_SIZE) {
            for (byte b : data) {
                freq[b & 0xFF]++;
            }
            count = len;
        } else {
            int step = len / SAMPLE_SIZE;
            for (int i = 0; i < len && count < SAMPLE_SIZE; i += step) {
                freq[data[i] & 0xFF]++;
                count++;
            }
        }

        double entropy = 0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / count;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }
}