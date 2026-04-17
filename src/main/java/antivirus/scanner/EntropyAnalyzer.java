package antivirus.scanner;

public class EntropyAnalyzer {

    private static final int SAMPLE_SIZE = 256 * 1024;

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

    public boolean isCompressed(byte[] data) {
        if (data.length < 4) return false;
        int magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        return magic == 0x504b0304 || magic == 0x504b0506 ||
               magic == 0x377a1850 || magic == 0x425a68 ||
               (data[0] == 0x1f && data[1] == (byte)0x8b);
    }

    public boolean isLikelyLegitimate(byte[] data, double entropy) {
        if (data.length > 50 * 1024 * 1024) return true;
        if (isCompressed(data)) return true;
        int zipHeader = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        if (zipHeader == 0x504b0304 || zipHeader == 0x504b0506) return true;
        return false;
    }
}