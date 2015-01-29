package cn.com.cybertech.pm.media.audio;

public class OpusDecoder {
    static {
        System.loadLibrary("opus");
    }

    private native long create(int sample_rate);
    private native int decode(long decoder_handle, byte[] in, int in_offset, int in_count, short[] out);
    private native void destroy(long decoder_handle);

    private long decoder = 0;

    public boolean init(int sample_rate) {
        decoder = create(sample_rate);
        return decoder != 0;
    }

    public int decode(byte[] in, int in_offset, int in_count, short[] out) {
        if (decoder != 0) {
            return decode(decoder, in, in_offset, in_count, out);
        }
        return -1;
    }

    public void release() {
        if (decoder != 0) {
            destroy(decoder);
            decoder = 0;
        }
    }
}