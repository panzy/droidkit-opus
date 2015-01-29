package cn.com.cybertech.pm.media.audio;

public class OpusEncoder {
    static {
        System.loadLibrary("opus");
    }

    private native long create(int sample_rate);
    private native int encode(long encoder_handle, short[] in, byte[] out);
    private native void destroy(long encoder_handle);

    private long encoder = 0;

    public boolean init(int sample_rate) {
        encoder = create(sample_rate);
        return encoder != 0;
    }

    public int encode(short[] in, byte[] out) {
        if (encoder != 0) {
            return encode(encoder, in, out);
        }
        return -1;
    }

    public void release() {
        if (encoder != 0) {
            destroy(encoder);
            encoder = 0;
        }
    }
}