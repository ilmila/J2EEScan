package burp.j2ee.passive.strutstoken;

import java.util.concurrent.atomic.AtomicLong;

public class ReplayRandom {
    private final AtomicLong seed;

    private static final long multiplier = 0x5DEECE66DL;
    private static final long addend = 0xBL;
    private static final long mask = (1L << 48) - 1;

    public ReplayRandom(long seed) {
        this.seed = new AtomicLong();
        this.seed.set(seed);
    }

    protected int next(int bits) {
        long oldseed, nextseed;
        AtomicLong seed = this.seed;
        do {
            oldseed = seed.get();
            nextseed = (oldseed * multiplier + addend) & mask;
        } while (!seed.compareAndSet(oldseed, nextseed));
        return (int)(nextseed >>> (48 - bits));
    }

    public int nextInt() {
        return next(32);
    }

    public long nextLong() {
        // it's okay that the bottom word remains signed.
        return ((long)(next(32)) << 32) + next(32);
    }
}
