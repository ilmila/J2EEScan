package burp.j2ee.passive.strutstoken;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

/**
 * Recover seed from Random instance base on a single Struts token.
 * @author Philippe Arteau
 */
public class StrutsTokenCracker {

    //Constants used to reproduce Java LCG PRNG
    private static final long multiplier = 0x5DEECE66DL;
    private static final long addend = 0xBL;
    private static final long mask = (1L << 48) - 1;

    /**
     * The guessing game can start ...
     * @param token
     */
    public static boolean testToken(String token) {
        //System.out.println("== bytes representation (reconstructed byte array)");
        int[] tokenInts = bytesToInt(bigIntToByte(token));
        /*for(int i=0;i<tokenInts.length;i++) {
            PrintHex.printInt(tokenInts[i]);
        }*/

        long seed = findSeed(reverseByteOrder(tokenInts[1]), reverseByteOrder(tokenInts[2]));
        ReplayRandom random = new ReplayRandom(seed);

        //System.out.println("== following int .. (should match the initial token last part) ");
        int[] nextInts = new int[4];
        for(int i=0;i<nextInts.length;i++) {
            nextInts[i] = reverseByteOrder(random.nextInt());
        }

        boolean match1 = tokenInts[2] == nextInts[0];
        boolean match2 = tokenInts[3] == nextInts[1];
        boolean match3 = tokenInts[4] == nextInts[2];

        return match1 && match2 && match3;
    }

    //Utility methods to restructure the data..

    private static byte[] bigIntToByte(String hexValue) {
        return new BigInteger(hexValue, 36).toByteArray();
    }

    private static int[] bytesToInt(byte[] bytes) {
        //I don't feel like to doing binary operations today..
        IntBuffer intBuf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).asIntBuffer();
        int[] array = new int[intBuf.remaining()];
        intBuf.get(array);
        return array;
    }

    /**
     * Need because of special bytes array construction in <code>java.util.Random#nextBytes(byte[])</code>
     */
    public static int reverseByteOrder(long value) {
        int reverseValue = 0x00000000;
        //Many
        reverseValue |= value << 24 & 0xFF000000;
        reverseValue |= value <<  8 & 0xFF0000;
        reverseValue |= value >>  8 & 0xFF00;
        reverseValue |= value >> 24 & 0xFF;

        return reverseValue;
    }

    //PRNG Brute Force

    /**
     * Guessing the unknown 16 bits of the seed.. (base on two int)
     * Taken from : https://jazzy.id.au/2010/09/20/cracking_random_number_generators_part_1.html
     */
    private static long findSeed(long v1, long v2) {
        //Important to remove the four 0xFF in case the initial int were negative
        v1 = v1 & 0xFFFFFFFFL;
        v2 = v2 & 0xFFFFFFFFL;

        //Brute for the 16 bit that is unknown (48 bits seed - 32 bits return value = 16 bits)
        for (int i = 0; i < 0x10000; i++) {
            long seed = (v1 << 16) + i;
            if ((((seed * multiplier + addend) & mask) >>> 16) == v2) {
                //System.out.println("Seed found: " + seed);
                return seed;
            }
        }
        //throw new RuntimeException("Not Found");
        //System.err.println("Seed Not Found. :(");
        return -1;
    }

}
