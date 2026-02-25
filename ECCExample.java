import java.math.BigInteger;
import java.security.SecureRandom;

public class ECCExample {

    // Curve: y^2 = x^3 + ax + b (mod p)
    static BigInteger a = new BigInteger("2");
    static BigInteger b = new BigInteger("3");
    static BigInteger p = new BigInteger("97");   // small prime (demo only)

    // Base point G (must lie on curve)
    static ECPoint G = new ECPoint(
            new BigInteger("3"),
            new BigInteger("6")
    );

    static SecureRandom random = new SecureRandom();

    // ---------------- Point Class ----------------
    static class ECPoint {
        BigInteger x;
        BigInteger y;

        ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        boolean isInfinity() {
            return x == null && y == null;
        }

        static ECPoint infinity() {
            return new ECPoint(null, null);
        }

        public String toString() {
            if (isInfinity()) return "Point at Infinity";
            return "(" + x + ", " + y + ")";
        }
    }

    // ---------------- Point Addition ----------------
    static ECPoint add(ECPoint P, ECPoint Q) {

        if (P.isInfinity()) return Q;
        if (Q.isInfinity()) return P;

        // If P == -Q → infinity
        if (P.x.equals(Q.x) &&
                P.y.equals(Q.y.negate().mod(p))) {
            return ECPoint.infinity();
        }

        BigInteger lambda;

        if (P.x.equals(Q.x) && P.y.equals(Q.y)) {
            // Point doubling
            BigInteger numerator = P.x.pow(2).multiply(new BigInteger("3")).add(a);
            BigInteger denominator = P.y.multiply(new BigInteger("2")).modInverse(p);
            lambda = numerator.multiply(denominator).mod(p);
        } else {
            // Point addition
            BigInteger numerator = Q.y.subtract(P.y);
            BigInteger denominator = Q.x.subtract(P.x).modInverse(p);
            lambda = numerator.multiply(denominator).mod(p);
        }

        BigInteger xr = lambda.pow(2).subtract(P.x).subtract(Q.x).mod(p);
        BigInteger yr = lambda.multiply(P.x.subtract(xr)).subtract(P.y).mod(p);

        return new ECPoint(xr, yr);
    }

    // ---------------- Scalar Multiplication ----------------
    static ECPoint multiply(BigInteger k, ECPoint P) {

        ECPoint result = ECPoint.infinity();
        ECPoint addend = P;

        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                result = add(result, addend);
            }
            addend = add(addend, addend);
            k = k.shiftRight(1);
        }
        return result;
    }

    // ---------------- MAIN METHOD ----------------
    public static void main(String[] args) {

        // -------- Key Generation --------
        // G has small order on this curve, so choose safe range 1–4
        BigInteger privateKey = new BigInteger("3");   // fixed for demo

        ECPoint publicKey = multiply(privateKey, G);

        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);

        // -------- Encryption --------
        BigInteger message = new BigInteger("2");  // simple numeric message
        ECPoint M = multiply(message, G);          // Encode message as point

        BigInteger k = new BigInteger("2");        // random session key (demo)
        ECPoint C1 = multiply(k, G);
        ECPoint C2 = add(M, multiply(k, publicKey));

        System.out.println("\nEncrypted:");
        System.out.println("C1: " + C1);
        System.out.println("C2: " + C2);

        // -------- Decryption --------
        ECPoint sharedSecret = multiply(privateKey, C1);

        ECPoint decrypted;
        if (sharedSecret.isInfinity()) {
            decrypted = C2;
        } else {
            ECPoint negShared = new ECPoint(
                    sharedSecret.x,
                    sharedSecret.y.negate().mod(p)
            );
            decrypted = add(C2, negShared);
        }

        System.out.println("\nDecrypted Point: " + decrypted);
    }
}