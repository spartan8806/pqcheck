import com.sun.net.httpserver.*;
import java.security.*;
import javax.crypto.KEM;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * pqcheck line-protocol harness for Java (JDK with JEP 496/497 PQC:
 * ML-KEM via javax.crypto.KEM, ML-DSA via java.security.Signature).
 *
 * pqcheck launches this harness as an "exec" adapter target (or via
 * the C-bridge argv convention) and appends:  <kem|sig> <algorithm>
 * e.g.  java JavaKemSigHarness kem ML-KEM-768
 *
 * Protocol (one request per line on stdin, one reply per line):
 *   info                    -> OK kind=kem alg=ML-KEM-768 pk=.. sk=.. ct=.. ss=..
 *   keygen <seed|->         -> OK <pk-hex> <sk-hex>
 *   encaps <pk>             -> OK <ss-hex> <ct-hex>
 *   decaps <sk> <ct>        -> OK <ss-hex>
 *   sign <sk> <msg>         -> OK <sig-hex>
 *   verify <pk> <msg> <sig> -> OK | REJ <reason>
 *   guard <hex|->           -> OK
 * Bad hex or unknown verbs get ERR; over-long lines get ERR and the
 * line is discarded, never truncated into a valid request.
 *
 * NOTE: seeds cannot be pinned through the JDK KEM/Signature APIs in
 * general; keygen ignores the seed argument (pqcheck does not declare
 * PINNED_RANDOMNESS for this harness). Replace the ADAPT sections
 * with the exact algorithms/providers you ship.
 */
public class JavaKemSigHarness {

    static final HexFormat HEX = HexFormat.of();
    static final int MAX_LINE = 1_000_000;

    // algorithm -> {pk, sk, ctOrSig, ss} byte sizes (FIPS 203/204)
    static int[] sizes(String kind, String alg) {
        return switch (kind + ":" + alg) {
            case "kem:ML-KEM-512" -> new int[]{800, 1632, 768, 32};
            case "kem:ML-KEM-768" -> new int[]{1184, 2400, 1088, 32};
            case "kem:ML-KEM-1024" -> new int[]{1568, 3168, 1568, 32};
            case "sig:ML-DSA-44" -> new int[]{1312, 2560, 2420, 0};
            case "sig:ML-DSA-65" -> new int[]{1952, 4032, 3309, 0};
            case "sig:ML-DSA-87" -> new int[]{2592, 4896, 4627, 0};
            default -> null;
        };
    }

    static byte[] unhex(String s) {
        if (s.equals("-")) return new byte[0];
        return HEX.parseHex(s); // throws on odd length / non-hex chars
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("ERR usage: JavaKemSigHarness <kem|sig> <algorithm>");
            return;
        }
        String kind = args[0], alg = args[1];
        int[] sz = sizes(kind, alg);
        if (sz == null) {
            System.out.println("ERR unsupported algorithm " + alg);
            return;
        }
        BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintWriter out = new PrintWriter(
                new BufferedWriter(new OutputStreamWriter(System.out)), true);
        // ADAPT: keep long-lived keys/material handlers here if your
        // provider needs explicit parameter objects.
        String line;
        while ((line = in.readLine()) != null) {
            if (line.length() > MAX_LINE) {
                out.println("ERR line exceeds this harness's input buffer");
                continue;
            }
            String[] p = line.trim().split("\\s+");
            if (p.length == 0 || p[0].isEmpty()) continue;
            try {
                switch (p[0]) {
                    case "info" -> {
                        if (kind.equals("kem"))
                            out.println("OK kind=kem alg=" + alg + " pk=" + sz[0] + " sk=" + sz[1] + " ct=" + sz[2] + " ss=" + sz[3]);
                        else
                            out.println("OK kind=sig alg=" + alg + " pk=" + sz[0] + " sk=" + sz[1] + " sig=" + sz[2]);
                    }
                    case "keygen" -> {
                        if (kind.equals("kem")) {
                            KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
                            KeyPair kp = g.generateKeyPair();
                            out.println("OK " + HEX.formatHex(kp.getPublic().getEncoded())
                                      + " " + HEX.formatHex(kp.getPrivate().getEncoded()));
                        } else {
                            KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
                            KeyPair kp = g.generateKeyPair();
                            out.println("OK " + HEX.formatHex(kp.getPublic().getEncoded())
                                      + " " + HEX.formatHex(kp.getPrivate().getEncoded()));
                        }
                    }
                    case "encaps" -> {
                        KEM kem = KEM.getInstance(alg);
                        PublicKey pk = KeyFactory.getInstance(alg)
                                .generatePublic(new java.security.spec.X509EncodedKeySpec(unhex(p[1])));
                        KEM.Encapsulator enc = kem.newEncapsulator(pk);
                        KEM.Encapsulated e = enc.encapsulate();
                        out.println("OK " + HEX.formatHex(e.key().getEncoded())
                                  + " " + HEX.formatHex(e.encapsulation()));
                    }
                    case "decaps" -> {
                        KEM kem = KEM.getInstance(alg);
                        PrivateKey sk = KeyFactory.getInstance(alg)
                                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(unhex(p[1])));
                        KEM.Decapsulator dec = kem.newDecapsulator(sk);
                        SecretKey ss = dec.decapsulate(unhex(p[2]));
                        out.println("OK " + HEX.formatHex(ss.getEncoded()));
                    }
                    case "sign" -> {
                        Signature s = Signature.getInstance(alg);
                        PrivateKey sk = KeyFactory.getInstance(alg)
                                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(unhex(p[1])));
                        s.initSign(sk);
                        s.update(unhex(p[2]));
                        out.println("OK " + HEX.formatHex(s.sign()));
                    }
                    case "verify" -> {
                        Signature s = Signature.getInstance(alg);
                        PublicKey pk = KeyFactory.getInstance(alg)
                                .generatePublic(new java.security.spec.X509EncodedKeySpec(unhex(p[1])));
                        s.initVerify(pk);
                        s.update(unhex(p[2]));
                        out.println(s.verify(unhex(p[3])) ? "OK" : "REJ signature mismatch");
                    }
                    case "guard" -> out.println("OK");
                    default -> out.println("ERR unknown verb " + p[0]);
                }
            } catch (Exception e) {
                out.println("ERR " + e.getClass().getSimpleName());
            }
        }
    }
}
