package sstendal.restsecurity;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;

/**
 * Generates and parses a JWT token with a subject and a secret.
 *
 * User: Sigurd Stendal
 * Date: 28.04.14
 */
public class JwtToken {

    // Generate random 32-bit shared secret
    private static SecureRandom random = new SecureRandom();
    private static byte[] sharedSecret = new byte[32];
    static {
        random.nextBytes(sharedSecret);
    }

    private String issuer;

    public JwtToken(String issuer) {
        this.issuer = issuer;
    }

    public String generate(String username, String sessionId) {

        try {
            // Create HMAC signer
            JWSSigner signer = new MACSigner(sharedSecret);

            // Prepare JWT with claims set
            JWTClaimsSet claimsSet = new JWTClaimsSet();
            claimsSet.setSubject(username);
            claimsSet.setCustomClaim("session", sessionId);
            claimsSet.setIssueTime(new Date());
            claimsSet.setIssuer(issuer);

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

            // Apply the HMAC
            signedJWT.sign(signer);

            // To serialize to compact form, produces something like
            // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed while generating JWT", e);
        }
    }

    public JwtClaims verifyAndGetClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            JWSVerifier verifier = new MACVerifier(sharedSecret);

            if(signedJWT.verify(verifier)) {
                ReadOnlyJWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                return JwtClaims.verified(claims.getSubject(), (String) claims.getCustomClaim("session"));
            } else {
                return JwtClaims.notVerified();
            }
        } catch (ParseException e) {
            throw new RuntimeException("Failed while parsing JWT: " + token, e);
        } catch (JOSEException e) {
            throw new RuntimeException("Failed while verifying JWT: " + token, e);
        }
    }

}

