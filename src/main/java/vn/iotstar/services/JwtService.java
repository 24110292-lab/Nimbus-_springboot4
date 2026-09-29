package vn.iotstar.services;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class JwtService {

    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.HS256;

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration) {

        Date now = new Date();
        Date expiry = new Date(now.getTime() + expiration);

        try {
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(now)
                    .expirationTime(expiry);

            if (extraClaims != null) {
                extraClaims.forEach(claimsBuilder::claim);
            }

            JWSHeader header = new JWSHeader.Builder(SIGNING_ALGORITHM)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            signedJWT.sign(new MACSigner(getSecretKeyBytes()));

            return signedJWT.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Could not create JWT token", exception);
        }
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return username != null
                    && username.equals(userDetails.getUsername())
                    && !isTokenExpired(token);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        Date expiration = extractExpiration(token);
        return expiration == null || expiration.before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    private JWTClaimsSet extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            if (!SIGNING_ALGORITHM.equals(signedJWT.getHeader().getAlgorithm())) {
                throw new IllegalArgumentException("Unsupported JWT signing algorithm");
            }

            if (!signedJWT.verify(new com.nimbusds.jose.crypto.MACVerifier(getSecretKeyBytes()))) {
                throw new IllegalArgumentException("Invalid JWT signature");
            }

            return signedJWT.getJWTClaimsSet();
        } catch (Exception exception) {
            if (exception instanceof IllegalArgumentException) {
                throw (IllegalArgumentException) exception;
            }
            throw new IllegalArgumentException("Invalid JWT token", exception);
        }
    }

    private byte[] getSecretKeyBytes() {
        String value = secretKey == null ? "" : secretKey.trim();

        if (value.isEmpty()) {
            throw new IllegalStateException("security.jwt.secret-key must not be empty");
        }

        // Keep compatibility with the existing project configuration:
        // the secret is stored as Base64, just as it was with JJWT.
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException exception) {
            // If a plain-text secret is supplied, use UTF-8 bytes instead.
            return value.getBytes(StandardCharsets.UTF_8);
        }
    }

    @SuppressWarnings("unused")
    private SecretKey getSignInKey() {
        return new SecretKeySpec(getSecretKeyBytes(), "HmacSHA256");
    }
}
