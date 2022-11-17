package com.example;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.UnauthorizedException;
import org.jboss.logging.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;

import javax.ws.rs.core.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class ApiSecurityUtils {

    private static final Logger LOG = Logger.getLogger(ApiSecurityUtils.class);

    public static Boolean validateToken(HttpHeaders headers, String requiredScope)
            throws InvalidJwtException, UnauthorizedException, ForbiddenException {
        Boolean validScope = true;
        List<String> scopeList= Arrays.stream(requiredScope.split(",")).collect(Collectors.toList());
        try {
            if (headers != null) {
                String token = headers.getRequestHeader(HttpHeaders.AUTHORIZATION).get(0).substring(7);
                String json = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]),
                        StandardCharsets.UTF_8);
                JwtClaims claims = JwtClaims.parse((json));
                ArrayList tokenScope = (ArrayList) claims.getClaimValue("scp");
                if (!scopeList.contains(tokenScope.get(0))) {
                    throw new ForbiddenException();
                }
                LOG.info("Token authenticated successfully");
            }
            return validScope;
        } catch (Exception e) {
            LOG.error("Exception while validating token");
        }
        return false;
    }
}
