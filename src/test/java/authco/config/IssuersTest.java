package authco.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class IssuersTest {

    private final Issuers issuers = new Issuers(List.of("https://Restauco.test:443/authco/", "http://barberco.test:8080/authco"));

    @Test
    @DisplayName("configured issuers are normalized: lowercase host, no default port, no trailing slash")
    void normalizesConfiguredIssuers() {
        assertEquals(List.of("https://restauco.test/authco", "http://barberco.test:8080/authco"), issuers.all());
    }

    @Test
    @DisplayName("equivalent spellings find the same issuer; other ports or hosts do not")
    void findsEquivalentIssuer() {
        assertEquals(Optional.of("https://restauco.test/authco"), issuers.find("HTTPS://RESTAUCO.TEST/authco"));
        assertEquals(Optional.of("http://barberco.test:8080/authco"), issuers.find("http://barberco.test:8080/authco/"));
        assertTrue(issuers.find("https://restauco.test:8443/authco").isEmpty());
        assertTrue(issuers.find("https://restauco.test.evil/authco").isEmpty());
    }

    @Test
    @DisplayName("an endpoint URL maps to the issuer it lives under, on a path boundary")
    void issuerOfEndpoint() {
        assertEquals(Optional.of("https://restauco.test/authco"),
                issuers.issuerOf("https://restauco.test:443/authco/oauth2/authorize"));
        assertTrue(issuers.issuerOf("https://restauco.test/authco-admin/oauth2/authorize").isEmpty());
    }

}
