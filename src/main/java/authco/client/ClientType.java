package authco.client;

/**
 * PUBLIC: runs on the user's device (SPA, mobile, CLI) and cannot keep a secret,
 * so it authenticates with PKCE alone. CONFIDENTIAL: runs on a server and gets a
 * client secret on top of PKCE.
 */
public enum ClientType {
    PUBLIC,
    CONFIDENTIAL
}
