package authco.client.exception;

public class ClientAlreadyExistsException extends RuntimeException {

    public ClientAlreadyExistsException(String clientId) {
        super("A client with client_id '" + clientId + "' already exists");
    }

}
