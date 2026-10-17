// Read-only capability probe. Does not subscribe to events or modify permissions.
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>

int main(void) {
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *message) {
        (void)c; (void)message;
    });
    const char *status = "unknown";
    switch (result) {
        case ES_NEW_CLIENT_RESULT_SUCCESS: status = "client_available_not_subscribed"; break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: status = "missing_endpoint_security_entitlement"; break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: status = "missing_user_privacy_approval"; break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: status = "requires_privileged_service"; break;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: status = "client_limit_reached"; break;
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: status = "invalid_argument"; break;
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: status = "system_error"; break;
    }
    printf("{\"endpointSecurity\":\"%s\",\"result\":%d,\"networkExtension\":\"not_checked\",\"eventCoverageVerified\":false}\n", status, result);
    if (client) es_delete_client(client);
    return result == ES_NEW_CLIENT_RESULT_SUCCESS ? 0 : 2;
}
