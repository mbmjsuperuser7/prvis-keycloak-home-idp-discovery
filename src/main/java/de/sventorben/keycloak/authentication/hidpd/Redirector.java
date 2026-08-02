package de.sventorben.keycloak.authentication.hidpd;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.sessions.AuthenticationSessionModel;

import static org.keycloak.services.resources.IdentityBrokerService.getIdentityProvider;

final class Redirector {

    private static final Logger LOG = Logger.getLogger(Redirector.class);

    private final AuthenticationFlowContext context;

    Redirector(AuthenticationFlowContext context) {
        this.context = context;
    }

    void redirectTo(IdentityProviderModel idp) {
        String providerAlias = idp.getAlias();
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
        KeycloakSession keycloakSession = context.getSession();
        ClientSessionCode<AuthenticationSessionModel> clientSessionCode =
            new ClientSessionCode<>(keycloakSession, realm, authenticationSession);
        clientSessionCode.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        if (!idp.isEnabled()) {
            LOG.warnf("Identity Provider %s is disabled.", providerAlias);
            return;
        }
        if (idp.isLinkOnly()) {
            LOG.warnf("Identity Provider %s is not allowed to perform a login.", providerAlias);
            return;
        }
        new HomeIdpAuthenticationFlowContext(context).loginHint().copyTo(clientSessionCode);
        IdentityProvider<?> identityProvider = getIdentityProvider(keycloakSession, idp.getAlias());

        // FIXED for Keycloak 26.4.x/26.5.x: performLogin and supportsLongStateParameter
        // moved from the base IdentityProvider interface onto the more specific
        // UserAuthenticationIdentityProvider sub-interface (confirmed directly against
        // the actual current Keycloak Javadocs, not guessed). Every real, user-facing
        // social/OIDC broker (Google, GitHub, Microsoft, etc.) implements this
        // sub-interface in practice, but this checks explicitly rather than assuming,
        // failing safely (log + no-op) instead of risking a ClassCastException if some
        // future or unusual provider type doesn't.
        if (!(identityProvider instanceof UserAuthenticationIdentityProvider)) {
            LOG.warnf("Identity Provider %s does not support user authentication (not a UserAuthenticationIdentityProvider); cannot redirect.", providerAlias);
            return;
        }
        UserAuthenticationIdentityProvider<?> userAuthProvider = (UserAuthenticationIdentityProvider<?>) identityProvider;

        Response response = userAuthProvider.performLogin(createAuthenticationRequest(providerAlias, userAuthProvider, clientSessionCode));
        context.forceChallenge(response);
    }

    private AuthenticationRequest createAuthenticationRequest(String providerAlias, UserAuthenticationIdentityProvider<?> identityProvider, ClientSessionCode<AuthenticationSessionModel> clientSessionCode) {
        AuthenticationSessionModel authSession = null;
        IdentityBrokerState encodedState = null;

        if (clientSessionCode != null) {
            authSession = clientSessionCode.getClientSession();
            String relayState = clientSessionCode.getOrGenerateCode();
            String clientData = identityProvider.supportsLongStateParameter() ? AuthenticationProcessor.getClientData(context.getSession(), authSession) : null;
            encodedState = IdentityBrokerState.decoded(relayState, authSession.getClient().getId(), authSession.getClient().getClientId(), authSession.getTabId(), clientData);
        }

        KeycloakSession keycloakSession = context.getSession();
        KeycloakUriInfo keycloakUriInfo = keycloakSession.getContext().getUri();
        RealmModel realm = context.getRealm();
        String redirectUri = Urls.identityProviderAuthnResponse(keycloakUriInfo.getBaseUri(), providerAlias, realm.getName()).toString();
        return new AuthenticationRequest(keycloakSession, realm, authSession, context.getHttpRequest(), keycloakUriInfo, encodedState, redirectUri);
    }

}
