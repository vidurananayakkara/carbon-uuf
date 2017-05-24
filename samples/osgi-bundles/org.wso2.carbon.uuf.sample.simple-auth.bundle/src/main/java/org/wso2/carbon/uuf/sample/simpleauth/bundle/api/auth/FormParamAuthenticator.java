/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.uuf.sample.simpleauth.bundle.api.auth;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.kernel.context.PrivilegedCarbonContext;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.carbon.security.caas.api.ProxyCallbackHandler;
import org.wso2.carbon.uuf.api.auth.User;
import org.wso2.carbon.uuf.api.config.Configuration;
import org.wso2.carbon.uuf.exception.AuthenticationException;
import org.wso2.carbon.uuf.spi.HttpRequest;
import org.wso2.carbon.uuf.spi.HttpResponse;
import org.wso2.carbon.uuf.spi.auth.Authenticator;
import org.wso2.carbon.uuf.spi.auth.SessionManager;

import java.util.Base64;
import java.util.Collections;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * Manages authentication using form parameters.
 * <p>
 * This authenticator authenticates an user using the 'username' and 'password' retrieved from the form parameters. The
 * parameters are passed to the Carbon CAAS framework for authentication.
 *
 * @since 1.0.0
 */
@Component(name = "org.wso2.carbon.uuf.sample.simpleauth.bundle.api.auth.FormParamAuthenticator",
           service = Authenticator.class, immediate = true)
public class FormParamAuthenticator implements Authenticator {

    public static final String LOGIN_REDIRECT_URI = "loginRedirectUri";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String AUTHORIZATION = "Authorization";
    private static final String BASIC = "Basic ";
    private static final String CARBON_SECURITY_CONFIG = "CarbonSecurityConfig";

    /**
     * {@inheritDoc}
     * <p>
     * Upon success authentication the user will be re-directed to 'loginRedirectUri' URI specified in the relevant
     * <tt>component.yaml</tt> configuration. If this value is not specified in <tt>component.yaml</tt> configuration
     * then the user will be re-directed to the app context path.
     */
    @Override
    public AuthenticatorResult login(HttpRequest request, HttpResponse response, SessionManager sessionManager,
                                     Configuration configuration) throws AuthenticationException {
        if (request.isGetRequest()) {
            return new AuthenticatorResult(AuthenticatorStatus.CONTINUE, null, null, null);
        }

        Object userName = request.getFormParams().get(USERNAME);
        Object password = request.getFormParams().get(PASSWORD);

        if (userName == null || password == null) {
            AuthenticationException exception = new AuthenticationException("Username or password field is empty");
            String loginPageUri = configuration.getLoginPageUri().orElseThrow(() -> exception);
            return new AuthenticatorResult(AuthenticatorStatus.ERROR, loginPageUri, exception, null);
        }

        PrivilegedCarbonContext.destroyCurrentContext();
        CarbonMessage carbonMessage = new DefaultCarbonMessage();
        carbonMessage.setHeader(AUTHORIZATION, BASIC + Base64.getEncoder()
                .encodeToString((userName + ":" + password).getBytes()));

        ProxyCallbackHandler callbackHandler = new ProxyCallbackHandler(carbonMessage);
        try {
            LoginContext loginContext = new LoginContext(CARBON_SECURITY_CONFIG, callbackHandler);
            loginContext.login();
        } catch (LoginException e) {
            AuthenticationException exception = new AuthenticationException("Login using login context failed", e);
            String loginPageUri = configuration.getLoginPageUri().orElseThrow(() -> exception);
            return new AuthenticatorResult(AuthenticatorStatus.ERROR, loginPageUri, exception, null);
        }

        User user = new User(userName.toString(), Collections.emptyMap());
        sessionManager.createSession(user, request, response);
        // "loginRedirectUri" value can be configured in the relevant 'component.yaml' configuration.
        String loginRedirectUri = configuration.other().getOrDefault(LOGIN_REDIRECT_URI, "/").toString();
        return new AuthenticatorResult(AuthenticatorStatus.SUCCESS, loginRedirectUri, null, user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticatorResult logout(HttpRequest request, HttpResponse response, SessionManager sessionManager,
                                      Configuration configuration) throws AuthenticationException {
        sessionManager.destroySession(request, response);
        return new AuthenticatorResult(AuthenticatorStatus.SUCCESS, request.getContextPath() + configuration.other()
                .get(LOGIN_REDIRECT_URI).toString(), null, null);
    }
}
