/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.uuf.spi.auth;

import org.wso2.carbon.uuf.api.auth.User;
import org.wso2.carbon.uuf.api.config.Configuration;
import org.wso2.carbon.uuf.exception.AuthenticationException;
import org.wso2.carbon.uuf.spi.HttpRequest;
import org.wso2.carbon.uuf.spi.HttpResponse;

/**
 * Authenticates users to UUF apps.
 * <p>
 * Please make note to specify the authenticator class name in the <tt>app.yaml</tt> configuration file under the
 * <tt>authenticator</tt> key in order for the implemented authenticator to be used in the app.
 * <p>
 * eg:
 * authenticator: "org.wso2.carbon.uuf.sample.simpleauth.bundle.api.auth.FormParamAuthenticator"
 * <p>
 * If the authenticator is not configured, all the authentications will be evaluated as failed authentication attempts.
 *
 * @since 1.0.0
 */
public interface Authenticator {

    /**
     * Authenticates an user to UUF apps.
     *
     * @param request        HTTP request
     * @param response       HTTP response
     * @param sessionManager Session manager for the UUF app
     * @param configuration  app configuration
     * @return {@link AuthenticatorResult} AuthenticatorResult depicting the status of the authentication
     * @throws AuthenticationException if any error occurs during the authentication process
     */
    AuthenticatorResult login(HttpRequest request, HttpResponse response, SessionManager sessionManager,
                              Configuration configuration) throws AuthenticationException;

    /**
     * Logout an authenticated user from UUF apps.
     *
     * @param request        HTTP request
     * @param response       HTTP response
     * @param sessionManager Session manager for the UUF app
     * @param configuration  app configuration
     * @return {@link AuthenticatorResult} AuthenticatorResult depicting the status of the logout
     * @throws AuthenticationException if any error occurs during the logout process
     */
    AuthenticatorResult logout(HttpRequest request, HttpResponse response, SessionManager sessionManager,
                               Configuration configuration) throws AuthenticationException;

    /**
     * Possible outcomes of the authentication process.
     * <p>
     * <ul>
     * <li>
     * SUCCESS - Indicates that the authentication or the logout process of an User is successful.
     * </li>
     * <li>
     * ERROR - Indicates that the authentication or the logout process of an User is unsuccessful.
     * </li>
     * <li>
     * REDIRECT - Indicates an authentication redirect.
     * </li>
     * <li>
     * CONTINUE - Indicates that the request do not comprehend to be an authentication request and also to
     * proceed without interruption.
     * </li>
     * </ul>
     */
    enum AuthenticatorStatus {
        SUCCESS,
        ERROR,
        REDIRECT,
        CONTINUE
    }

    /**
     * Bean class to hold the result of an authentication.
     */
    class AuthenticatorResult {

        private final AuthenticatorStatus status;
        private final String redirectURL;
        private final AuthenticationException exception;
        private final User user;

        /**
         * Constructs an authenticator result.
         *
         * @param status      status of the authentication
         * @param redirectURL redirect URL after the authentication attempt
         * @param exception   authentication exception upon error on authentication
         * @param user        authenticated user
         */
        public AuthenticatorResult(AuthenticatorStatus status, String redirectURL, AuthenticationException exception,
                                   User user) {
            this.status = status;
            this.redirectURL = redirectURL;
            this.exception = exception;
            this.user = user;
        }

        /**
         * Get authenticator status.
         *
         * @return authenticator status
         */
        public AuthenticatorStatus getStatus() {
            return status;
        }

        /**
         * Get redirect URL after the authentication attempt.
         *
         * @return redirect URL
         */
        public String getRedirectURL() {
            return redirectURL;
        }

        /**
         * Get authentication exception upon error on authentication or logout.
         *
         * @return authentication exception
         */
        public AuthenticationException getException() {
            return exception;
        }

        /**
         * Get authenticated user.
         *
         * @return authenticated user
         */
        public User getUser() {
            return user;
        }
    }
}
