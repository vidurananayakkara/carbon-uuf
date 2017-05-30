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

package org.wso2.carbon.uuf.api.config;

import com.google.common.collect.ImmutableMap;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Collections;

/**
 * Test cases for configuration.
 *
 * @since 1.0.0
 */
public class ConfigurationTest {

    private static Configuration createConfiguration() {
        return new Configuration();
    }

    @Test
    public void testContextPathValidation() {
        Configuration configuration = createConfiguration();
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setContextPath(""));
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setContextPath("a/bc"));

        configuration.setContextPath(null);
        configuration.setContextPath("/abc");
    }

    @Test
    public void testThemeNameValidation() {
        Configuration configuration = createConfiguration();
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setThemeName(""));

        configuration.setThemeName(null);
        configuration.setThemeName("org.wso2.carbon.uuf.sample.blue.theme");
    }

    @Test
    public void testLoginPageUriValidation() {
        Configuration configuration = createConfiguration();
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setLoginPageUri(""));
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setLoginPageUri("a/bc"));

        configuration.setLoginPageUri(null);
        configuration.setLoginPageUri("/simple-auth/login");
    }

    @Test
    public void testLogoutPageUriValidation() {
        Configuration configuration = createConfiguration();
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setLogoutPageUri(""));
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setLogoutPageUri("a/bc"));

        configuration.setLogoutPageUri(null);
        configuration.setLogoutPageUri("/simple-auth/logout");
    }

    @Test
    public void testAuthorizerValidations() {
        Configuration configuration = createConfiguration();

        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setAuthorizer(""));
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setAuthorizer("c/lass"));
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setAuthorizer("c*lass"));

        configuration.setAuthorizer(null);
        configuration.setAuthorizer("CaasAuthorizer");
        configuration.setAuthorizer("org.wso2.carbon.uuf.sample.simpleauth.bundle.api.auth." +
                "CaasAuthorizer");
    }

    @Test
    public void testSessionManagerValidations() {
        Configuration configuration = createConfiguration();

        // Session manager factory class validations
        Assert.assertThrows(IllegalArgumentException.class, () ->
                configuration.setSessionManagerFactoryClassName(""));
        Assert.assertThrows(IllegalArgumentException.class, () ->
                configuration.setSessionManagerFactoryClassName("c/lass"));
        Assert.assertThrows(IllegalArgumentException.class, () ->
                configuration.setSessionManagerFactoryClassName("c*lass"));
        configuration.setSessionManagerFactoryClassName(null);
        configuration.setSessionManagerFactoryClassName("PersistentSessionManager");
        configuration.setSessionManagerFactoryClassName("org.wso2.carbon.uuf.sample.simpleauth.bundle.api.auth." +
                "PersistentSessionManagerFactory");

        // Session timeout validations
        Assert.assertEquals(0L, configuration.getSessionTimeout());
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setSessionTimeout(-1));
        configuration.setSessionTimeout(0);
    }

    @Test
    public void testAuthenticatorValidations() {
        Configuration configuration = createConfiguration();

        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setAuthenticator(""));
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setAuthenticator("c/lass"));
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setAuthenticator("c*lass"));
        configuration.setAuthenticator(null);
        configuration.setAuthenticator("FormParamAuthenticator");
        configuration.setAuthenticator("org.wso2.carbon.uuf.sample.simpleauth.bundle.api.auth.FormParamAuthenticator");
    }

    @Test
    public void testErrorPageUrisValidation() {
        Configuration configuration = createConfiguration();
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> configuration.setErrorPageUris(ImmutableMap.of(99, "/error/99")));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> configuration.setErrorPageUris(ImmutableMap.of(1000, "/error/100")));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> configuration.setErrorPageUris(Collections.singletonMap(500, null)));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> configuration.setErrorPageUris(ImmutableMap.of(500, "")));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> configuration.setErrorPageUris(ImmutableMap.of(500, "error/500")));

        configuration.setErrorPageUris(null);
        configuration.setErrorPageUris(Collections.emptyMap());
        configuration.setErrorPageUris(ImmutableMap.of(500, "/error/500"));
    }

    @Test
    public void testDefaultErrorPageUriValidation() {
        Configuration configuration = createConfiguration();
        Assert.assertThrows(IllegalArgumentException.class, () -> configuration.setDefaultErrorPageUri(""));
        Assert.assertThrows(IllegalArgumentException.class,
                            () -> configuration.setDefaultErrorPageUri("error/default"));

        configuration.setDefaultErrorPageUri(null);
        configuration.setDefaultErrorPageUri("/error/default");
    }
}
