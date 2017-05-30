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

package org.wso2.carbon.uuf.core;


import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedSet;
import com.google.gson.JsonObject;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.uuf.api.Placeholder;
import org.wso2.carbon.uuf.api.auth.Permission;
import org.wso2.carbon.uuf.api.auth.Session;
import org.wso2.carbon.uuf.api.auth.User;
import org.wso2.carbon.uuf.api.config.Configuration;
import org.wso2.carbon.uuf.api.model.MapModel;
import org.wso2.carbon.uuf.exception.PageRedirectException;
import org.wso2.carbon.uuf.exception.UUFException;
import org.wso2.carbon.uuf.spi.HttpRequest;
import org.wso2.carbon.uuf.spi.HttpResponse;
import org.wso2.carbon.uuf.spi.Renderable;
import org.wso2.carbon.uuf.spi.auth.SessionManager;
import org.wso2.carbon.uuf.spi.model.Model;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static java.util.Collections.emptySortedSet;
import static java.util.Collections.singleton;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test cases for app.
 *
 * @since 1.0.0
 */
public class AppTest {

    private static SessionManager createSessionManager() {
        User user = mock(User.class);
        SessionManager sessionManager = mock(SessionManager.class);
        when(sessionManager.getSession(any(HttpRequest.class), any())).thenReturn(Optional.of(new Session(user)));
        return sessionManager;
    }

    private static Page createPage(String uri, String content) {
        return new Page(new UriPatten(uri), (model, lookup, requestLookup, api) -> content, null);
    }

    private static Page createErrorPage(String uri) {
        return new Page(new UriPatten(uri), null, null) {
            @Override
            public String render(Model model, Lookup lookup, RequestLookup requestLookup, API api) {
                return model.toMap().get("status") + ":" + model.toMap().get("message");
            }
        };
    }

    private static Fragment createFragment(String name, String content) {
        Renderable renderable = (model, l, rl, a) -> content + (model.toMap().isEmpty() ? "" : model.toMap());
        return new Fragment(name, renderable, null);
    }

    private static Fragment createFragmentWithResources(String name, String content) {
        return new Fragment(name, null, null) {
            @Override
            public String render(Model model, Lookup lookup, RequestLookup requestLookup, API api) {
                requestLookup.addToPlaceholder(Placeholder.css, "CSS Content");
                requestLookup.addToPlaceholder(Placeholder.js, "JS Content");
                requestLookup.addToPlaceholder(Placeholder.headJs, "Head JS Content");
                return content;
            }
        };
    }

    private static HttpRequest createRequest(String contextPath, String uriWithoutContextPath) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.getContextPath()).thenReturn(contextPath);
        when(request.getUri()).thenReturn(contextPath + uriWithoutContextPath);
        when(request.getUriWithoutContextPath()).thenReturn(uriWithoutContextPath);
        when(request.isGetRequest()).thenReturn(true);
        return request;
    }

    private static Configuration createConfiguration() {
        return new Configuration();
    }

    @Test
    public void testRenderPage() {
        final String page1Content = "Page 1 content.";
        Page p1 = createPage("/a/b", page1Content);
        final String page2Content = "Page 2 content.";
        Page p2 = createPage("/x/y", page2Content);
        Component cmp = new Component("cmp", null, "/cmp", ImmutableSortedSet.of(p1, p2), emptySet(), emptySet(),
                                      emptySet(), null);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH, emptySortedSet(),
                                                emptySet(), emptySet(), singleton(cmp), null);
        Configuration configuration = createConfiguration();
        SessionManager sessionManager = createSessionManager();
        App app = createApp(ImmutableSet.of(cmp, rootComponent), configuration, sessionManager);
        String html = app.renderPage(createRequest(app.getContextPath(), "/cmp/a/b"), null);
        Assert.assertEquals(html, page1Content);

        html = app.renderPage(createRequest(app.getContextPath(), "/cmp/x/y"), null);
        Assert.assertEquals(html, page2Content);
    }

    @Test
    public void testRenderPageInRootComponent() {
        Page p1 = createPage("/a/b", "Page 1 content.");
        Page p2 = createPage("/x/y", "Page 2 content.");
        Component cmp = new Component("cmp", null, "/cmp", ImmutableSortedSet.of(p1, p2), emptySet(), emptySet(),
                                      emptySet(), null);
        final String page1Content = "Root page 1 content.";
        Page rootP1 = createPage("/a/b", page1Content);
        final String page2Content = "Root page 2 content.";
        Page rootP2 = createPage("/x/y", page2Content);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH,
                                                ImmutableSortedSet.of(rootP1, rootP2), emptySet(), emptySet(),
                                                singleton(cmp), null);
        Configuration configuration = createConfiguration();
        SessionManager sessionManager = createSessionManager();
        App app = createApp(ImmutableSet.of(cmp, rootComponent), configuration, sessionManager);

        String html = app.renderPage(createRequest(app.getContextPath(), "/a/b"), null);
        Assert.assertEquals(html, page1Content);

        html = app.renderPage(createRequest(app.getContextPath(), "/x/y"), null);
        Assert.assertEquals(html, page2Content);
    }

    @Test
    public void testRenderFragment() {
        final String fragment1Content = "Fragment 1 content.";
        Fragment f1 = createFragment("cmp.f1", fragment1Content);
        final String fragment2Content = "Fragment 2 content.";
        Fragment f2 = createFragment("cmp.f2", fragment2Content);
        Component cmp = new Component("cmp", null, "/cmp", emptySortedSet(), ImmutableSet.of(f1, f2), emptySet(),
                                      emptySet(), null);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH, emptySortedSet(),
                                                emptySet(), emptySet(), singleton(cmp), null);
        Configuration configuration = createConfiguration();
        SessionManager sessionManager = createSessionManager();
        App app = createApp(ImmutableSet.of(cmp, rootComponent), configuration, sessionManager);

        HttpRequest request = createRequest(app.getContextPath(), "/fragments/cmp.f1");
        when(request.getFormParams()).thenReturn(emptyMap());
        JsonObject output = app.renderFragment(request, null);
        Assert.assertEquals(output.get("html").getAsString(), fragment1Content);

        request = createRequest(app.getContextPath(), "/fragments/cmp.f2");
        when(request.getFormParams()).thenReturn(emptyMap());
        output = app.renderFragment(request, null);
        Assert.assertEquals(output.get("html").getAsString(), fragment2Content);
    }

    @Test
    public void testRenderFragmentWithResources() {
        final String fragment1Content = "Fragment 1 with Resource content.";
        Fragment f1 = createFragmentWithResources("cmp.f1", fragment1Content);
        Component cmp = new Component("cmp", null, "/cmp", emptySortedSet(), ImmutableSet.of(f1), emptySet(),
                                      emptySet(), null);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH, emptySortedSet(),
                                                emptySet(), emptySet(), singleton(cmp), null);
        Configuration configuration = createConfiguration();
        App app = createApp(ImmutableSet.of(cmp, rootComponent), configuration, null);

        HttpRequest request = createRequest(app.getContextPath(), "/fragments/cmp.f1");
        when(request.getFormParams()).thenReturn(emptyMap());
        JsonObject output = app.renderFragment(request, null);
        Assert.assertEquals(output.get("html").getAsString(), fragment1Content);
        Assert.assertEquals(output.get("css").getAsString(), "CSS Content");
        Assert.assertEquals(output.get("js").getAsString(), "JS Content");
        Assert.assertEquals(output.get("headJs").getAsString(), "Head JS Content");
    }

    @Test
    public void testRenderFragmentWithParams() {
        final String fragment1Content = "Fragment 1 content.";
        Fragment f1 = createFragment("cmp.f1", fragment1Content);
        Fragment f2 = createFragment("cmp.f2", "Fragment 2 content.");
        Component cmp = new Component("cmp", null, "/cmp", emptySortedSet(), ImmutableSet.of(f1, f2), emptySet(),
                                      emptySet(), null);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH, emptySortedSet(),
                                                emptySet(), emptySet(), singleton(cmp), null);
        Configuration configuration = createConfiguration();
        SessionManager sessionManager = createSessionManager();
        App app = createApp(ImmutableSet.of(cmp, rootComponent), configuration, sessionManager);
        Map<String, Object> formParams = ImmutableMap.of("key1", "value1", "key2", ImmutableList.of("v2-1", "v2-2"));

        HttpRequest request = createRequest(app.getContextPath(), "/fragments/cmp.f1");
        when(request.getFormParams()).thenReturn(formParams);
        HttpResponse response = mock(HttpResponse.class);
        JsonObject output = app.renderFragment(request, response);
        Assert.assertEquals(output.get("html").getAsString(), (fragment1Content + formParams.toString()));
    }

    @Test
    public void testPageUrlCorrection() {
        Page page = createPage("/a/b", null);
        Component cmp = new Component("cmp", null, "/cmp", ImmutableSortedSet.of(page), emptySet(), emptySet(),
                                      emptySet(), null);
        Page rootPage = createPage("/x/y/", null);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH,
                                                ImmutableSortedSet.of(rootPage), emptySet(), emptySet(),
                                                singleton(cmp), null);
        Configuration configuration = createConfiguration();
        SessionManager sessionManager = createSessionManager();
        App app = createApp(ImmutableSet.of(cmp, rootComponent), configuration, sessionManager);
        PageRedirectException pre;

        pre = Assert.expectThrows(PageRedirectException.class,
                                  () -> app.renderPage(createRequest(app.getContextPath(), "/cmp/a/b/"), null));
        Assert.assertEquals(pre.getHttpStatusCode(), HttpResponse.STATUS_FOUND);
        Assert.assertEquals(pre.getRedirectUrl(), "/test/cmp/a/b");

        pre = Assert.expectThrows(PageRedirectException.class,
                                  () -> app.renderPage(createRequest(app.getContextPath(), "/x/y"), null));
        Assert.assertEquals(pre.getHttpStatusCode(), HttpResponse.STATUS_FOUND);
        Assert.assertEquals(pre.getRedirectUrl(), "/test/x/y/");
    }

    @Test
    public void testErrorPageRendering() {
        // Creating component with error pages.
        Page page404 = createErrorPage("/error/404");
        Page page500 = createErrorPage("/error/500");
        Page pageDefault = createErrorPage("/error/default");
        Component cmp = new Component("cmp", null, "/cmp", ImmutableSortedSet.of(page404, page500, pageDefault),
                                      emptySet(), emptySet(), emptySet(), null);
        // Creating root component.
        Page p1 = new Page(new UriPatten("/a"), (m, l, rl, a) -> {
            throw new UUFException("Some error.");
        }, null);
        Page p2 = new Page(new UriPatten("/b"), (m, l, rl, a) -> {
            API.sendError(418, "I’m a Teapot!");
            return null;
        }, null);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH,
                                                ImmutableSortedSet.of(p1, p2), emptySet(), emptySet(), singleton(cmp),
                                                null);
        // Creating configuration.
        Configuration configuration = createConfiguration();
        configuration.setErrorPageUris(ImmutableMap.of(404, "/cmp/error/404", 500, "/cmp/error/500"));
        configuration.setDefaultErrorPageUri("/cmp/error/default");
        // Creating app.
        SessionManager sessionManager = createSessionManager();
        App app = createApp(ImmutableSet.of(cmp, rootComponent), configuration, sessionManager);
        String html;
        Map<String, Object> params;

        // 404 - PageNotFoundException
        html = app.renderPage(createRequest(app.getContextPath(), "/x"), null);
        params = ImmutableMap.of("status", HttpResponse.STATUS_NOT_FOUND,
                                 "message", "Requested page '/x' does not exists.");
        Assert.assertEquals(html, page404.render(new MapModel(params), null, null, null));
        // 500
        html = app.renderPage(createRequest(app.getContextPath(), "/a"), null);
        params = ImmutableMap.of("status", HttpResponse.STATUS_INTERNAL_SERVER_ERROR, "message", "Some error.");
        Assert.assertEquals(html, pageDefault.render(new MapModel(params), null, null, null));
        // 418
        html = app.renderPage(createRequest(app.getContextPath(), "/b"), null);
        params = ImmutableMap.of("status", 418, "message", "I’m a Teapot!");
        Assert.assertEquals(html, page500.render(new MapModel(params), null, null, null));
    }

    @Test
    public void testRedirectingToLoginPage() {
        // Creating root component with secured page.
        String pageUri = "/a";
        Page page = new Page(new UriPatten(pageUri), (m, l, rl, a) -> "Secured page.", Permission.ANY_PERMISSION);
        Component rootComponent = new Component("root", null, Component.ROOT_COMPONENT_CONTEXT_PATH,
                ImmutableSortedSet.of(page), emptySet(), emptySet(), emptySet(), null);
        // Creating configuration.
        Configuration configuration = createConfiguration();
        String loginPageUri = "/some/login/page";
        configuration.setLoginPageUri(loginPageUri);
        // Create session manager
        SessionManager sessionManager = mock(SessionManager.class);
        when(sessionManager.getSession(any(HttpRequest.class), any(HttpResponse.class)))
                .thenReturn(Optional.empty());
        App app = createApp(singleton(rootComponent), configuration, sessionManager);
        PageRedirectException pre = Assert.expectThrows(PageRedirectException.class, () ->
                app.renderPage(createRequest(app.getContextPath(), "/a"), null));
        Assert.assertEquals(pre.getHttpStatusCode(), HttpResponse.STATUS_FOUND);
        Assert.assertEquals(pre.getRedirectUrl(), app.getContextPath() + loginPageUri);
    }

    private App createApp(Set<Component> componentSet, Configuration configuration, SessionManager sessionManager) {
        return new App(null, "/test", componentSet, emptySet(), configuration,
                null, null, sessionManager, null, null);
    }
}
