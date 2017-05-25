/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

//noinspection JSUnusedGlobalSymbols
function onGet(env) {
    var session = getSession();
    if (!session) {
        var User = Java.type("org.wso2.carbon.uuf.api.auth.User");
        var user = new User("admin", null);
        createSession(user);
        // TODO: Session to be applied without any re-directs.
        sendRedirect(env.contextPath + "/theme/session-scope");

    }
    session.setThemeName("org.wso2.carbon.uuf.sample.green.theme");
}
