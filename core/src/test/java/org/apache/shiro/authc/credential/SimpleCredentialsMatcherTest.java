/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.authc.credential;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.util.SimpleByteSource;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for the {@link SimpleCredentialsMatcher} implementation.
 */
public class SimpleCredentialsMatcherTest {

    @Test
    public void testMatchingCredentials() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertTrue(matcher.doCredentialsMatch(new UsernamePasswordToken("user", "secret"),
                new SimpleAuthenticationInfo("user", "secret", "realm")));
        assertTrue(matcher.doCredentialsMatch(new UsernamePasswordToken("user", "secret"),
                new SimpleAuthenticationInfo("user", "secret".toCharArray(), "realm")));
    }

    @Test
    public void testNonMatchingCredentials() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", "wrong"),
                new SimpleAuthenticationInfo("user", "secret", "realm")));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", ""),
                new SimpleAuthenticationInfo("user", "secret", "realm")));
    }

    /**
     * An empty stored credential must never match an empty submitted password.
     */
    @Test
    public void testEmptyStoredCredentialsNeverMatchEmptySubmittedPassword() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        UsernamePasswordToken emptyPassword = new UsernamePasswordToken("user", "");

        assertFalse(matcher.doCredentialsMatch(emptyPassword, new SimpleAuthenticationInfo("user", "", "realm")));
        assertFalse(matcher.doCredentialsMatch(emptyPassword,
                new SimpleAuthenticationInfo("user", new char[0], "realm")));
        assertFalse(matcher.doCredentialsMatch(emptyPassword,
                new SimpleAuthenticationInfo("user", new byte[0], "realm")));
        assertFalse(matcher.doCredentialsMatch(emptyPassword,
                new SimpleAuthenticationInfo("user", new SimpleByteSource(new byte[0]), "realm")));
    }

    /**
     * A missing (null) stored credential must never match, neither a missing nor an empty submitted password.
     */
    @Test
    public void testMissingStoredCredentialsNeverMatch() {
        SimpleCredentialsMatcher matcher = new SimpleCredentialsMatcher();
        AuthenticationInfo noCredentials = new SimpleAuthenticationInfo("user", null, "realm");

        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", (char[]) null), noCredentials));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", ""), noCredentials));
        assertFalse(matcher.doCredentialsMatch(new UsernamePasswordToken("user", "secret"), noCredentials));
    }

    /**
     * An account configured with an empty password must not be accessible by logging in with an empty password.
     */
    @Test
    public void testRealmAccountWithEmptyPasswordCannotLogInWithEmptyPassword() {
        SimpleAccountRealm realm = new SimpleAccountRealm();
        realm.addAccount("user", "");
        realm.addAccount("other", "secret");

        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken("user", ""));
            fail("An empty stored password must not match an empty submitted password.");
        } catch (IncorrectCredentialsException expected) {
        }

        // an account with a real password still authenticates
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken("other", "secret")));
    }
}
