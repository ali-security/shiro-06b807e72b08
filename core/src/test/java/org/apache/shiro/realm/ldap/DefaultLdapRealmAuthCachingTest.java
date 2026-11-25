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
package org.apache.shiro.realm.ldap;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Tests that a {@link DefaultLdapRealm} with authentication caching enabled still verifies the submitted
 * credentials against the cached {@link AuthenticationInfo} (CVE-2026-129349).
 * <p/>
 * Once a user has logged in successfully, the cached {@code AuthenticationInfo} is used for later login attempts of
 * that user without consulting the LDAP directory again, so the realm's {@code CredentialsMatcher} is the only check
 * left for those attempts.
 */
public class DefaultLdapRealmAuthCachingTest {

    private static final String USERNAME = "jsmith";
    private static final String USER_DN = "uid=jsmith,ou=users,dc=mycompany,dc=com";
    private static final String PASSWORD = "secret";
    private static final String WRONG_PASSWORD = "wrong";

    private DefaultLdapRealm realm;
    private LdapContextFactory factory;

    @Before
    public void setUp() throws NamingException {
        realm = new DefaultLdapRealm();
        realm.setUserDnTemplate("uid={0},ou=users,dc=mycompany,dc=com");
        realm.setCacheManager(new MemoryConstrainedCacheManager());
        realm.setAuthenticationCachingEnabled(true);

        // the directory accepts exactly one bind for the user, and only with the correct password: any further
        // lookup (e.g. for the wrong password) is an unexpected call and fails the test
        factory = createMock(LdapContextFactory.class);
        expect(factory.getLdapContext(eq(USER_DN), aryEq(PASSWORD.toCharArray())))
                .andReturn(createNiceMock(LdapContext.class)).once();
        replay(factory);
        realm.setContextFactory(factory);
    }

    @Test
    public void testDefaultCredentialsMatcherVerifiesCredentials() {
        assertTrue(realm.getCredentialsMatcher() instanceof SimpleCredentialsMatcher);
    }

    @Test
    public void testCachedLoginWithWrongPasswordFails() {
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));
        assertNotNull(info);
        assertEquals(USERNAME, info.getPrincipals().getPrimaryPrincipal());

        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, WRONG_PASSWORD));
            fail("A login with a wrong password must not succeed using the cached AuthenticationInfo.");
        } catch (IncorrectCredentialsException expected) {
            // expected
        }

        // the second attempt was served from the cache, not from the directory
        verify(factory);
    }

    @Test
    public void testCachedLoginWithCorrectPasswordSucceeds() {
        AuthenticationInfo first = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));
        AuthenticationInfo second = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));

        assertNotNull(first);
        assertNotNull(second);
        assertEquals(USERNAME, second.getPrincipals().getPrimaryPrincipal());

        // the directory was consulted only for the first login
        verify(factory);
    }

    /**
     * Documents the attack this test class guards against: with the {@link AllowAllCredentialsMatcher} that
     * {@code DefaultLdapRealm} used to install by default, a cached login accepts any password.
     */
    @Test
    public void testAllowAllCredentialsMatcherAcceptsCachedLoginWithAnyPassword() {
        realm.setCredentialsMatcher(new AllowAllCredentialsMatcher());

        realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, PASSWORD));
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken(USERNAME, WRONG_PASSWORD));

        assertNotNull(info);
        assertEquals(USERNAME, info.getPrincipals().getPrimaryPrincipal());
        verify(factory);
    }
}
