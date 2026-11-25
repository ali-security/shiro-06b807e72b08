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
package org.apache.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.HashService;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AuthenticatingRealmJavaTest {

    private static final String EXISTING_USER = "existing";
    private static final String EXISTING_PASSWORD = "secret";

    @Test
    public void authenticatingRealmShouldCreateSha256HashWhenUserDoesNotExist() {
        // given
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(token);

        // then
        assertNull(info);
        assertEquals(1, passwordMatcher.createSimulatedCredentialsCount);
        assertEquals("the simulated credentials must be verified for a non-existent user",
                1, passwordMatcher.doCredentialsMatchCount);

        Object simulatedCredentials = realm.authInfo.getCredentials();
        assertTrue(simulatedCredentials instanceof String);
        // DefaultPasswordService defaults: SHA-256, 500000 iterations, Shiro1CryptFormat
        assertTrue(String.valueOf(simulatedCredentials), ((String) simulatedCredentials).startsWith("$shiro1$SHA-256$500000$"));
    }

    @Test
    public void authenticatingRealmShouldUseConfiguredHashAlgorithmWhenUserDoesNotExist() {
        // given
        DefaultHashService sha512HashService = new DefaultHashService();
        sha512HashService.setHashAlgorithmName("SHA-512");
        sha512HashService.setHashIterations(1024);
        sha512HashService.setGeneratePublicSalt(true);
        DefaultPasswordService defaultPasswordService = new DefaultPasswordService();
        defaultPasswordService.setHashService(sha512HashService);
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        passwordMatcher.setPasswordService(defaultPasswordService);

        AuthenticationToken token = new UsernamePasswordToken("username", "password".toCharArray());
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(token);

        // then
        assertNull(info);
        assertEquals(1, passwordMatcher.createSimulatedCredentialsCount);
        assertEquals(1, passwordMatcher.doCredentialsMatchCount);

        Object simulatedCredentials = realm.authInfo.getCredentials();
        assertTrue(simulatedCredentials instanceof String);
        assertTrue(String.valueOf(simulatedCredentials), ((String) simulatedCredentials).startsWith("$shiro1$SHA-512$1024$"));
    }

    @Test
    public void simulatedCredentialsShouldBeCreatedOnlyOnce() {
        // given
        CountingPasswordMatcher passwordMatcher = new CountingPasswordMatcher();
        passwordMatcher.setPasswordService(passwordService(new DefaultHashService()));
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(passwordMatcher);

        // when
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("user1", "password1".toCharArray())));
        AuthenticationInfo first = realm.authInfo;
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("user2", "password2".toCharArray())));

        // then
        assertNotNull(first);
        assertSame(first, realm.authInfo);
        assertEquals(1, passwordMatcher.createSimulatedCredentialsCount);
        assertEquals(2, passwordMatcher.doCredentialsMatchCount);
    }

    /**
     * CVE-2026-23901: an attacker must not be able to distinguish an existing account from a non-existent one by
     * the time it takes to reject the login, i.e. a non-existent user has to cost the same password hashing work
     * (same algorithm, same number of iterations) as an existing user submitting a wrong password.
     */
    @Test
    public void passwordMatcherShouldHashUnknownUserLikeExistingUser() {
        // given
        CountingHashService hashService = new CountingHashService();
        DefaultPasswordService passwordService = passwordService(hashService);
        PasswordMatcher passwordMatcher = new PasswordMatcher();
        passwordMatcher.setPasswordService(passwordService);
        SingleUserRealm realm = new SingleUserRealm(passwordService.encryptPassword(EXISTING_PASSWORD));
        realm.setCredentialsMatcher(passwordMatcher);
        // the simulated credentials are created (once) on the first unknown-user login
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("warmup", "warmup".toCharArray())));

        // when: existing user, wrong password
        hashService.requests.clear();
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(EXISTING_USER, "wrong".toCharArray()));
            fail("IncorrectCredentialsException should have been thrown.");
        } catch (IncorrectCredentialsException expected) {
        }
        List<HashRequest> existingUserRequests = new ArrayList<HashRequest>(hashService.requests);

        // when: non-existent user
        hashService.requests.clear();
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken("unknown", "wrong".toCharArray()));
        List<HashRequest> unknownUserRequests = new ArrayList<HashRequest>(hashService.requests);

        // then
        assertNull(info);
        assertEquals(1, existingUserRequests.size());
        assertEquals("a non-existent user must cost the same password hashing as an existing one",
                existingUserRequests.size(), unknownUserRequests.size());
        assertEquals(existingUserRequests.get(0).getAlgorithmName(), unknownUserRequests.get(0).getAlgorithmName());
        assertEquals(existingUserRequests.get(0).getIterations(), unknownUserRequests.get(0).getIterations());
        assertEquals(2048, unknownUserRequests.get(0).getIterations());
    }

    /**
     * Same as {@link #passwordMatcherShouldHashUnknownUserLikeExistingUser()} for the (1.x-common)
     * {@link HashedCredentialsMatcher}, which inherits its simulated credentials from {@link SimpleCredentialsMatcher}.
     */
    @Test
    public void hashedCredentialsMatcherShouldHashUnknownUserLikeExistingUser() {
        // given
        CountingHashedCredentialsMatcher matcher = new CountingHashedCredentialsMatcher();
        matcher.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
        matcher.setHashIterations(1024);
        SingleUserRealm realm = new SingleUserRealm(new Sha256Hash(EXISTING_PASSWORD, null, 1024).toHex());
        realm.setCredentialsMatcher(matcher);
        // sanity check: the existing user can log in
        assertNotNull(realm.getAuthenticationInfo(new UsernamePasswordToken(EXISTING_USER, EXISTING_PASSWORD.toCharArray())));

        // when: existing user, wrong password
        matcher.hashIterations.clear();
        try {
            realm.getAuthenticationInfo(new UsernamePasswordToken(EXISTING_USER, "wrong".toCharArray()));
            fail("IncorrectCredentialsException should have been thrown.");
        } catch (IncorrectCredentialsException expected) {
        }
        List<Integer> existingUserHashes = new ArrayList<Integer>(matcher.hashIterations);

        // when: non-existent user
        matcher.hashIterations.clear();
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken("unknown", "wrong".toCharArray()));
        List<Integer> unknownUserHashes = new ArrayList<Integer>(matcher.hashIterations);

        // then
        assertNull(info);
        assertEquals(1, existingUserHashes.size());
        assertEquals("a non-existent user must cost the same credentials hashing as an existing one",
                existingUserHashes, unknownUserHashes);
    }

    @Test
    public void simpleCredentialsMatcherShouldCheckSimulatedCredentialsWhenUserDoesNotExist() {
        // given
        CountingSimpleCredentialsMatcher matcher = new CountingSimpleCredentialsMatcher();
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(matcher);

        // when
        AuthenticationInfo info = realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password".toCharArray()));

        // then
        assertNull(info);
        assertEquals(1, matcher.doCredentialsMatchCount);
        assertTrue(realm.authInfo.getCredentials() instanceof byte[]);
    }

    @Test
    public void credentialsMatcherWithoutSimulatedCredentialsShouldStillReturnNull() {
        // given: a custom matcher which does not implement createSimulatedCredentials()
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(new CredentialsMatcher() {
            public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
                return false;
            }
        });

        // when / then
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password".toCharArray())));
        assertNull(realm.authInfo);
    }

    @Test
    public void simulatedCredentialsMatchingShouldNotAuthenticate() {
        // given: a misconfigured matcher that matches its own simulated credentials
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(new CredentialsMatcher() {
            public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
                return true;
            }

            @Override
            public Optional<AuthenticationInfo> createSimulatedCredentials() {
                return Optional.of(new SimpleAuthenticationInfo("user", "password", "realm"));
            }
        });

        // when / then
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password".toCharArray())));
    }

    @Test
    public void missingCredentialsMatcherShouldStillReturnNull() {
        // given
        NullAuthenticatingRealm realm = new NullAuthenticatingRealm();
        realm.setCredentialsMatcher(null);

        // when / then
        assertNull(realm.getAuthenticationInfo(new UsernamePasswordToken("username", "password".toCharArray())));
    }

    private static DefaultPasswordService passwordService(HashService hashService) {
        if (hashService instanceof DefaultHashService) {
            DefaultHashService defaultHashService = (DefaultHashService) hashService;
            defaultHashService.setHashAlgorithmName("SHA-256");
            defaultHashService.setHashIterations(2048);
            defaultHashService.setGeneratePublicSalt(true);
        }
        DefaultPasswordService passwordService = new DefaultPasswordService();
        passwordService.setHashService(hashService);
        return passwordService;
    }

    /**
     * For the test, it is important that this class returns {@code null} for
     * {@link AuthenticatingRealm#doGetAuthenticationInfo(AuthenticationToken)},
     * so that simulatedAuthenticationInfo is being created.
     */
    static class NullAuthenticatingRealm extends AuthenticatingRealm {

        /**
         * captured created authenticationInfo
         */
        private AuthenticationInfo authInfo;

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
            return null;
        }

        /**
         * Captures the created authenticationInfo for tests.
         * @return see super method.
         */
        @Override
        AuthenticationInfo ensureSimulatedAuthenticationInfo() {
            final AuthenticationInfo authInfo1 = super.ensureSimulatedAuthenticationInfo();
            this.authInfo = authInfo1;
            return authInfo1;
        }
    }

    /**
     * Realm knowing a single {@link #EXISTING_USER} account; every other username does not exist.
     */
    static class SingleUserRealm extends AuthenticatingRealm {

        private final Object storedCredentials;

        SingleUserRealm(Object storedCredentials) {
            this.storedCredentials = storedCredentials;
        }

        @Override
        protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
            if (EXISTING_USER.equals(token.getPrincipal())) {
                return new SimpleAuthenticationInfo(EXISTING_USER, storedCredentials, getName());
            }
            return null;
        }
    }

    static class CountingPasswordMatcher extends PasswordMatcher {
        private int createSimulatedCredentialsCount;
        private int doCredentialsMatchCount;

        @Override
        public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
            doCredentialsMatchCount++;
            return super.doCredentialsMatch(token, info);
        }

        @Override
        public Optional<AuthenticationInfo> createSimulatedCredentials() {
            createSimulatedCredentialsCount++;
            return super.createSimulatedCredentials();
        }
    }

    static class CountingSimpleCredentialsMatcher extends SimpleCredentialsMatcher {
        private int doCredentialsMatchCount;

        @Override
        public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
            doCredentialsMatchCount++;
            return super.doCredentialsMatch(token, info);
        }
    }

    static class CountingHashedCredentialsMatcher extends HashedCredentialsMatcher {
        private final List<Integer> hashIterations = new ArrayList<Integer>();

        @Override
        protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations) {
            this.hashIterations.add(hashIterations);
            return super.hashProvidedCredentials(credentials, salt, hashIterations);
        }
    }

    static class CountingHashService extends DefaultHashService {
        private final List<HashRequest> requests = new ArrayList<HashRequest>();

        @Override
        public Hash computeHash(HashRequest request) {
            requests.add(request);
            return super.computeHash(request);
        }
    }
}
