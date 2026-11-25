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
package org.apache.shiro.mgt;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.AbstractValidatingSessionManager;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;

import static org.junit.Assert.*;


/**
 * @since 0.2
 */
public class DefaultSecurityManagerTest extends AbstractSecurityManagerTest {

    DefaultSecurityManager sm = null;

    @Before
    public void setup() {
        sm = new DefaultSecurityManager();
        Ini ini = new Ini();
        Ini.Section section = ini.addSection(IniRealm.USERS_SECTION_NAME);
        section.put("guest", "guest, guest");
        section.put("lonestarr", "vespa, goodguy");
        sm.setRealm(new IniRealm(ini));
        SecurityUtils.setSecurityManager(sm);
    }

    @After
    public void tearDown() {
        SecurityUtils.setSecurityManager(null);
        sm.destroy();
        super.tearDown();
    }

    @Test
    public void testDefaultConfig() {
        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertTrue(subject.isAuthenticated());
        assertTrue("guest".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("guest"));

        Session session = subject.getSession();
        session.setAttribute("key", "value");
        assertEquals(session.getAttribute("key"), "value");

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());
    }

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-46">JSEC-46</a>
     */
    @Test
    public void testAutoCreateSessionAfterInvalidation() {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        Serializable origSessionId = session.getId();

        String key = "foo";
        String value1 = "bar";
        session.setAttribute(key, value1);
        assertEquals(value1, session.getAttribute(key));

        //now test auto creation:
        session.setTimeout(50);
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            //ignored
        }
        try {
            session.setTimeout(AbstractValidatingSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
            fail("Session should have expired.");
        } catch (ExpiredSessionException expected) {
        }
    }

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-22">JSEC-22</a>
     */
    @Test
    public void testSubjectReuseAfterLogout() {

        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertTrue(subject.isAuthenticated());
        assertTrue("guest".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("guest"));

        Session session = subject.getSession();
        Serializable firstSessionId = session.getId();

        session.setAttribute("key", "value");
        assertEquals(session.getAttribute("key"), "value");

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());

        subject.login(new UsernamePasswordToken("lonestarr", "vespa"));
        assertTrue(subject.isAuthenticated());
        assertTrue("lonestarr".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("goodguy"));

        assertNotNull(subject.getSession());
        assertFalse(firstSessionId.equals(subject.getSession().getId()));

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());

    }

    /**
     * Test ensures that a {@link Subject#login(AuthenticationToken)} first uses
     * the {@link SecurityManager} passed to its {@link Subject.Builder}
     * (if one was) instead of the one found in either the {@link ThreadContext}
     * or statically in {@link SecurityUtils}, either of which may not exist.
     * <a href="https://issues.apache.org/jira/browse/SHIRO-457">SHIRO-457</a>
     */
    @Test
    public void testNewSubjectWithoutThreadSecurityManager() {
        // Ensure no fallback sm exists in thread context or statically
        SecurityUtils.setSecurityManager(null);
        try {
            SecurityUtils.getSecurityManager();
        } catch (UnavailableSecurityManagerException e) {
            assertTrue(e.getMessage().startsWith("No SecurityManager accessible"));
        }

        // Specify sm to use and build subject with
        DelegatingSubject subject =
            (DelegatingSubject)(new Subject.Builder(sm)).buildSubject();

        // Login and verify specified sm is used and no error thrown
        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertEquals(sm, subject.getSecurityManager());
    }

    /**
     * Restoring a Subject from a RememberMe identity over an existing (possibly attacker-fixated) session must
     * stop that session and continue on a newly created one (session fixation protection).
     */
    @Test
    public void testRememberedSubjectRegeneratesExistingSession() {
        // an anonymous session, e.g. one whose ID was planted by an attacker:
        Session fixated = new Subject.Builder(sm).buildSubject().getSession();
        fixated.setAttribute("tenantId", "ACME");
        Serializable fixatedId = fixated.getId();

        sm.setRememberMeManager(new FixedRememberMeManager(new SimplePrincipalCollection("guest", "iniRealm")));

        Subject remembered = new Subject.Builder(sm).sessionId(fixatedId).buildSubject();
        assertTrue(remembered.isRemembered());
        assertEquals("guest", remembered.getPrincipal());

        Session session = remembered.getSession(false);
        assertNotNull(session);
        assertNotEquals("session ID must change when a subject is restored from RememberMe",
                fixatedId, session.getId());
        assertEquals("session attributes must survive session rotation", "ACME", session.getAttribute("tenantId"));

        // the fixated session must be gone, so its ID can no longer resolve to the remembered identity:
        try {
            sm.getSession(new DefaultSessionKey(fixatedId));
            fail("The fixated session should have been stopped.");
        } catch (InvalidSessionException expected) {
        }
        sm.setRememberMeManager(null);
        Subject attacker = new Subject.Builder(sm).sessionId(fixatedId).buildSubject();
        assertNull("fixated session ID must not carry the remembered principal", attacker.getPrincipal());
        assertNull(attacker.getSession(false));
    }

    /**
     * Once the remembered identity is stored in the (regenerated) session, later subjects built for that session do
     * not rotate it again.
     */
    @Test
    public void testRememberedSubjectSessionNotRegeneratedOnSubsequentRequests() {
        sm.setRememberMeManager(new FixedRememberMeManager(new SimplePrincipalCollection("guest", "iniRealm")));

        Subject first = new Subject.Builder(sm).buildSubject();
        assertTrue(first.isRemembered());
        Serializable sessionId = first.getSession().getId();

        Subject next = new Subject.Builder(sm).sessionId(sessionId).buildSubject();
        assertEquals("guest", next.getPrincipal());
        assertEquals(sessionId, next.getSession(false).getId());
    }

    /**
     * Restoring a remembered identity without an existing session must not fail.
     */
    @Test
    public void testRememberedSubjectWithoutExistingSession() {
        sm.setRememberMeManager(new FixedRememberMeManager(new SimplePrincipalCollection("guest", "iniRealm")));

        Subject remembered = new Subject.Builder(sm).buildSubject();
        assertTrue(remembered.isRemembered());
        assertEquals("guest", remembered.getPrincipal());
        assertEquals(remembered.getPrincipals(),
                remembered.getSession().getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY));
    }

    /**
     * A subject built over an existing session without a remembered identity keeps its session.
     */
    @Test
    public void testNonRememberedSubjectKeepsExistingSession() {
        Serializable sessionId = new Subject.Builder(sm).buildSubject().getSession().getId();

        Subject subject = new Subject.Builder(sm).sessionId(sessionId).buildSubject();
        assertFalse(subject.isRemembered());
        assertEquals(sessionId, subject.getSession(false).getId());
    }

    private static class FixedRememberMeManager implements RememberMeManager {

        private final PrincipalCollection principals;

        FixedRememberMeManager(PrincipalCollection principals) {
            this.principals = principals;
        }

        public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
            return principals;
        }

        public void forgetIdentity(SubjectContext subjectContext) {
        }

        public void onSuccessfulLogin(Subject subject, AuthenticationToken token, AuthenticationInfo info) {
        }

        public void onFailedLogin(Subject subject, AuthenticationToken token, AuthenticationException ae) {
        }

        public void onLogout(Subject subject) {
        }
    }
}
