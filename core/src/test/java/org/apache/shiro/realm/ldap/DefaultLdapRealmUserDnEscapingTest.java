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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Tests that the {@link DefaultLdapRealm} escapes the user-supplied principal when substituting it into the
 * configured {@link DefaultLdapRealm#setUserDnTemplate(String) userDnTemplate} (CVE-2026-49268).
 */
public class DefaultLdapRealmUserDnEscapingTest {

    private static final String TEMPLATE = "uid={0},ou=users,dc=mycompany,dc=com";

    private DefaultLdapRealm realm;

    @Before
    public void setUp() {
        realm = new DefaultLdapRealm();
        realm.setUserDnTemplate(TEMPLATE);
    }

    @Test
    public void testUserDnTemplateIsUnchanged() {
        assertEquals(TEMPLATE, realm.getUserDnTemplate());
    }

    @Test
    public void testPlainPrincipalIsUnchanged() {
        assertEquals("uid=jsmith,ou=users,dc=mycompany,dc=com", realm.getUserDn("jsmith"));
    }

    @Test
    public void testInjectedRdnSeparatorsAreEscaped() {
        // an injected ',' / '=' must not add new RDNs to the constructed User DN
        assertEquals("uid=jsmith\\,ou\\=admins,ou=users,dc=mycompany,dc=com",
                realm.getUserDn("jsmith,ou=admins"));
    }

    @Test
    public void testInjectedMultiValuedRdnIsEscaped() {
        // an injected '+' must not turn the RDN into a multi-valued RDN
        assertEquals("uid=jsmith\\+cn\\=admin,ou=users,dc=mycompany,dc=com",
                realm.getUserDn("jsmith+cn=admin"));
    }

    @Test
    public void testRemainingSpecialCharactersAreEscaped() {
        assertEquals("uid=\\#a\\;b\\<c\\>d\\\"e\\\\f\\ ,ou=users,dc=mycompany,dc=com",
                realm.getUserDn("#a;b<c>d\"e\\f "));
    }

    @Test
    public void testAuthenticationBindsWithEscapedUserDn() throws NamingException {
        LdapContextFactory factory = createMock(LdapContextFactory.class);
        realm.setContextFactory(factory);

        // the injected DN components are escaped and stay part of the uid value
        Object expectedPrincipal =
                "uid=admin\\,ou\\=admins\\,dc\\=mycompany\\,dc\\=com\\,,ou=users,dc=mycompany,dc=com";

        expect(factory.getLdapContext(eq(expectedPrincipal), isA(Object.class)))
                .andReturn(createNiceMock(LdapContext.class));
        replay(factory);

        realm.getAuthenticationInfo(new UsernamePasswordToken("admin,ou=admins,dc=mycompany,dc=com,", "secret"));
        verify(factory);
    }
}
