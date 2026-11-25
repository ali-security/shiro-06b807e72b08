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

import org.apache.shiro.io.DefaultSerializer;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.junit.Test;

import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test cases for the {@link AbstractRememberMeManager} implementation.
 */
public class AbstractRememberMeManagerTest {

    /**
     * Tests the {@link AbstractRememberMeManager#getRememberedPrincipals(SubjectContext)} method
     * implementation when the internal
     * {@link AbstractRememberMeManager#getRememberedSerializedIdentity(SubjectContext)} method
     * returns null or empty bytes.
     */
    @Test
    public void testGetRememberedPrincipalsWithEmptySerializedBytes() {
        AbstractRememberMeManager rmm = new DummyRememberMeManager();
        //Since the dummy's getRememberedSerializedIdentity implementation returns an empty byte
        //array, we should be ok:
        PrincipalCollection principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);

        //try with a null return value too:
        rmm = new DummyRememberMeManager() {
            @Override
            protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
                return null;
            }
        };
        principals = rmm.getRememberedPrincipals(new DefaultSubjectContext());
        assertNull(principals);
    }

    /**
     * Ensures the remembered identity carries the server-side creation time (as returned by
     * {@link AbstractRememberMeManager#now()}) and that the principals survive the serialization round trip.
     */
    @Test
    public void testRememberedIdentityContainsCreationTime() {
        Instant creationTime = Instant.parse("2021-01-01T00:00:00Z");
        InMemoryRememberMeManager rmm = new InMemoryRememberMeManager();
        rmm.currentTime = creationTime;
        PrincipalCollection principals = new SimplePrincipalCollection("user", "test");

        byte[] bytes = rmm.convertPrincipalsToBytes(principals);

        AbstractRememberMeManager.RememberedIdentity remembered = rmm.deserialize(rmm.decrypt(bytes));
        assertEquals(principals, remembered.principals());
        assertEquals(creationTime, remembered.creationTime());

        rmm.currentTime = creationTime.plusSeconds(60);
        assertEquals(principals, rmm.convertBytesToPrincipals(bytes, new DefaultSubjectContext()));
    }

    /**
     * A remember me identity captured by an attacker must not be accepted any more once it is older than the
     * permitted max age, even though the captured (encrypted) bytes are replayed unchanged.
     */
    @Test
    public void testReplayedRememberedIdentityIsRejectedAfterMaxAge() {
        final long maxAgeSeconds = 5;
        Instant creationTime = Instant.parse("2021-01-01T00:00:00Z");
        InMemoryRememberMeManager rmm = new InMemoryRememberMeManager() {
            @Override
            protected PrincipalCollection checkExpiration(RememberedIdentity remembered) {
                if (now().isAfter(remembered.creationTime().plusSeconds(maxAgeSeconds))) {
                    return null;
                }
                return super.checkExpiration(remembered);
            }
        };
        PrincipalCollection principals = new SimplePrincipalCollection("user", "test");

        rmm.currentTime = creationTime;
        rmm.rememberIdentity(null, principals);
        byte[] captured = rmm.remembered;

        //still within the max age:
        rmm.currentTime = creationTime.plusSeconds(maxAgeSeconds - 1);
        assertEquals(principals, rmm.getRememberedPrincipals(new DefaultSubjectContext()));

        //replay of the captured identity after the max age has passed:
        rmm.remembered = captured;
        rmm.currentTime = creationTime.plusSeconds(maxAgeSeconds + 1);
        assertNull(rmm.getRememberedPrincipals(new DefaultSubjectContext()));
    }

    /**
     * A remembered identity serialized without a creation time (a bare {@code PrincipalCollection}) cannot be
     * expired and must therefore be rejected instead of being accepted indefinitely.
     */
    @Test
    public void testRememberedIdentityWithoutCreationTimeIsRejected() {
        InMemoryRememberMeManager rmm = new InMemoryRememberMeManager();
        PrincipalCollection principals = new SimplePrincipalCollection("user", "test");
        rmm.remembered = rmm.encrypt(new DefaultSerializer<PrincipalCollection>().serialize(principals));

        PrincipalCollection result = null;
        try {
            result = rmm.getRememberedPrincipals(new DefaultSubjectContext());
            fail("A remembered identity without a creation time must not be accepted");
        } catch (RuntimeException expected) {
            //expected - the identity is forgotten and the failure is propagated
        }
        assertNull(result);
        assertTrue(rmm.forgotten);
    }

    private static class InMemoryRememberMeManager extends AbstractRememberMeManager {
        private Instant currentTime = Instant.now();
        private byte[] remembered;
        private boolean forgotten;

        @Override
        protected Instant now() {
            return currentTime;
        }

        public void forgetIdentity(SubjectContext subjectContext) {
            forgotten = true;
        }

        @Override
        protected void forgetIdentity(Subject subject) {
            forgotten = true;
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
            remembered = serialized;
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return remembered;
        }
    }

    private static class DummyRememberMeManager extends AbstractRememberMeManager {
        public void forgetIdentity(SubjectContext subjectContext) {
            //do nothing
        }

        @Override
        protected void forgetIdentity(Subject subject) {
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return new byte[0];
        }
    }
}
