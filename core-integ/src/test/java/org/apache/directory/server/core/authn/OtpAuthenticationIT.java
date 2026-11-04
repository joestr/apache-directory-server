/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.server.core.authn;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.ApacheDSTestExtension;
import org.apache.directory.server.core.integ.IntegrationUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;


/**
 * Checks the <code>&lt;totp-code&gt;&lt;password&gt;</code> simple bind used for accounts
 * having an <code>otpAuthUri</code> attribute, and that accounts without it are unaffected.
 */
@ExtendWith( ApacheDSTestExtension.class )
@CreateDS(name = "OtpAuthenticationIT-DS")
public class OtpAuthenticationIT extends AbstractLdapTestUnit
{
    /** RFC 6238 test secret ("12345678901234567890", Base32) */
    private static final String SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String OTP_URI = "otpauth://totp/Example:otpuser?secret=" + SECRET + "&issuer=Example";

    private static final String OTP_USER_DN = "uid=otpuser,ou=system";
    private static final String PLAIN_USER_DN = "uid=plainuser,ou=system";
    private static final String PASSWORD = "secret1";


    @BeforeEach
    public void setup() throws Exception
    {
        try ( LdapConnection admin = IntegrationUtils.getAdminConnection( getService() ) )
        {
            String[] schema = new String[]
                {
                    "( 1.3.6.1.4.1.18060.0.4.1.2.20000 NAME 'otpAuthUri' "
                        + "DESC 'otpauth URI (draft-andesco-otpauth-uri)' "
                        + "EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE "
                        + "X-SCHEMA 'other' )"
                };

            admin.modify( subschemaDn( admin ),
                new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, "attributeTypes", schema ) );

            String[] oc = new String[]
                {
                    "( 1.3.6.1.4.1.18060.0.4.1.3.20000 NAME 'otpAccount' AUXILIARY MAY otpAuthUri "
                        + "X-SCHEMA 'other' )"
                };

            admin.modify( subschemaDn( admin ),
                new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, "objectClasses", oc ) );

            admin.add( new DefaultEntry( "uid=otpuser,ou=system",
                "objectClass: top", "objectClass: person", "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson", "objectClass: otpAccount",
                "uid: otpuser", "cn: OTP User", "sn: User",
                "userPassword", PASSWORD,
                "otpAuthUri", OTP_URI ) );

            admin.add( new DefaultEntry( "uid=plainuser,ou=system",
                "objectClass: top", "objectClass: person", "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: plainuser", "cn: Plain User", "sn: User",
                "userPassword", PASSWORD ) );
        }
    }


    @AfterEach
    public void closeConnections()
    {
        IntegrationUtils.closeConnections();
    }


    private static String subschemaDn( LdapConnection conn ) throws Exception
    {
        Entry rootDse = conn.getRootDse( "subschemaSubentry" );

        return rootDse.get( "subschemaSubentry" ).getString();
    }


    private static String currentCode()
    {
        return TotpVerifier.parse( OTP_URI ).generate( System.currentTimeMillis() / 1000L / 30L );
    }


    private boolean binds( String dn, String credentials ) throws Exception
    {
        try ( LdapConnection connection = IntegrationUtils.getConnectionAs( getService(), dn, credentials ) )
        {
            return connection.isAuthenticated();
        }
        catch ( LdapAuthenticationException e )
        {
            return false;
        }
    }


    @Test
    public void testValidCodeAndPassword() throws Exception
    {
        assertTrue( binds( OTP_USER_DN, currentCode() + PASSWORD ) );
    }


    @Test
    public void testWrongCodeRightPassword() throws Exception
    {
        String good = currentCode();
        String wrong = String.format( "%06d", ( Integer.parseInt( good ) + 1234 ) % 1000000 );

        assertFalse( binds( OTP_USER_DN, wrong + PASSWORD ) );
    }


    @Test
    public void testRightCodeWrongPassword() throws Exception
    {
        assertFalse( binds( OTP_USER_DN, currentCode() + "wrong" ) );
    }


    @Test
    public void testPasswordWithoutCodeIsRejected() throws Exception
    {
        assertFalse( binds( OTP_USER_DN, PASSWORD ) );
    }


    @Test
    public void testCodeOnlyIsRejected() throws Exception
    {
        assertFalse( binds( OTP_USER_DN, currentCode() ) );
    }


    @Test
    public void testAccountWithoutOtpAttributeIsUnaffected() throws Exception
    {
        assertTrue( binds( PLAIN_USER_DN, PASSWORD ) );
        // a code prefix must NOT be accepted where no OTP is configured
        assertFalse( binds( PLAIN_USER_DN, currentCode() + PASSWORD ) );
    }


    @Test
    public void testMalformedOtpUriFailsClosed() throws Exception
    {
        try ( LdapConnection admin = IntegrationUtils.getAdminConnection( getService() ) )
        {
            admin.modify( OTP_USER_DN,
                new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, "otpAuthUri", "not-a-uri" ) );
        }

        // Even the plain password must not be enough
        if ( binds( OTP_USER_DN, PASSWORD ) || binds( OTP_USER_DN, currentCode() + PASSWORD ) )
        {
            fail( "Bind must fail when the stored otpAuthUri is unusable" );
        }
    }
}
