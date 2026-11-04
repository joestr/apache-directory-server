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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;


public class TotpVerifierTest
{
    private static final String SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static final String SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";


    @Test
    public void testRfc6238Sha1()
    {
        TotpVerifier v = TotpVerifier.parse( "otpauth://totp/Example:alice?secret=" + SHA1 + "&digits=8&issuer=Example" );

        assertTrue( v.verify( "94287082", 59_000L ) );
        assertTrue( v.verify( "07081804", 1111111109_000L ) );
        assertFalse( v.verify( "94287083", 59_000L ) );
    }


    @Test
    public void testRfc6238Sha256()
    {
        TotpVerifier v = TotpVerifier.parse( "otpauth://totp/a?secret=" + SHA256 + "&digits=8&algorithm=SHA256" );

        assertTrue( v.verify( "46119246", 59_000L ) );
    }


    @Test
    public void testDefaultsAndWindow()
    {
        TotpVerifier v = TotpVerifier.parse( "otpauth://totp/a?secret=" + SHA1 );
        String code = v.generate( 59L / 30 );

        assertEquals( 6, code.length() );
        assertTrue( v.verify( code, 59_000L ) );
        // one step later still accepted, several steps not
        assertTrue( v.verify( code, 89_000L ) );
        assertFalse( v.verify( code, 150_000L ) );
    }


    @Test
    public void testRejectsBadInput()
    {
        TotpVerifier v = TotpVerifier.parse( "otpauth://totp/a?secret=" + SHA1 );

        assertFalse( v.verify( null, 0L ) );
        assertFalse( v.verify( "12345", 0L ) );
        assertFalse( v.verify( "abcdef", 0L ) );
    }


    @Test
    public void testRejectsBadUris()
    {
        assertThrows( IllegalArgumentException.class, () -> TotpVerifier.parse( null ) );
        assertThrows( IllegalArgumentException.class, () -> TotpVerifier.parse( "http://totp/a?secret=" + SHA1 ) );
        assertThrows( IllegalArgumentException.class, () -> TotpVerifier.parse( "otpauth://hotp/a?secret=" + SHA1 ) );
        assertThrows( IllegalArgumentException.class, () -> TotpVerifier.parse( "otpauth://totp/a" ) );
        assertThrows( IllegalArgumentException.class, () -> TotpVerifier.parse( "otpauth://totp/a?secret=!!!" ) );
        assertThrows( IllegalArgumentException.class,
            () -> TotpVerifier.parse( "otpauth://totp/a?secret=" + SHA1 + "&algorithm=MD5" ) );
    }
}
