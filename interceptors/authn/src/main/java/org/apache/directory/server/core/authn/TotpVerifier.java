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


import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


/**
 * Verifies TOTP (RFC 6238) codes against an <code>otpauth://totp/...</code> URI as
 * described in draft-andesco-otpauth-uri-00.
 * <p>
 * Supported URI parameters: <code>secret</code> (Base32, required), <code>algorithm</code>
 * (SHA1 (default), SHA256, SHA512), <code>digits</code> (default 6) and <code>period</code>
 * (default 30). Other parameters (e.g. <code>issuer</code>) are ignored. Only the
 * <code>totp</code> type is supported; anything else is rejected.
 * </p>
 * Instances are immutable and thread safe.
 */
public final class TotpVerifier
{
    private static final int DEFAULT_DIGITS = 6;
    private static final int DEFAULT_PERIOD = 30;
    private static final int MAX_DIGITS = 9;

    /** Number of time steps accepted before and after the current one (clock skew) */
    private static final int WINDOW = 1;

    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private final byte[] secret;
    private final String macAlgorithm;
    private final int digits;
    private final int period;


    private TotpVerifier( byte[] secret, String macAlgorithm, int digits, int period )
    {
        this.secret = secret;
        this.macAlgorithm = macAlgorithm;
        this.digits = digits;
        this.period = period;
    }


    /**
     * Parses an otpauth URI.
     *
     * @param otpAuthUri the URI
     * @return the verifier
     * @throws IllegalArgumentException if the URI is malformed or not a usable TOTP URI
     */
    public static TotpVerifier parse( String otpAuthUri )
    {
        if ( otpAuthUri == null )
        {
            throw new IllegalArgumentException( "otpauth URI is null" );
        }

        URI uri;

        try
        {
            uri = new URI( otpAuthUri.trim() );
        }
        catch ( URISyntaxException e )
        {
            throw new IllegalArgumentException( "Invalid otpauth URI", e );
        }

        if ( !"otpauth".equalsIgnoreCase( uri.getScheme() ) )
        {
            throw new IllegalArgumentException( "Not an otpauth URI" );
        }

        if ( !"totp".equalsIgnoreCase( uri.getHost() ) && !"totp".equalsIgnoreCase( uri.getAuthority() ) )
        {
            throw new IllegalArgumentException( "Unsupported otpauth type, only totp is supported" );
        }

        Map<String, String> params = parseQuery( uri.getRawQuery() );

        String secretParam = params.get( "secret" );

        if ( secretParam == null || secretParam.isEmpty() )
        {
            throw new IllegalArgumentException( "otpauth URI has no secret" );
        }

        byte[] key = decodeBase32( secretParam );

        String algorithm = params.getOrDefault( "algorithm", "SHA1" ).toUpperCase( Locale.ROOT );
        String mac;

        switch ( algorithm )
        {
            case "SHA1":
                mac = "HmacSHA1";
                break;

            case "SHA256":
                mac = "HmacSHA256";
                break;

            case "SHA512":
                mac = "HmacSHA512";
                break;

            default:
                throw new IllegalArgumentException( "Unsupported otpauth algorithm: " + algorithm );
        }

        int digitCount = parsePositive( params.get( "digits" ), DEFAULT_DIGITS, "digits" );

        if ( digitCount > MAX_DIGITS )
        {
            throw new IllegalArgumentException( "Unsupported number of digits: " + digitCount );
        }

        int periodSeconds = parsePositive( params.get( "period" ), DEFAULT_PERIOD, "period" );

        return new TotpVerifier( key, mac, digitCount, periodSeconds );
    }


    /**
     * @return the number of digits of a code
     */
    public int getDigits()
    {
        return digits;
    }


    /**
     * Checks a code against the current time (plus/minus one time step).
     *
     * @param code the submitted code, exactly {@link #getDigits()} digits
     * @param currentTimeMillis the current time
     * @return true if the code is valid
     */
    public boolean verify( String code, long currentTimeMillis )
    {
        if ( code == null || code.length() != digits )
        {
            return false;
        }

        for ( int i = 0; i < code.length(); i++ )
        {
            if ( code.charAt( i ) < '0' || code.charAt( i ) > '9' )
            {
                return false;
            }
        }

        long counter = Math.floorDiv( currentTimeMillis / 1000L, ( long ) period );
        byte[] submitted = code.getBytes( StandardCharsets.US_ASCII );
        boolean match = false;

        // Always evaluate the whole window, no early exit
        for ( int i = -WINDOW; i <= WINDOW; i++ )
        {
            byte[] expected = generate( counter + i ).getBytes( StandardCharsets.US_ASCII );
            match |= MessageDigest.isEqual( expected, submitted );
        }

        return match;
    }


    /**
     * Generates the code for a time step counter (RFC 4226 dynamic truncation).
     */
    String generate( long counter )
    {
        byte[] message = new byte[8];

        for ( int i = 7; i >= 0; i-- )
        {
            message[i] = ( byte ) ( counter & 0xFF );
            counter >>>= 8;
        }

        byte[] hash;

        try
        {
            Mac mac = Mac.getInstance( macAlgorithm );
            mac.init( new SecretKeySpec( secret, macAlgorithm ) );
            hash = mac.doFinal( message );
        }
        catch ( GeneralSecurityException e )
        {
            throw new IllegalStateException( "Cannot compute HMAC " + macAlgorithm, e );
        }

        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ( ( hash[offset] & 0x7F ) << 24 )
            | ( ( hash[offset + 1] & 0xFF ) << 16 )
            | ( ( hash[offset + 2] & 0xFF ) << 8 )
            | ( hash[offset + 3] & 0xFF );

        long modulus = 1;

        for ( int i = 0; i < digits; i++ )
        {
            modulus *= 10;
        }

        StringBuilder sb = new StringBuilder( Long.toString( binary % modulus ) );

        while ( sb.length() < digits )
        {
            sb.insert( 0, '0' );
        }

        return sb.toString();
    }


    private static int parsePositive( String value, int defaultValue, String name )
    {
        if ( value == null )
        {
            return defaultValue;
        }

        try
        {
            int parsed = Integer.parseInt( value.trim() );

            if ( parsed <= 0 )
            {
                throw new IllegalArgumentException( "Invalid otpauth " + name + ": " + value );
            }

            return parsed;
        }
        catch ( NumberFormatException e )
        {
            throw new IllegalArgumentException( "Invalid otpauth " + name + ": " + value, e );
        }
    }


    private static Map<String, String> parseQuery( String rawQuery )
    {
        Map<String, String> params = new HashMap<>();

        if ( rawQuery == null )
        {
            return params;
        }

        for ( String pair : rawQuery.split( "&" ) )
        {
            int eq = pair.indexOf( '=' );

            if ( eq <= 0 )
            {
                continue;
            }

            String key = decode( pair.substring( 0, eq ) )
                .toLowerCase( Locale.ROOT );
            String value = decode( pair.substring( eq + 1 ) );
            params.putIfAbsent( key, value );
        }

        return params;
    }


    private static String decode( String s )
    {
        try
        {
            return URLDecoder.decode( s, "UTF-8" );
        }
        catch ( java.io.UnsupportedEncodingException | IllegalArgumentException e )
        {
            throw new IllegalArgumentException( "Invalid otpauth URI encoding", e );
        }
    }


    private static byte[] decodeBase32( String input )
    {
        String s = input.trim().replace( " ", "" ).replace( "-", "" ).toUpperCase( Locale.ROOT );

        int end = s.length();

        while ( end > 0 && s.charAt( end - 1 ) == '=' )
        {
            end--;
        }

        s = s.substring( 0, end );

        if ( s.isEmpty() )
        {
            throw new IllegalArgumentException( "Empty otpauth secret" );
        }

        byte[] out = new byte[s.length() * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int pos = 0;

        for ( int i = 0; i < s.length(); i++ )
        {
            int val = BASE32.indexOf( s.charAt( i ) );

            if ( val < 0 )
            {
                throw new IllegalArgumentException( "Invalid Base32 character in otpauth secret" );
            }

            buffer = ( buffer << 5 ) | val;
            bits += 5;

            if ( bits >= 8 )
            {
                bits -= 8;
                out[pos++] = ( byte ) ( ( buffer >> bits ) & 0xFF );
            }
        }

        if ( pos == 0 )
        {
            throw new IllegalArgumentException( "otpauth secret too short" );
        }

        return out;
    }
}
