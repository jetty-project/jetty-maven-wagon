//
//  ========================================================================
//  Copyright (c) 1995-2019 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//
package org.apache.maven.wagon.providers.http;

import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.repository.Repository;
import org.eclipse.jetty.maven.wagon.JettyClientMavenWagon;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Properties;

public class JettyClientHttpsWagonTest
    extends HttpWagonTestCase
{
    @Override
    protected String getProtocol()
    {
        return "https";
    }

    @Override
    protected void setHttpHeaders( StreamingWagon wagon, Properties properties )
    {
        ( (JettyClientMavenWagon) wagon ).setHttpHeaders( properties );
    }

    public void testClientAuthenticationWithCertificates()
        throws Exception
    {
        logger.info( "\n\nRunning test: " + getName() );

        _handlers = Arrays.asList( new StatusHandler( 200 ) );
        connectors.add( newHttpsConnector( true ) );

        setupRepositories();

        setupWagonTestingFixtures();

        Properties props = System.getProperties();

        try
        {
            System.setProperty( "javax.net.ssl.keyStore", getTestFile( "src/test/resources/ssl/client-store" ).getAbsolutePath() );
            System.setProperty( "javax.net.ssl.keyStorePassword", "client-pwd" );
            System.setProperty( "javax.net.ssl.keyStoreType", "jks" );
            System.setProperty( "javax.net.ssl.trustStore", getTestFile( "src/test/resources/ssl/keystore" ).getAbsolutePath() );
            System.setProperty( "javax.net.ssl.trustStorePassword", "storepwd" );
            System.setProperty( "javax.net.ssl.trustStoreType", "jks" );

            StreamingWagon wagon = (StreamingWagon) getWagon();

            wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

            try
            {
                wagon.getToStream( "/base.txt", new ByteArrayOutputStream() );
            }
            finally
            {
                wagon.disconnect();

                tearDownWagonTestingFixtures();

                stopTestServer();
            }
        }
        finally
        {
            System.setProperties( props );
        }
    }

}
