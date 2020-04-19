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

package org.eclipse.jetty.maven.wagon;

import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.repository.Repository;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.AbstractHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JettyClientHttpWagonTest
    extends HttpWagonTestCase
{

    @Override
    protected String getProtocol()
    {
        return "http";
    }

    @Override
    protected void setHttpHeaders( StreamingWagon wagon, Properties properties )
    {
        ( (JettyClientMavenWagon) wagon ).setHttpHeaders( properties );
    }

    public void testGetRedirectFromHttpToHttps()
        throws Exception
    {

        logger.info( "Running test: " + getName() );

        SslRedirectHandler handler = new SslRedirectHandler();
        _handlers.add( handler );
        connectors.addAll( Arrays.asList( newHttpsConnector(), newHttpConnector() ) );

        setupRepositories();

        setupWagonTestingFixtures();

        handler.httpsPort = ( ( ServerConnector)server.getConnectors()[0]).getLocalPort();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            wagon.getToStream( "/base.txt", out );

            assertEquals( "PASSED", out.toString( "UTF-8" ) );
            assertEquals( 1, handler.redirects );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    private static class SslRedirectHandler
        extends AbstractHandler
    {

        int httpsPort;

        int redirects;

        @Override
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            if ( request.isHandled() )
            {
                return;
            }

            if ( request.getServerPort() != httpsPort )
            {
                String url = "https://" + request.getServerName() + ":" + httpsPort + request.getRequestURI();

                httpServletResponse.setStatus( HttpServletResponse.SC_MOVED_PERMANENTLY );
                httpServletResponse.setHeader( "Location", url );

                redirects++;
            }
            else
            {
                httpServletResponse.getWriter().write( "PASSED" );
            }

            request.setHandled( true );
        }
    }

//    public void testFailedGet()
//        throws Exception
//    {
//        super.testFailedGet();
//    }
//
//    public void testFailedGetIfNewer()
//        throws Exception
//    {
//        super.testFailedGetIfNewer();
//    }
//
//    public void testWagonGetIfNewerIsSame()
//        throws Exception
//    {
//        super.testWagonGetIfNewerIsSame();
//    }
//
//    public void testFailedGetIfNewerToStream()
//        throws Exception
//    {
//        super.testFailedGetIfNewerToStream();
//    }

//    public void testWagonResourceNotExists()
//        throws Exception
//    {
//        super.testWagonResourceNotExists();
//    }
}
