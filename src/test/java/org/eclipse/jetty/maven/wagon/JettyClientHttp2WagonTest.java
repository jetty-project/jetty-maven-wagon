//
//  ========================================================================
//  Copyright (c) 1995-2020 Mort Bay Consulting Pty. Ltd.
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

import org.apache.maven.wagon.Wagon;
import org.apache.maven.wagon.repository.Repository;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.codehaus.plexus.util.xml.Xpp3DomBuilder;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;

import java.io.File;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;

public class JettyClientHttp2WagonTest
    extends JettyClientHttpsWagonTest
{

    @Override
    protected String getWagonRoleHint()
    {
        return "h2";
    }

    @Override
    protected Connector newHttpsConnector(boolean needClientAuth)
    {

        // HTTPS Configuration
        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.addCustomizer(new SecureRequestCustomizer());

        // HTTP/2 Connection Factory
        HTTP2ServerConnectionFactory h2 = new HTTP2ServerConnectionFactory(httpsConfig);

        ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
        alpn.setDefaultProtocol(h2.getProtocol());
        // SSL Connection Factory
        SslConnectionFactory ssl = new SslConnectionFactory( getSslContextFactory(needClientAuth), alpn.getProtocol());

        // HTTP/2 Connector
        ServerConnector http2Connector =
            new ServerConnector(server,1, 1, ssl, alpn, h2, new HttpConnectionFactory(httpsConfig));

        return http2Connector;
    }

    public void testGetRedirectFromHttpToHttps()
    {
        // no sense here
    }

    public void testGetRealResource()
        throws Exception
    {
        Wagon wagon = getWagon();
        logger.info("Wagon: {}", wagon);
        Repository repository = new Repository("central","https://repo.maven.apache.org/maven2/");
        wagon.connect( repository );
        {
            Path tmp = Files.createTempFile( "test", "jetty-client" );
            wagon.get( "commons-discovery/commons-discovery/20040218.194635/commons-discovery-20040218.194635.pom", tmp.toFile() );
            assertTrue( tmp.toFile().exists() );
            logger.info( "commons-discovery-20040218.194635.pom file size: {}", tmp.toFile().length());
            logger.info( "commons-discovery-20040218.194635.pom content {}", Files.readAllLines( tmp ));
            try (Reader reader = Files.newBufferedReader( tmp ))
            {
                // ensure it's an xml file
                Xpp3Dom xpp3Dom = Xpp3DomBuilder.build(reader);
                xpp3Dom.getChildCount();
            }
            Files.deleteIfExists( tmp );
        }
        {
            Path tmp = Files.createTempFile( "test", "jetty-client" );
            wagon.get( "org/eclipse/jetty/jetty-client/9.4.28.v20200408/jetty-client-9.4.28.v20200408.jar", tmp.toFile() );
            assertTrue( tmp.toFile().exists() );
            logger.info( "jetty-client-9.4.28.v20200408.jar file size: {}", tmp.toFile().length() );
            Files.deleteIfExists( tmp );
        }
    }



}
