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

import org.apache.maven.wagon.Wagon;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;

public class JettyClientHttp2NoAlpnWagonTest
    extends JettyClientHttpsWagonTest
{

    @Override
    protected String getWagonRoleHint()
    {
        return "h2";
    }

    @Override
    protected void tearDown()
        throws Exception
    {
        super.tearDown();
        JettyClientH2MavenWagon.useAlpn = false;
    }

    @Override
    protected Wagon getWagon()
        throws Exception
    {
        JettyClientH2MavenWagon.useAlpn = false;
        JettyClientH2MavenWagon wagon = (JettyClientH2MavenWagon)super.getWagon();
        return wagon;
    }

    @Override
    protected Connector newHttpsConnector(boolean needClientAuth)
    {
        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.addCustomizer(new SecureRequestCustomizer());
        HTTP2ServerConnectionFactory h2 = new HTTP2ServerConnectionFactory(httpsConfig);
        ServerConnector http2Connector =
            new ServerConnector(server,getSslContextFactory(needClientAuth), h2);

        return http2Connector;
    }
}
