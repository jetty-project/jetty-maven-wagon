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

import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;


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
        ServerConnector connector = new ServerConnector( server,
                                                         getSslContextFactory(needClientAuth),
                                                         new HTTP2ServerConnectionFactory(new HttpConfiguration()));
        return connector;
    }
}
