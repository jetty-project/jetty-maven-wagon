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

import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.ServerConnector;

public class JettyClientHttp2CWagonTest
    extends JettyClientHttpWagonTest
{

    @Override
    protected String getWagonRoleHint()
    {
        return "h2c";
    }

    @Override
    protected Connector newHttpConnector()
    {
        ServerConnector connector = new ServerConnector( server,
                                                         new HTTP2CServerConnectionFactory(new HttpConfiguration()));
        return connector;
    }

    public void testGetRedirectFromHttpToHttps()
    {
        // no sense here
    }
}
