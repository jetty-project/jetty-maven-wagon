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

import org.apache.maven.wagon.ConnectionException;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.proxy.ProxyInfo;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpClientTransport;
import org.eclipse.jetty.client.HttpProxy;
import org.eclipse.jetty.client.ProxyConfiguration;
import org.eclipse.jetty.client.util.BasicAuthentication;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.http.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

public class JettyClientH2MavenWagon
    extends JettyClientMavenWagon
{

    private static final Logger LOGGER = LoggerFactory.getLogger(JettyClientH2MavenWagon.class);

    private static HttpClient httpClient = createHttpClient();

    private static int sessionRecvWindow = Integer.getInteger("maven.wagon.http.h2.sessionRecvWindow",
                                                              16 * 1024 * 1024);
    private static int streamRecvWindow = Integer.getInteger("maven.wagon.http.h2.streamRecvWindow",
                                                             16 * 1024 * 1024);
    private static int selectors = Integer.getInteger("maven.wagon.http.h2.jetty.selectors", 1);
    protected static boolean useAlpn = Boolean.parseBoolean(System.getProperty("maven.wagon.http.ssl.useAlpn", "true"));

    protected static HttpClientTransport getHttpClientTransport()
    {
        HTTP2Client http2Client = new HTTP2Client();
        // Chrome uses 15 MiB session and 6 MiB stream windows.
        // Firefox uses 12 MiB session and stream windows.
        http2Client.setInitialSessionRecvWindow(sessionRecvWindow);
        http2Client.setInitialStreamRecvWindow(streamRecvWindow);
        http2Client.setSelectors(selectors);
        HttpClientTransportOverHTTP2 httpClientTransportOverHTTP2 = new HttpClientTransportOverHTTP2(http2Client);
        httpClientTransportOverHTTP2.setUseALPN(useAlpn);
        LOGGER.debug("sessionRecvWindow: {}, streamRecvWindow: {}, selectors: {}, useAlpn: {}",
                     sessionRecvWindow, streamRecvWindow, selectors, useAlpn);
        return httpClientTransportOverHTTP2;
    }

    private static HttpClient createHttpClient()
    {
        LOGGER.info("create H2 HttpClient");
        try
        {
            SslContextFactory sslContextFactory = new SslContextFactory.Client(SSL_INSECURE);
            HttpClient httpClient = new HttpClient(getHttpClientTransport(), sslContextFactory);
            httpClient.start();
            return httpClient;
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    protected Logger getLogger()
    {
        return LOGGER;
    }

    protected HttpClient getHttpClient()
    {
        return httpClient;
    }

    protected void restartClient()
    {
        httpClient = createHttpClient();
    }

}
