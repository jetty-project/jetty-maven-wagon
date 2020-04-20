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

import org.eclipse.jetty.client.HttpClientTransport;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.http.HttpClientTransportOverHTTP2;

public class JettyClientH2MavenWagon
    extends JettyClientMavenWagon
{
    private int sessionRecvWindow = 16 * 1024 * 1024;
    private int streamRecvWindow = 16 * 1024 * 1024;
    private int selectors = 1;
    private boolean useAlpn = true;

    @Override
    protected HttpClientTransport getHttpClientTransport()
    {
        HTTP2Client http2Client = new HTTP2Client();
        // Chrome uses 15 MiB session and 6 MiB stream windows.
        // Firefox uses 12 MiB session and stream windows.
        http2Client.setInitialSessionRecvWindow(getSessionRecvWindow());
        http2Client.setInitialStreamRecvWindow(getStreamRecvWindow());
        http2Client.setSelectors(getSelectors());
        HttpClientTransportOverHTTP2 httpClientTransportOverHTTP2 = new HttpClientTransportOverHTTP2(http2Client);
        httpClientTransportOverHTTP2.setUseALPN(useAlpn);
        return httpClientTransportOverHTTP2;
    }



    public int getSessionRecvWindow()
    {
        return sessionRecvWindow;
    }

    public void setSessionRecvWindow(int sessionRecvWindow)
    {
        this.sessionRecvWindow = sessionRecvWindow;
    }

    public int getStreamRecvWindow()
    {
        return streamRecvWindow;
    }

    public void setStreamRecvWindow(int streamRecvWindow)
    {
        this.streamRecvWindow = streamRecvWindow;
    }

    public int getSelectors()
    {
        return selectors;
    }

    public void setSelectors(int selectors )
    {
        this.selectors = selectors;
    }

    public boolean isUseAlpn()
    {
        return useAlpn;
    }

    public void setUseAlpn( boolean useAlpn )
    {
        this.useAlpn = useAlpn;
    }
}
