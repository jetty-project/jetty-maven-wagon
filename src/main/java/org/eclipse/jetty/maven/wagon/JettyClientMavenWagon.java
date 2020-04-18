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

import org.apache.maven.wagon.AbstractWagon;
import org.apache.maven.wagon.ConnectionException;
import org.apache.maven.wagon.OutputData;
import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.events.TransferEvent;
import org.apache.maven.wagon.proxy.ProxyInfo;
import org.apache.maven.wagon.resource.Resource;
import org.codehaus.plexus.util.StringUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpProxy;
import org.eclipse.jetty.client.ProxyConfiguration;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.InputStreamContentProvider;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.zip.GZIPInputStream;

/**
 * JettyClientMavenWagon
 */
public class JettyClientMavenWagon
    extends AbstractWagon
    implements StreamingWagon
{
    
    private static final Logger LOGGER = LoggerFactory.getLogger(JettyClientMavenWagon.class);
    
    /**
     * plexus.configuration default="false"
     */
    private boolean useCache;

    /**
     * plexus.configuration default=0 (means default HttpClient default 64)
     */
    protected int maxConnections = 256;

    /**
     * plexus.configuration default="true"
     */
    private boolean followRedirect = true;

    private static HttpClient HTTP_CLIENT = createHttpClient();

    private Map<String, String> _httpHeaders = new HashMap<>();

    public JettyClientMavenWagon()
    {
        //
    }

    private static HttpClient createHttpClient()
    {
        try
        {
            HttpClient httpClient = new HttpClient();
            httpClient.start();
            return httpClient;
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    protected HttpClient getHttpClient()
    {
        return HTTP_CLIENT;
    }

    @Override
    protected void closeConnection()
        throws ConnectionException
    {
        try
        {
            getHttpClient().stop();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }


    @Override
    protected void openConnectionInternal()
        throws ConnectionException, AuthenticationException
    {

        getHttpClient().setFollowRedirects(this.isFollowRedirect());
        if (this.maxConnections > 0)
        {
            getHttpClient().setMaxConnectionsPerDestination(this.maxConnections);
        }

        if (getHttpClient().isStopped())
        {
//            try
//            {
//                getHttpClient().start();
//            }
//            catch (Exception e)
//            {
//                throw new ConnectionException(e.getMessage(), e);
//            }
            HTTP_CLIENT = createHttpClient();
        }

        ProxyInfo proxyInfo = getProxyInfo("http", getRepository().getHost());
        if (proxyInfo != null && proxyInfo.getHost() != null)
        {
            String proxyType = proxyInfo.getType();
            if (!ProxyInfo.PROXY_HTTP.toLowerCase().equalsIgnoreCase(proxyType))
            {
                throw new ConnectionException("Connection failed: " + proxyType + " is not supported");
            }
            ProxyConfiguration proxyConfiguration = HTTP_CLIENT.getProxyConfiguration();
            proxyConfiguration.getProxies().add(new HttpProxy(proxyInfo.getHost(), proxyInfo.getPort()));
            // TODO proxy authz
            //if (proxyInfo.getUserName() != null)
        }
        // TODO authz for PUT
//        AuthenticationInfo authInfo = getAuthenticationInfo();
//        if (authInfo != null && authInfo.getUserName() != null)

//        closeConnection();
//
//        try
//        {
//            HTTP_CLIENT = new HttpClient();
//            
//
//            HTTP_CLIENT.setConnectorType(HttpClient.CONNECTOR_SELECT_CHANNEL);
//            HTTP_CLIENT.setTimeout(super.getTimeout());
//
//            if (maxConnections > 0)
//            {
//                HTTP_CLIENT.setMaxConnectionsPerAddress(maxConnections);
//            }
//
//            HTTP_CLIENT.setTrustStoreLocation(System.getProperty("javax.net.ssl.trustStore"));
//            HTTP_CLIENT.setTrustStorePassword(System.getProperty("javax.net.ssl.trustStorePassword"));
//            HTTP_CLIENT.setKeyStoreLocation(System.getProperty("javax.net.ssl.keyStore"));
//            HTTP_CLIENT.setKeyStorePassword(System.getProperty("javax.net.ssl.keyStorePassword"));
//            HTTP_CLIENT.setKeyManagerPassword(System.getProperty("javax.net.ssl.keyStorePassword"));
//
//
//            setupClient();
//
//            HTTP_CLIENT.start();
//        }
//        catch (Exception ex)
//        {
//            HTTP_CLIENT = null;
//            throw new ConnectionException(ex.getLocalizedMessage(), ex);
//        }
    }

    /**
     * Builds a complete URL string from the repository URL and the relative path passed.
     *
     * @param resourceName the relative path
     * @return the complete URL
     */
    private String buildUrl(String resourceName)
    {
        StringBuilder urlBuilder = new StringBuilder();

        String baseUrl = getRepository().getUrl();
        int index = baseUrl.indexOf('/');

        String protocol = baseUrl.substring(0, index);
        urlBuilder.append(protocol);

        urlBuilder.append(baseUrl.substring(index));
        if (baseUrl.endsWith("/"))
        {
            urlBuilder.deleteCharAt(urlBuilder.length() - 1); // avoid double slash
        }
        if (urlBuilder.charAt(urlBuilder.length() - 1) == ':')
        {
            urlBuilder.append('/');
        }

        // encode whitespace
        String resourceUri = resourceName.replace(' ', '+');

        String[] parts = StringUtils.split(resourceUri, "/");
        for(String part:parts)
        {
            // encode URI
            urlBuilder.append('/').append(URLEncoder.encode(part));
        }

        if (resourceName.endsWith("/"))
        {
            urlBuilder.append('/'); // directory URI
        }

        return urlBuilder.toString();
    }

    public void get(String resourceName, File destination)
        throws TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        getIfNewer(resourceName, destination, 0);
    }

    public boolean getIfNewer(String resourceName, File destination, long timestamp)
        throws TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        Resource resource = new Resource(resourceName);

        fireGetInitiated(resource, destination);

        return getIfNewer(resource, null, destination, timestamp);
    }

    public void getToStream(String resourceName, OutputStream stream)
        throws ResourceDoesNotExistException, TransferFailedException, AuthorizationException
    {
        getIfNewerToStream(resourceName, stream, 0);
    }

    public boolean getIfNewerToStream(String resourceName, OutputStream stream, long timestamp)
        throws ResourceDoesNotExistException, TransferFailedException, AuthorizationException
    {
        Resource resource = new Resource(resourceName);

        fireGetInitiated(resource, null);

        return getIfNewer(resource, stream, null, timestamp);
    }

    private boolean getIfNewer(Resource resource, OutputStream stream, File destination, long timestamp)
        throws ResourceDoesNotExistException, TransferFailedException, AuthorizationException
    {
        String resourceUrl = buildUrl(resource.getName());

        Request request = newRequest(resourceUrl).method(HttpMethod.GET);

        request.header("Accept-Encoding", "gzip");
        if (!useCache)
        {
            request.header("Pragma", "no-cache") //
                .header("Cache-Control", "no-cache, no-store");
        }

        try
        {
            ContentResponse contentResponse;

                contentResponse = request
                    .onResponseContent((response, buffer) ->
                                       {
                                           int size = buffer.limit() - buffer.position();
                                           LOGGER.info("GET#onResponseContent {}", size);
                                           // TODO see getResponseContentSource weird but done in another way...
//                                           buffer.flip();
//                                           TransferEvent transferEvent = new TransferEvent(this,
//                                                                                            resource,
//                                                                                            TransferEvent.TRANSFER_PROGRESS,
//                                                                                            TransferEvent.REQUEST_GET);
//                                           fireTransferProgress(transferEvent, buffer.array(), size);
                                       })
                    .onRequestFailure((request1, throwable) -> LOGGER.info("onRequestFailure: " + request.getURI() + ":"
                                                                               +throwable.getMessage(), throwable))
                    .onResponseFailure((response, throwable) -> LOGGER.info("onResponseFailure: " + request.getURI() + ":"
                                                                                +throwable.getMessage(), throwable))
                    .send();


            int responseStatus = contentResponse.getStatus();
            switch (responseStatus)
            {
                case HttpStatus.OK_200:
                case HttpStatus.NOT_MODIFIED_304:
                    break;

                case HttpStatus.FORBIDDEN_403:
                    fireSessionConnectionRefused();
                    throw new AuthorizationException("Transfer failed: [" + responseStatus + "] " + resourceUrl);

                case HttpStatus.UNAUTHORIZED_401:
                    fireSessionConnectionRefused();
                    throw new AuthorizationException("Transfer failed: Not authorized");

                case HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407:
                    fireSessionConnectionRefused();
                    throw new AuthorizationException("Transfer failed: Not authorized by proxy");

                case HttpStatus.NOT_FOUND_404:
                    throw new ResourceDoesNotExistException("Transfer failed: " + resourceUrl + " does not exist");

                default:
                {
                    cleanupGetTransfer(resource);
                    TransferFailedException ex =
                        new TransferFailedException("Transfer failed: [" + responseStatus + "] " + resourceUrl);
                    fireTransferError(resource, ex, TransferEvent.REQUEST_GET);
                    throw ex;
                }
            }

            boolean retValue = false;

            long lastModified = contentResponse.getHeaders().getDateField("Last-Modified");

            resource.setLastModified(lastModified);
            resource.setContentLength(contentResponse.getHeaders().getLongField("Content-Length"));

            if (timestamp == 0 || timestamp < resource.getLastModified())
            {
                retValue = true;

                InputStream input = getResponseContentSource(contentResponse);

                if (stream != null)
                {
                    fireGetStarted(resource, destination);
                    getTransfer(resource, stream, input);
                    fireGetCompleted(resource, destination);
                }
                else if (destination != null)
                {
                    getTransfer(resource, destination, input);
                }
                else
                {
                    // discard the response
                }
            }

            return retValue;
        }
        catch (InterruptedException | TimeoutException | ExecutionException e)
        {
            LOGGER.error( "error connecting to " + request.getURI(), e);

            fireTransferError(resource, e, TransferEvent.REQUEST_GET);

            throw new TransferFailedException("Transfer interrupted: " + e.getMessage(), e);
        }
        catch (FileNotFoundException e)
        {
            fireGetCompleted(resource, null);

            throw new ResourceDoesNotExistException("Transfer error: Resource not found in repository", e);
        }
        catch (IOException | IllegalStateException e)
        {
            fireTransferError(resource, e, TransferEvent.REQUEST_GET);

            throw new TransferFailedException("Transfer error: " + e.getMessage(), e);
        }
    }

    public void put(File source, String resourceName)
        throws TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        Resource resource = new Resource(resourceName);

        firePutInitiated(resource, source);

        resource.setContentLength(source.length());

        resource.setLastModified(source.lastModified());

        put(null, source, resource);
    }

    public void putFromStream(InputStream stream, String destination)
        throws TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        Resource resource = new Resource(destination);

        firePutInitiated(resource, null);

        put(stream, null, resource);
    }

    public void putFromStream(InputStream stream, String destination, long contentLength, long lastModified)
        throws TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        Resource resource = new Resource(destination);

        firePutInitiated(resource, null);

        resource.setContentLength(contentLength);

        resource.setLastModified(lastModified);

        put(stream, null, resource);
    }

    private void put(InputStream stream, File source, Resource resource)
        throws TransferFailedException, AuthorizationException, ResourceDoesNotExistException
    {
        String resourceUrl = buildUrl(resource.getName());
        Request request = newRequest(resourceUrl).method(HttpMethod.PUT);
        if (!useCache)
        {
            request.header("Pragma", "no-cache")
                .header("Cache-Control", "no-cache, no-store");
        }

        firePutStarted(resource, source);

        try
        {
            setRequestContentSource(request, stream, source);

            ContentResponse contentResponse = request
                .onComplete(result -> 
                            {
                                LOGGER.info("PUT#onComplete");
                                firePutCompleted(resource, source);
                            })
                .onRequestContent((request1, buffer) -> 
                            {
                                int size = buffer.limit() - buffer.position();
                                //LOGGER.info("PUT#onRequestContent {}", size);
                                buffer.flip();
                                TransferEvent transferEvent = new TransferEvent(this, 
                                                                                resource,
                                                                                TransferEvent.TRANSFER_PROGRESS, 
                                                                                 TransferEvent.REQUEST_PUT);
                                fireTransferProgress(transferEvent, buffer.array(), size);
                            })
                .onResponseFailure((response, throwable) -> 
                            {
                                LOGGER.info("PUT#onResponseFailure", throwable);
                                fireTransferError(resource, new Exception(throwable), TransferEvent.REQUEST_PUT);
                            })
                .send();

            int responseStatus = contentResponse.getStatus();

            switch (responseStatus)
            {
                // Success Codes
                case HttpStatus.OK_200: // 200
                case HttpStatus.CREATED_201: // 201
                case HttpStatus.ACCEPTED_202: // 202
                case HttpStatus.NO_CONTENT_204: // 204
                    break;

                case HttpStatus.FORBIDDEN_403:
                    fireSessionConnectionRefused();
                    throw new AuthorizationException("Transfer failed: [" + responseStatus + "] " + resourceUrl);

                case HttpStatus.UNAUTHORIZED_401:
                    fireSessionConnectionRefused();
                    throw new AuthorizationException("Transfer failed: Not authorized");

                case HttpStatus.PROXY_AUTHENTICATION_REQUIRED_407:
                    fireSessionConnectionRefused();
                    throw new AuthorizationException("Transfer failed: Not authorized by proxy");

                case HttpStatus.NOT_FOUND_404:
                    throw new ResourceDoesNotExistException("Transfer failed: " + resourceUrl + " does not exist");

                default:
                {
                    LOGGER.warn("Transfer failed: [{}] {}",responseStatus, resourceUrl);
                    TransferFailedException ex =
                        new TransferFailedException("Transfer failed: [" + responseStatus + "] " + resourceUrl);
                    fireTransferError(resource, ex, TransferEvent.REQUEST_PUT);
                    throw ex;
                }
            }
            fireTransferDebug(resourceUrl + " [" + responseStatus + "]");
        }
        catch (InterruptedException | TimeoutException | ExecutionException e)
        {
            fireTransferError(resource, e, TransferEvent.REQUEST_PUT);

            throw new TransferFailedException("Transfer interrupted: " + e.getMessage(), e);
        }
        catch (IOException | IllegalStateException e)
        {
            fireTransferError(resource, e, TransferEvent.REQUEST_PUT);

            throw new TransferFailedException("Transfer error: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean resourceExists(String resourceName)
        throws TransferFailedException, AuthorizationException
    {
        Resource resource = new Resource(resourceName);

        try
        {
            return getIfNewer(resource, null, null, 0);
        }
        catch (ResourceDoesNotExistException ex)
        {
            return false;
        }
    }

    @Override
    public List getFileList(String destinationDirectory)
        throws TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        throw new UnsupportedOperationException();
    }

    protected void setRequestContentSource(Request request, InputStream sourceStream, File srcFile)
        throws IOException
    {
        InputStream source = null;
        if (sourceStream != null)
        {
            source = sourceStream;
        }
        else if (srcFile != null)
        {
            source = new FileInputStream(srcFile);
        }

        if (source != null && !source.markSupported())
        {
            BufferedInputStream bstream = new BufferedInputStream(source);
            bstream.mark(srcFile == null ? Integer.MAX_VALUE : (int)srcFile.length());
            source = bstream;
        }

        request.content(new InputStreamContentProvider(source));
    }

    protected InputStream getResponseContentSource(ContentResponse contentResponse)
        throws IOException
    {
        byte[] source = contentResponse.getContent();

        if (source != null)
        {
            String contentEncoding = contentResponse.getHeaders().get("Content-Encoding");
            if ("gzip".equalsIgnoreCase(contentEncoding))
            {
                return new GZIPInputStream(new ByteArrayInputStream(source));
            }
            return new ByteArrayInputStream(source);
        }
        return null;
    }

    public void setHttpHeaders(Properties properties)
    {
        if (properties == null)
        {
            return;
        }
        properties.forEach((name, value) -> _httpHeaders.put((String)name, (String)value));

    }

    protected Request newRequest(String uri)
    {
        Request request = getHttpClient().newRequest(uri).followRedirects(this.followRedirect);
        _httpHeaders.forEach(request::header);
        return request;
    }
    
    protected void mkdirs(String dirname)
        throws IOException
    {
    }

    public void fillOutputData(OutputData arg0)
        throws TransferFailedException
    {
        throw new IllegalStateException("Should not be using the streaming wagon for HTTP PUT");
    }

    public boolean getUseCache()
    {
        return useCache;
    }

    public boolean isUseCache()
    {
        return useCache;
    }

    public void setUseCache( boolean useCache )
    {
        this.useCache = useCache;
    }

    public int getMaxConnections()
    {
        return maxConnections;
    }

    public void setMaxConnections( int maxConnections )
    {
        this.maxConnections = maxConnections;
    }

    public boolean isFollowRedirect()
    {
        return followRedirect;
    }

    public void setFollowRedirect( boolean followRedirect )
    {
        this.followRedirect = followRedirect;
    }
}
