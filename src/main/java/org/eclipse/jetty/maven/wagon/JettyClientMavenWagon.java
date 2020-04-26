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

import org.apache.maven.wagon.AbstractWagon;
import org.apache.maven.wagon.ConnectionException;
import org.apache.maven.wagon.OutputData;
import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.events.TransferEvent;
import org.apache.maven.wagon.proxy.ProxyInfo;
import org.apache.maven.wagon.resource.Resource;
import org.codehaus.plexus.util.StringUtils;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpClientTransport;
import org.eclipse.jetty.client.HttpProxy;
import org.eclipse.jetty.client.ProxyConfiguration;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.api.Response;
import org.eclipse.jetty.client.api.Result;
import org.eclipse.jetty.client.http.HttpClientTransportOverHTTP;
import org.eclipse.jetty.client.util.BasicAuthentication;
import org.eclipse.jetty.client.util.FutureResponseListener;
import org.eclipse.jetty.client.util.InputStreamContentProvider;
import org.eclipse.jetty.http.HttpField;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.util.BufferUtil;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
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

    protected static boolean SSL_INSECURE = Boolean.getBoolean("maven.wagon.http.ssl.insecure");

    private final Map<String, String> _httpHeaders = new HashMap<>();

    private static HttpClient createHttpClient()
    {
        LOGGER.info("createHttpClient");
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

    protected void restartClient()
    {
        HTTP_CLIENT = createHttpClient();
    }

    protected static HttpClientTransport getHttpClientTransport()
    {
        return new HttpClientTransportOverHTTP();
    }

    protected HttpClient getHttpClient()
    {
        return HTTP_CLIENT;
    }

    @Override
    protected void closeConnection()
        throws ConnectionException
    {
        LOGGER.debug("closeConnection");
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
        LOGGER.debug("openConnection");
        getHttpClient().setFollowRedirects(this.isFollowRedirect());
        if (this.maxConnections > 0)
        {
            getHttpClient().setMaxConnectionsPerDestination(this.maxConnections);
        }
        if (getHttpClient() == null || getHttpClient().isStopped())
        {
            restartClient();
        }

        ProxyInfo proxyInfo = getProxyInfo("http", getRepository().getHost());
        if (proxyInfo != null && proxyInfo.getHost() != null)
        {
            String proxyType = proxyInfo.getType();
            if (!ProxyInfo.PROXY_HTTP.toLowerCase().equalsIgnoreCase(proxyType))
            {
                throw new ConnectionException("Connection failed: " + proxyType + " is not supported");
            }
            ProxyConfiguration proxyConfiguration = getHttpClient().getProxyConfiguration();
            proxyConfiguration.getProxies().add(new HttpProxy(proxyInfo.getHost(), proxyInfo.getPort()));
            // TODO proxy authz
            //if (proxyInfo.getUserName() != null)
        }

        AuthenticationInfo authInfo = getAuthenticationInfo();
        if (authInfo != null && authInfo.getUserName() != null)
        {
            URI uri = URI.create(getRepository().getUrl());
            BasicAuthentication basicAuthentication = new BasicAuthentication(uri,
                                                                              "realm-" + repository.getId(),
                                                                              authInfo.getUserName(),
                                                                              authInfo.getPassword());
            getHttpClient().getAuthenticationStore().addAuthentication(basicAuthentication);
            // preemptive
            BasicAuthentication.BasicResult basicResult = new BasicAuthentication.BasicResult(uri,
                                                                                              authInfo.getUserName(),
                                                                                              authInfo.getPassword());
            getHttpClient().getAuthenticationStore().addAuthenticationResult(basicResult);
        }
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
        switch (protocol)
        {
            case "h2:":
                protocol = "https:";
                break;
            case "h2c:":
                protocol = "http:";
                break;
            default:
                // do nothing
        }
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
        for (String part:parts)
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
        request.header(HttpHeader.ACCEPT_ENCODING, "gzip");

        AtomicBoolean retValue = new AtomicBoolean(Boolean.FALSE);
        AtomicInteger responseStatus = new AtomicInteger(HttpStatus.OK_200);
        // this method can be called only to check if the resource exists so we do not download it and output are null
        try (OutputStream destinationStream = stream != null ? stream
            : destination != null ? Files.newOutputStream(destination.toPath()) : null)
        {
            FutureResponseListener listener = new FutureResponseListener(request)
            {
                @Override
                public void onFailure(Response response, Throwable failure)
                {
                    LOGGER.debug("onResponseFailure: " +
                                     request.getURI() +
                                     ":" +
                                     failure.getMessage(), failure);
                }

                @Override
                public void onHeaders(Response response)
                {
                    resource.setLastModified(response.getHeaders().getDateField("Last-Modified"));
                    if (timestamp == 0 || timestamp < resource.getLastModified())
                    {
                        retValue.set(true);
                    }
                    resource.setContentLength(response.getHeaders().getLongField("Content-Length"));
                    if (destinationStream != null && resource.getContentLength() > 0 && retValue.get())
                    {
                        fireGetStarted(resource, destination);
                    }
                }

                @Override
                public void onContent(Response response, ByteBuffer buffer)
                {
                    byte[] bytes = BufferUtil.toArray(buffer);
                    try
                    {
                        if (destinationStream != null && retValue.get())
                        {
                            destinationStream.write(bytes);
                            TransferEvent transferEvent = new TransferEvent(JettyClientMavenWagon.this,
                                                                            resource,
                                                                            TransferEvent.TRANSFER_PROGRESS,
                                                                            TransferEvent.REQUEST_GET);
                            fireTransferProgress(transferEvent, bytes, bytes.length);
                        }
                    }
                    catch (Exception e)
                    {
                        throw new RuntimeException(e.getMessage(),e);
                    }
                }

                @Override
                public void onComplete(Result result)
                {
                    super.onComplete(result);
                    LOGGER.debug("onComplete, isDone? {}", isDone());
                }

                @Override
                public void onSuccess(Response response)
                {
                    if (destinationStream != null && retValue.get())
                    {
                        fireGetCompleted(resource, destination);
                    }
                    responseStatus.set(response.getStatus());
                }
            };
            request.send(listener);
            listener.get(getReadTimeout(), TimeUnit.MILLISECONDS);

            switch (responseStatus.get())
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

            // the file may have been written whereas we do not need it timestamp check etc...
            // so delete it
            if (!retValue.get() && destination != null && Files.exists(destination.toPath()))
            {
                Files.deleteIfExists(destination.toPath());
            }
            return retValue.get();
        }
        catch (InterruptedException | TimeoutException | ExecutionException e)
        {
            LOGGER.error("error connecting to " + request.getURI(), e);
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

        firePutStarted(resource, source);
        try
        {
            setRequestContentSource(request, stream, source);

            ContentResponse contentResponse = request
                .onComplete(result -> 
                {
                    LOGGER.debug("PUT#onComplete");
                    firePutCompleted(resource, source);
                })
                .onRequestContent((request1, buffer) -> 
                {
                    int size = buffer.limit() - buffer.position();
                    buffer.flip();
                    TransferEvent transferEvent = new TransferEvent(this, 
                                                                    resource,
                                                                    TransferEvent.TRANSFER_PROGRESS, 
                                                                     TransferEvent.REQUEST_PUT);
                    fireTransferProgress(transferEvent, buffer.array(), size);
                })
                .onResponseFailure((response, throwable) -> 
                {
                    LOGGER.debug("PUT#onResponseFailure", throwable);
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
                    LOGGER.warn("Transfer failed: [{}] {}", responseStatus, resourceUrl);
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
        request.content(new InputStreamContentProvider(source));
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

        // User-Agent need special treatement
        // until this one fixed https://github.com/eclipse/jetty.project/issues/4808
        _httpHeaders.entrySet().stream()
            .filter(entry -> !StringUtils.equalsIgnoreCase(entry.getKey(), HttpHeader.USER_AGENT.asString()))
            .forEach(entry -> request.header(entry.getKey(), entry.getValue()));

        _httpHeaders.entrySet().stream()
            .filter(entry -> StringUtils.equalsIgnoreCase(entry.getKey(), HttpHeader.USER_AGENT.asString()))
            .map(Map.Entry::getValue)
            .findFirst()
            .ifPresent(s ->
            {
                request.header(HttpHeader.USER_AGENT, null);
                request.agent(s);
            });
        ProxyInfo proxyInfo = getProxyInfo(getRepository().getProtocol(),getRepository().getHost());
        if (proxyInfo != null && proxyInfo.getUserName() != null)
        {
            byte[] authBytes = (proxyInfo.getUserName() + ":" + 
                proxyInfo.getPassword()).getBytes(StandardCharsets.ISO_8859_1);
            String value = "Basic " + Base64.getEncoder().encodeToString(authBytes);
            request.header(HttpHeader.PROXY_AUTHORIZATION, value);
        }

        if (!useCache)
        {
            request.header(HttpHeader.PRAGMA, "no-cache") //
                .header(HttpHeader.CACHE_CONTROL, "no-cache, no-store");
        }
        return request.idleTimeout(getTimeout(), TimeUnit.MILLISECONDS)
                        .timeout(getReadTimeout(), TimeUnit.MILLISECONDS);
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

    public void setUseCache(boolean useCache)
    {
        this.useCache = useCache;
    }

    public int getMaxConnections()
    {
        return maxConnections;
    }

    public void setMaxConnections(int maxConnections)
    {
        this.maxConnections = maxConnections;
    }

    public boolean isFollowRedirect()
    {
        return followRedirect;
    }

    public void setFollowRedirect(boolean followRedirect)
    {
        this.followRedirect = followRedirect;
    }

    public boolean isSslInsecure()
    {
        return SSL_INSECURE;
    }

    public void setSslInsecure(boolean sslInsecure)
    {
        this.SSL_INSECURE = sslInsecure;
    }
}
