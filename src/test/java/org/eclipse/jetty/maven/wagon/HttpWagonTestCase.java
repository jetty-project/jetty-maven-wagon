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

import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.StreamingWagonTestCase;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.observers.ChecksumObserver;
import org.apache.maven.wagon.proxy.ProxyInfo;
import org.apache.maven.wagon.repository.Repository;
import org.apache.maven.wagon.resource.Resource;
import org.codehaus.plexus.util.FileUtils;
import org.codehaus.plexus.util.IOUtil;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConnection;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Password;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.stream.StreamSupport;
import java.util.zip.GZIPOutputStream;

public abstract class HttpWagonTestCase
    extends StreamingWagonTestCase
{

    Logger logger = LoggerFactory.getLogger( getClass() );

    protected Server server;

    protected List<Connector> connectors = new ArrayList<>();

    protected List<Handler> _handlers = new ArrayList<>();

    protected List<ContextHandler> _contextHandlers = new ArrayList<>();

    @Override
    protected void setupWagonTestingFixtures()
        throws Exception
    {
        // stop first if running
        tearDownWagonTestingFixtures();

        File repositoryDirectory = getRepositoryDirectory();
        FileUtils.deleteDirectory( repositoryDirectory );
        repositoryDirectory.mkdirs();

        server = new Server();

//        server.setDumpAfterStart( true );
//        server.setDumpBeforeStop( true );

        addConnectors( server );
        List<Handler> handlers = setupHandlers( server );
        addContexts( server, handlers );

        server.start();
    }

    protected void stopTestServer()
        throws Exception
    {
        if ( server != null )
        {
            logger.info( "stopping server port {}", getLocalPort() );
            server.stop();
            server = null;
        }
    }

    @Override
    protected void tearDown()
        throws Exception
    {
        stopTestServer();
        super.tearDown();
    }

    @Override
    protected void tearDownWagonTestingFixtures()
        throws Exception
    {
        super.tearDownWagonTestingFixtures();
        stopTestServer();
    }

    protected void addConnectors( Server server )
    {
        if ( connectors != null && !connectors.isEmpty() )
        {
            server.setConnectors( connectors.toArray( new Connector[connectors.size()] ) );
            connectors = null;
        }
        else if ( getProtocol().equalsIgnoreCase( "http" ) )
        {
            server.addConnector( newHttpConnector() );
        }
        else
        {
            server.addConnector( newHttpsConnector() );
        }
    }

    protected Connector newHttpConnector()
    {
        ServerConnector connector = new ServerConnector( server, new HttpConnectionFactory() );
        return connector;
    }

    protected Connector newHttpsConnector()
    {
        return newHttpsConnector( false );
    }

    protected Connector newHttpsConnector( boolean needClientAuth )
    {
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();

        sslContextFactory.setKeyStorePath( getTestFile( "src/test/resources/ssl/keystore" ).getAbsolutePath() );
        sslContextFactory.setKeyStorePassword( "storepwd" );
        //sslContextFactory.setKeyPassword( "keypwd" );

        sslContextFactory.setTrustStorePath( getTestFile( "src/test/resources/ssl/client-store" ).getAbsolutePath() );
        sslContextFactory.setTrustStorePassword( "client-pwd" );
        sslContextFactory.setNeedClientAuth( needClientAuth );

        ServerConnector connector = new ServerConnector( server, sslContextFactory );
        return connector;
    }

    protected List<Handler> setupHandlers( final Server server )
    {
        List<Handler> handlers = new ArrayList<>();
        handlers.add( new PutHandler( getRepositoryPath() ) );
        handlers.addAll( _handlers );
        return handlers;
    }

    protected void addContexts( Server server, List<Handler> handlers )
        throws IOException
    {
        if ( _contextHandlers == null || _contextHandlers.isEmpty() )
        {

            ServletContextHandler root = new ServletContextHandler( null, "/", ServletContextHandler.SESSIONS );
            root.setResourceBase( getRepositoryPath() );
            ServletHolder servletHolder = new ServletHolder( new DefaultServlet() );
            servletHolder.setInitParameter( "gzip", "true" );
            root.addServlet( servletHolder, "/*" );
            List<Handler> handlerList = new ArrayList<>();
            handlerList.addAll(handlers);
            handlerList.add(root);
            HandlerList contexts = new HandlerList(new HandlerList(handlerList.toArray(new Handler[handlerList.size()])));

            server.setHandler( contexts );

        }
        else
        {
            handlers.addAll( _contextHandlers );
            server.setHandler( new HandlerList(handlers.toArray(new Handler[handlers.size()])) );
        }


    }

    @Override
    protected void setupRepositories()
        throws Exception
    {
        resource = "test-resource";

        testRepository = new Repository( "test", getTestRepositoryUrl() );
        testRepository.setPermissions( getPermissions() );

        localRepositoryPath = getRepositoryPath();
        localRepository = createFileRepository( "file://" + localRepositoryPath );
        message( "Local repository: " + localRepository );
    }

    protected File getRepositoryDirectory()
    {
        return getTestFile( "target/test-output/http-repository" );
    }

    protected String getRepositoryPath()
    {
        return getRepositoryDirectory().getAbsolutePath();
    }

    protected String getOutputPath()
    {
        return getTestFile( "target/test-output" ).getAbsolutePath();
    }

    @Override
    protected String getTestRepositoryUrl()
    {
        return getProtocol() + "://localhost:" + getLocalPort();
    }

    protected int getLocalPort()
    {
        Connector[] cons = server.getConnectors();
        return ( (ServerConnector) cons[cons.length - 1] ).getLocalPort();
    }

    @Override
    public void testWagonGetFileList()
        throws Exception
    {
        // not supported
    }

    @Override
    public void testWagonGetFileListWhenDirectoryDoesNotExist()
        throws Exception
    {
        // not supported
    }

    public void testHttpHeaders()
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        Properties properties = new Properties();
        properties.setProperty( "User-Agent", "Maven-Wagon/1.0" );

        JettyClientMavenWagon wagon = (JettyClientMavenWagon) getWagon();
        setHttpHeaders( wagon, properties );

        TestHeaderHandler handler = new TestHeaderHandler();
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        wagon.getToStream( "resource", new ByteArrayOutputStream() );

        wagon.disconnect();

        tearDownWagonTestingFixtures();

        stopTestServer();

        assertEquals( "Maven-Wagon/1.0", handler.headers.get( "User-Agent" ) );
    }

    protected abstract void setHttpHeaders( StreamingWagon wagon, Properties properties );

    public void testGetForbidden()
        throws Exception
    {
        try
        {
            runTestGet( HttpServletResponse.SC_FORBIDDEN );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testGet404()
        throws Exception
    {
        try
        {
            runTestGet( HttpServletResponse.SC_NOT_FOUND );
            fail();
        }
        catch ( ResourceDoesNotExistException e )
        {
            assertTrue( true );
        }
    }

    public void testGet500()
        throws Exception
    {
        try
        {
            runTestGet( HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
            fail();
        }
        catch ( TransferFailedException e )
        {

        }
    }

    private void runTestGet( final int status )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        StatusHandler handler = new StatusHandler();
        handler.setStatusToReturn( status );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            wagon.getToStream( "resource", new ByteArrayOutputStream() );
            fail();
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testResourceExistsForbidden()
        throws Exception
    {
        try
        {
            runTestResourceExists( HttpServletResponse.SC_FORBIDDEN );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testResourceExists404()
        throws Exception
    {
        try
        {
            assertFalse( runTestResourceExists( HttpServletResponse.SC_NOT_FOUND ) );
        }
        catch ( ResourceDoesNotExistException e )
        {
            assertTrue( true );
        }
    }

    public void testResourceExists500()
        throws Exception
    {
        try
        {
            runTestResourceExists( HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
            fail();
        }
        catch ( TransferFailedException e )
        {
            assertTrue( true );
        }
    }

    private boolean runTestResourceExists( final int status )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        StatusHandler handler = new StatusHandler();
        handler.setStatusToReturn( status );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            return wagon.resourceExists( "resource" );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    @Override
    protected long getExpectedLastModifiedOnGet( final Repository repository, final Resource resource )
    {
        File file = new File( getRepositoryPath(), resource.getName() );
        return ( file.lastModified() / 1000 ) * 1000;
    }


    public void testGetFileThatIsBiggerThanMaxHeap()
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        long bytes = (long) ( Runtime.getRuntime().maxMemory() * 1.1 );

        _handlers = Arrays.asList( new HugeDataHandler( bytes ) );

        setupWagonTestingFixtures();

        setupRepositories();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        File hugeFile = File.createTempFile( "wagon-test-" + getName(), ".tmp" );
        hugeFile.deleteOnExit();

        try
        {
            wagon.get( "huge.txt", hugeFile );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }

        assertTrue( hugeFile.isFile() );
        assertEquals( bytes, hugeFile.length() );
    }

    public void testProxiedRequest()
        throws Exception
    {
        if ( getProtocol().equals( "http" ) )
        {
            ProxyInfo proxyInfo = createProxyInfo();
            TestHeaderHandler handler = new TestHeaderHandler();

            runTestProxiedRequest( proxyInfo, handler );
        }
    }

    public void testProxiedRequestWithAuthentication()
        throws Exception
    {
        if ( getProtocol().equals( "http" ) )
        {
            ProxyInfo proxyInfo = createProxyInfo();
            proxyInfo.setUserName( "user" );
            proxyInfo.setPassword( "secret" );
            TestHeaderHandler handler = new AuthorizingProxyHandler();

            runTestProxiedRequest( proxyInfo, handler );

            assertEquals( "Basic dXNlcjpzZWNyZXQ=", handler.headers.get( "Proxy-Authorization" ) );
        }
    }

    private void runTestProxiedRequest( final ProxyInfo proxyInfo, final TestHeaderHandler handler )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        proxyInfo.setPort( getLocalPort() );

        File srcFile = new File( getRepositoryPath() + "/proxy" );
        srcFile.mkdirs();
        srcFile.deleteOnExit();

        String resName = "proxy-res.txt";
        FileUtils.fileWrite( srcFile.getAbsolutePath() + "/" + resName, "test proxy" );

        File destFile = new File( getOutputPath(), getName() + ".txt" );
        destFile.deleteOnExit();

        Properties properties = new Properties();
        properties.setProperty( "Proxy-Connection", "close" );

        StreamingWagon wagon = (StreamingWagon) getWagon();
        setHttpHeaders( wagon, properties );

        wagon.connect( new Repository( "id", "http://www.example.com/" ), proxyInfo );

        try
        {
            wagon.get( "proxy/" + resName, destFile );

            assertTrue( handler.headers.containsKey( "Proxy-Connection" ) );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    private ProxyInfo createProxyInfo()
    {
        ProxyInfo proxyInfo = new ProxyInfo();
        proxyInfo.setHost( "localhost" );
        proxyInfo.setNonProxyHosts( null );
        proxyInfo.setType( "http" );
        return proxyInfo;
    }

    public void testSecuredGetUnauthorized()
        throws Exception
    {
        try
        {
            runTestSecuredGet( null );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredGetWrongPassword()
        throws Exception
    {
        try
        {
            AuthenticationInfo authInfo = new AuthenticationInfo();
            authInfo.setUserName( "user" );
            authInfo.setPassword( "admin" );
            runTestSecuredGet( authInfo );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredGet()
        throws Exception
    {
        AuthenticationInfo authInfo = new AuthenticationInfo();
        authInfo.setUserName( "user" );
        authInfo.setPassword( "secret" );
        runTestSecuredGet( authInfo );
    }

    public void runTestSecuredGet( final AuthenticationInfo authInfo )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        _handlers = Arrays.asList( createSecuredContext() );

        setupWagonTestingFixtures();

        setupRepositories();

        File srcFile = new File( getRepositoryPath() + "/secured" );
        srcFile.mkdirs();
        srcFile.deleteOnExit();

        String resName = "secured-res.txt";
        FileUtils.fileWrite( srcFile.getAbsolutePath() + "/" + resName, "top secret" );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), authInfo );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            wagon.getToStream( "secured/" + resName, out );

            assertEquals( "top secret", out.toString() );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public ServletContextHandler createSecuredContext()
    {
        ServletContextHandler root = new ServletContextHandler( ServletContextHandler.SESSIONS );
        root.setContextPath( "/" );
        root.setHandler( new AuthorizingSecurityHandler() );
        root.setResourceBase( getRepositoryPath() );
        ServletHolder servletHolder = new ServletHolder( new DefaultServlet() );
        root.addServlet( servletHolder, "/*" );

        return root;
    }

    public void testSecuredResourceExistsUnauthorized()
        throws Exception
    {
        try
        {
            runTestSecuredResourceExists( null );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredResourceExistsWrongPassword()
        throws Exception
    {
        try
        {
            AuthenticationInfo authInfo = new AuthenticationInfo();
            authInfo.setUserName( "user" );
            authInfo.setPassword( "admin" );
            runTestSecuredResourceExists( authInfo );
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredResourceExists()
        throws Exception
    {
        AuthenticationInfo authInfo = new AuthenticationInfo();
        authInfo.setUserName( "user" );
        authInfo.setPassword( "secret" );
        runTestSecuredResourceExists( authInfo );
    }

    public void runTestSecuredResourceExists( final AuthenticationInfo authInfo )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        ServletContextHandler context = createSecuredContext();
        _handlers = Arrays.asList( context );

        setupWagonTestingFixtures();

        setupRepositories();

        File srcFile = new File( getRepositoryPath() + "/secured" );
        srcFile.mkdirs();
        srcFile.deleteOnExit();

        String resName = "secured-res.txt";
        FileUtils.fileWrite( srcFile.getAbsolutePath() + "/" + resName, "top secret" );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), authInfo );

        try
        {
            assertTrue( wagon.resourceExists( "secured/" + resName ) );

            assertFalse( wagon.resourceExists( "secured/missing-" + resName ) );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testPutForbidden()
        throws Exception
    {
        try
        {
            runTestPutFailure( HttpServletResponse.SC_FORBIDDEN );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testPut404()
        throws Exception
    {
        try
        {
            runTestPutFailure( HttpServletResponse.SC_NOT_FOUND );
            fail();
        }
        catch ( ResourceDoesNotExistException e )
        {
            assertTrue( true );
        }
    }

    public void testPut500()
        throws Exception
    {
        try
        {
            runTestPutFailure( HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
            fail();
        }
        catch ( TransferFailedException e )
        {
            assertTrue( true );
        }
    }

    private void runTestPutFailure( final int status )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        StatusHandler handler = new StatusHandler();
        handler.setStatusToReturn( status );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        String resName = "put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "test put" );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            wagon.put( srcFile, resName );
            fail();
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();

            srcFile.delete();
        }
    }

    public void testSecuredPutUnauthorized()
        throws Exception
    {
        try
        {
            runTestSecuredPut( null );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredPutWrongPassword()
        throws Exception
    {
        try
        {
            AuthenticationInfo authInfo = new AuthenticationInfo();
            authInfo.setUserName( "user" );
            authInfo.setPassword( "admin" );
            runTestSecuredPut( authInfo );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredPut()
        throws Exception
    {
        AuthenticationInfo authInfo = new AuthenticationInfo();
        authInfo.setUserName( "user" );
        authInfo.setPassword( "secret" );
        runTestSecuredPut( authInfo );
    }

    public void runTestSecuredPut( final AuthenticationInfo authInfo )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        AuthorizingSecurityHandler shandler = new AuthorizingSecurityHandler();
        PutHandler handler = new PutHandler( getRepositoryPath() );
        shandler.setHandler( handler ); // must nest the put handler behind the authorization handler
        _handlers = Arrays.asList( shandler );

        setupWagonTestingFixtures();

        setupRepositories();

        String resName = "secured-put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "UTF-8", "put top secret" );

        File dstFile = new File( getRepositoryPath() + "/secured", resName );
        dstFile.mkdirs();
        dstFile.delete();
        assertFalse( dstFile.exists() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        ChecksumObserver checksumObserver = new ChecksumObserver( "SHA-1" );
        wagon.addTransferListener( checksumObserver );

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), authInfo );

        try
        {
            wagon.put( srcFile, "secured/" + resName );

            assertEquals( "put top secret", FileUtils.fileRead( dstFile.getAbsolutePath(), "UTF-8" ) );

            assertEquals( "8b4f978eeec389ebed2c8b0acd8e107efff29be5", checksumObserver.getActualChecksum() );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();

            // srcFile.delete();
        }
    }

    public void testPut()
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        PutHandler handler = new PutHandler( getRepositoryPath() );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        String resName = "put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "test put" );

        File dstFile = new File( getRepositoryPath() + "/put", resName );
        dstFile.mkdirs();
        dstFile.delete();
        assertFalse( dstFile.exists() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            wagon.put( srcFile, "put/" + resName );

            assertEquals( "test put", FileUtils.fileRead( dstFile.getAbsolutePath() ) );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();

            srcFile.delete();
        }
    }

    public void testPutFileThatIsBiggerThanMaxHeap()
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        long bytes = (long) ( Runtime.getRuntime().maxMemory() * 1.1 );

        _handlers = Arrays.asList( new PutHandler( getRepositoryPath() ) );

        setupWagonTestingFixtures();

        setupRepositories();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        File hugeFile = File.createTempFile( "wagon-test-" + getName(), ".tmp" );
        hugeFile.deleteOnExit();
        FileOutputStream fos = new FileOutputStream( hugeFile );
        IOUtil.copy( new HugeInputStream( bytes ), fos );
        fos.close();
        assertEquals( bytes, hugeFile.length() );

        try
        {
            wagon.put( hugeFile, "huge.txt" );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }

        File remoteFile = new File( getRepositoryPath(), "huge.txt" );
        assertTrue( remoteFile.isFile() );
        assertEquals( hugeFile.length(), remoteFile.length() );
    }

    public void testGetUnknownIP()
        throws Exception
    {
        runTestGetUnknown( "http://244.0.0.0/" );
    }

    public void testGetUnknownHost()
        throws Exception
    {
        runTestGetUnknown( "http://null.apache.org/" );
    }

    private void runTestGetUnknown( String url )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        StreamingWagon wagon = (StreamingWagon) getWagon();
        wagon.setTimeout( 5000 );
        try

        {
            wagon.connect( new Repository( "id", url ) );

            wagon.getToStream( "resource", new ByteArrayOutputStream() );

            fail();
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );
        }
    }

    public void testPutUnknownIP()
        throws Exception
    {
        runTestPutUnknown( "http://244.0.0.0/" );
    }

    public void testPutUnknownHost()
        throws Exception
    {
        runTestPutUnknown( "http://null.apache.org/" );
    }

    private void runTestPutUnknown( String url )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        String resName = "put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "test put" );

        StreamingWagon wagon = (StreamingWagon) getWagon();
        wagon.setTimeout( 5000 );

        try
        {
            wagon.connect( new Repository( "id", url ) );

            wagon.put( srcFile, resName );

            fail();
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );

            srcFile.delete();
        }
    }

    public void testHighLatencyGet()
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        Handler handler = new LatencyHandler( 300, 10 );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.setTimeout( 10000 );

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try
        {
            wagon.getToStream( "large.txt", byteArrayOutputStream );
            assertEquals(10240, byteArrayOutputStream.toString().length() );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testInfiniteLatencyGet()
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        Handler handler = new LatencyHandler( -1, 100 );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.setTimeout( 2000 );

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            wagon.getToStream( "large.txt", out );

            fail( "Should have failed to transfer due to transaction timeout." );
        }
        catch ( TransferFailedException e )
        {
            assertTrue( true );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testGetRedirectOncePermanent()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", 1, false );
    }

    public void testGetRedirectOnceTemporary()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_TEMPORARILY, "/moved.txt", "/base.txt", 1, false );
    }

    public void testGetRedirectSixPermanent()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", 6, false );
    }

    public void testGetRedirectSixTemporary()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_TEMPORARILY, "/moved.txt", "/base.txt", 6, false );
    }

    public void testGetRedirectRelativeLocation()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", 1, true );
    }

    private void runTestRedirectSuccess( int code, String currUrl, String origUrl, int maxRedirects,
                                         boolean relativeLocation )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        Handler handler = new RedirectHandler( code, currUrl, origUrl, maxRedirects, relativeLocation );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            wagon.getToStream( currUrl, out );

            assertEquals( out.toString().length(), 1024 );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testGetRedirectLimitPermanent()
        throws Exception
    {
        runTestRedirectFail( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", -1 );
    }

    public void testGetRedirectLimitTemporary()
        throws Exception
    {
        runTestRedirectFail( HttpServletResponse.SC_MOVED_TEMPORARILY, "/moved.txt", "/base.txt", -1 );
    }

    private void runTestRedirectFail( int code, String currUrl, String origUrl, int maxRedirects )
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        Handler handler = new RedirectHandler( code, currUrl, origUrl, maxRedirects, false );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            wagon.getToStream( currUrl, out );
            fail();
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testGracefulFailureUnderMultithreadedMisuse()
        throws Exception
    {
        logger.info( "Running test: " + getName() );

        Handler handler = new LatencyHandler( 500, 2 );
        _handlers = Arrays.asList( handler );

        setupWagonTestingFixtures();

        setupRepositories();

        final StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        new Thread( new Runnable()
        {

            public void run()
            {
                try
                {
                    Thread.sleep( 1000 );
                    // closing the wagon from another thread must not hang the main thread
                    wagon.disconnect();
                }
                catch ( Exception e )
                {
                    e.printStackTrace();
                }
            }

        }, "wagon-killer" ).start();

        try
        {
            wagon.getToStream( "large.txt", new ByteArrayOutputStream() );
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    static class StatusHandler
        extends AbstractHandler
    {
        private int status;

        public StatusHandler()
        {
            this( 0 );
        }

        public StatusHandler( int status )
        {
            this.status = status;
        }

        public void setStatusToReturn( final int status )
        {
            this.status = status;
        }

        @Override
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            if ( status != 0 )
            {
                httpServletResponse.setStatus( status );
                request.setHandled( true );
            }
        }
    }

    static class PutHandler
        extends AbstractHandler
    {
        private final String resourcePath;

        public PutHandler( final String repositoryPath )
        {
            this.resourcePath = repositoryPath;
        }

        @Override
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            Request base_request = request instanceof Request
                ? request
                : HttpConnection.getCurrentConnection().getHttpChannel().getRequest();

            if ( base_request.isHandled() || !"PUT".equals( base_request.getMethod() ) )
            {
                return;
            }

            base_request.setHandled( true );

            File file = new File( resourcePath, URLDecoder.decode( request.getPathInfo() ) );
            file.getParentFile().mkdirs();
            FileOutputStream out = new FileOutputStream( file );
            ServletInputStream in = request.getInputStream();
            try
            {
                IOUtil.copy( in, out );
            }
            finally
            {
                in.close();
                out.close();
            }

            httpServletResponse.setStatus( HttpServletResponse.SC_CREATED );
        }
    }

    private static class TestHeaderHandler
        extends AbstractHandler
    {
        protected Map<String, String> headers;

        public TestHeaderHandler()
        {
        }

        @Override
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            headers = new HashMap<>();
            for ( Enumeration e = request.getHeaderNames(); e.hasMoreElements(); )
            {
                String name = (String) e.nextElement();
                headers.put( name, request.getHeader( name ) );
            }

            httpServletResponse.setContentType( "text/plain" );
            httpServletResponse.setStatus( HttpServletResponse.SC_OK );
            httpServletResponse.getWriter().println( "Hello, World!" );

            request.setHandled( true );
        }
    }

    private static class AuthorizingProxyHandler
        extends TestHeaderHandler
    {
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            if ( request.getHeader( "Proxy-Authorization" ) == null )
            {
                httpServletResponse.setStatus( 407 );
                httpServletResponse.addHeader( "Proxy-Authenticate", "Basic realm=\"Squid proxy-caching web server\"" );

                ( (Request) request ).setHandled( true );
                return;
            }
            super.handle( s, request, httpServletRequest, httpServletResponse );
        }
    }

    private static class AuthorizingSecurityHandler
        extends ConstraintSecurityHandler
    {
        public AuthorizingSecurityHandler()
        {
            Constraint constraint = new Constraint();
            constraint.setName( Constraint.__BASIC_AUTH );
            constraint.setRoles( new String[]{ "admin" } );
            constraint.setAuthenticate( true );

            ConstraintMapping cm = new ConstraintMapping();
            cm.setConstraint( constraint );
            cm.setPathSpec( "/*" );

            HashLoginService hashLoginService = new HashLoginService();
            UserStore userStore = new UserStore();
            userStore.addUser( "user", new Password( "secret" ), new String[]{ "admin" } );
            hashLoginService.setUserStore( new UserStore() );
            setLoginService( hashLoginService );

//            HashUserRealm hashUserRealm = new HashUserRealm( "MyRealm" );
//            hashUserRealm.put( "user", "secret" );
//            hashUserRealm.addUserToRole( "user", "admin" );

//            setUserRealm( hashUserRealm );
//            setConstraintMappings( new ConstraintMapping[]{ cm } );
        }


    }

    private static class LatencyHandler
        extends AbstractHandler
    {
        private long delay;
        private int repeat;

        public LatencyHandler( long delay, int repeat )
        {
            this.delay = delay;
            this.repeat = repeat;
        }

        @Override
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            if ( request.isHandled() )
            {
                return;
            }

            if ( delay < 0 )
            {
                System.out.println( "Starting infinite wait." );
                synchronized ( this )
                {
                    try
                    {
                        wait();
                    }
                    catch ( InterruptedException e )
                    {
                    }
                }

                return;
            }

            Random randGen = new Random();

            int buffSize = 1024;
            byte[] buff = new byte[buffSize];
            randGen.nextBytes( buff );

//            for ( int idx = 0; idx < buffSize; idx++ )
//            {
//                buff[idx] = (byte) ( buff[idx] & 0x6F + (int) ' ' );
//            }

            OutputStream out = httpServletResponse.getOutputStream();
            for ( int cnt = 0; cnt < repeat; cnt++ )
            {
                try
                {
                    Thread.sleep( delay );
                }
                catch ( InterruptedException ex )
                {
                    // consume exception
                }

                out.write( buff );
                out.flush();
            }

            request.setHandled( true );
        }
    }

    private static class RedirectHandler
        extends AbstractHandler
    {
        private final String origUrl;

        private final int code;

        private final int maxRedirects;

        private int redirectCount = 0;

        private final String currUrl;

        private final boolean relativeLocation;

        public RedirectHandler( final int code, final String currUrl, final String origUrl, final int maxRedirects,
                                boolean relativeLocation )
        {
            this.code = code;
            this.currUrl = currUrl;
            this.origUrl = origUrl;
            this.maxRedirects = maxRedirects;
            this.relativeLocation = relativeLocation;
        }

        @Override
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            if ( request.isHandled() )
            {
                return;
            }

            if ( request.getRequestURI().equals( currUrl ) )
            {
                redirectCount++;

                String location;
                if ( maxRedirects < 0 || redirectCount < maxRedirects )
                {
                    location = currUrl;
                }
                else
                {
                    location = origUrl;
                }

                if ( !relativeLocation && location.startsWith( "/" ) )
                {
                    String base = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
                    location = base + location;
                }

                httpServletResponse.setStatus( code );
                httpServletResponse.setHeader( "Location", location );
                ( (Request) request ).setHandled( true );
            }
            else if ( request.getRequestURI().equals( origUrl ) )
            {
                Random randGen = new Random();

                int buffSize = 1024;
                byte[] buff = new byte[buffSize];
                randGen.nextBytes( buff );

                for ( int idx = 0; idx < buffSize; idx++ )
                {
                    buff[idx] = (byte) ( buff[idx] & 0x2F + (int) ' ' );
                }

                OutputStream out = httpServletResponse.getOutputStream();
                out.write( buff );

                request.setHandled( true );
            }
        }
    }

    static class HugeDataHandler
        extends AbstractHandler
    {

        private long size;

        public HugeDataHandler( long size )
        {
            this.size = size;
        }

        @Override
        public void handle( String s, Request request, HttpServletRequest httpServletRequest,
                            HttpServletResponse httpServletResponse )
            throws IOException, ServletException
        {
            if ( "GET".equals( request.getMethod() ) )
            {
                OutputStream os = httpServletResponse.getOutputStream();

                IOUtil.copy( new HugeInputStream( size ), os );
                os.close();

                httpServletResponse.setStatus( 200 );
                request.setHandled( true );
            }
        }
    }
}
