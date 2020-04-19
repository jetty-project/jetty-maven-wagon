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

import java.io.IOException;
import java.io.InputStream;

class HugeInputStream
    extends InputStream
{

    private long size;

    private long read;

    public HugeInputStream(long size)
    {
        this.size = size;
    }

    public long getSize()
    {
        return size;
    }

    @Override
    public int read()
        throws IOException
    {
        if (read >= size)
        {
            return -1;
        }
        read++;
        return 0;
    }

    @Override
    public int read(byte[] b, int off, int len)
        throws IOException
    {
        if (read >= size)
        {
            return -1;
        }

        int avail = (int) Math.min(len, size - read);

        read += avail;

        return avail;
    }

}
