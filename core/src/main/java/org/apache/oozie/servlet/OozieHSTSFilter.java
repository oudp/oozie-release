/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.oozie.servlet;

import com.google.common.annotations.VisibleForTesting;
import org.apache.oozie.service.ConfigurationService;
import org.apache.oozie.util.XLog;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OozieHSTSFilter implements Filter {

    private static final XLog LOG = XLog.getLog(OozieHSTSFilter.class);

    @VisibleForTesting
    static final String STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";

    private boolean isHSTSEnabled;
    private int hstsMaxAgeSeconds;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.isHSTSEnabled = ConfigurationService.getBoolean(ConfigurationService.HSTS_PROPERTY);
        this.hstsMaxAgeSeconds = ConfigurationService.getInt(ConfigurationService.HSTS_MAX_AGE_SECONDS);
        LOG.info("Initialized Strict Transport Security (HSTS) with property: max-age = {0}; isHSTSEnabled={1}",
                hstsMaxAgeSeconds, isHSTSEnabled);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) servletResponse;
        if (servletRequest.isSecure() && isHSTSEnabled) {
                res.addHeader(STRICT_TRANSPORT_SECURITY, "max-age=" + hstsMaxAgeSeconds);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
    }
}
