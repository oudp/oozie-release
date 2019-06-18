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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter that adds headers to the HTTP response based on the Oozie configuration
 */
public class OozieXResponseHeaderFilter implements Filter {

    private static final XLog LOG = XLog.getLog(OozieXResponseHeaderFilter.class);

    @VisibleForTesting
    static final String XXS_HEADER = "X-XSS-Protection";
    @VisibleForTesting
    static final String X_CONTENT_TYPE_HEADER = "X-Content-Type-Options";
    @VisibleForTesting
    static final String CACHE_CONTROL_HEADER = "Cache-Control";
    @VisibleForTesting
    static final String CACHE_CONTROL_VALUE = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0";

    private boolean isXXSEnabled;
    private boolean isXContentTypeEnabled;
    private boolean isCacheControlEnabled;

    @Override
    public void init(FilterConfig config) throws ServletException {
        initXXSFilter();
        initXContentTypeFilter();
        initCacheControlFilter();
    }

    private void initXXSFilter(){
        this.isXXSEnabled = ConfigurationService.getBoolean(ConfigurationService.XSS_PROPERTY);
        LOG.info("Initalized XSS Protection with properties: 1; mode=block; isXXSEnabled={0}", isXXSEnabled);
    }

    private void initXContentTypeFilter(){
        this.isXContentTypeEnabled = ConfigurationService.getBoolean(ConfigurationService.X_CONTENT_PROPERTY);
        LOG.info("Initialized X-Content-Type-Options with property: nosniff; isXContentTypeEnabled={0}",
                isXContentTypeEnabled);
    }

    private void initCacheControlFilter(){
        this.isCacheControlEnabled = ConfigurationService.getBoolean(ConfigurationService.CACHE_CONTROL_PROPERTY);
        LOG.info("Initialized Cache-Contol header with properties: " + CACHE_CONTROL_VALUE
                + ";isCacheControlEnabled={0}", isCacheControlEnabled);
    }

    private void addHeadersIfNeeded(ServletRequest request, ServletResponse response){
        HttpServletResponse res = (HttpServletResponse) response;
        if(isXXSEnabled){
            res.setHeader(XXS_HEADER,  "1; mode=block");
        }
        if(isXContentTypeEnabled){
            res.setHeader(X_CONTENT_TYPE_HEADER, "nosniff");
        }
        if(isCacheControlEnabled){
            res.setHeader(CACHE_CONTROL_HEADER, CACHE_CONTROL_VALUE);
            res.setHeader("Pragma", "no-cache");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        addHeadersIfNeeded(req, res);
        chain.doFilter(req,res);
    }

    @Override
    public void destroy() {
    }
}
