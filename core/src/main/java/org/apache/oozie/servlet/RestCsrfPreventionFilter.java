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

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;

import org.apache.oozie.util.XLog;

/**
 * This filter provides protection against cross site request forgery (CSRF)
 * attacks for REST APIs. Enabling this filter on an endpoint results in the
 * requirement of all client to send a particular (configurable) HTTP header
 * with every request. In the absense of this header the filter will reject the
 * attempt as a bad request.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public class RestCsrfPreventionFilter implements Filter {

    private static final XLog LOG = XLog.getLog(RestCsrfPreventionFilter.class);

    private static final String HEADER_USER_AGENT = "User-Agent";
    private static final String BROWSER_USER_AGENT_PARAM =
            "browser-useragents-regex";
    private static final String CUSTOM_HEADER_PARAM = "custom-header";
    private static final String CUSTOM_METHODS_TO_IGNORE_PARAM =
            "methods-to-ignore";
    static final String  BROWSER_USER_AGENTS_DEFAULT = "^Mozilla.*,^Opera.*";
    private static final String HEADER_DEFAULT = "X-XSRF-HEADER";
    static final String  METHODS_TO_IGNORE_DEFAULT = "GET,OPTIONS,HEAD,TRACE";
    static final String OOZIE_CSRF_COOKIE_NAME = "OOZIE-CSRF-TOKEN";
    String  headerName = HEADER_DEFAULT;
    private Set<String> methodsToIgnore = null;
    private Set<Pattern> browserUserAgents;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String customHeader = filterConfig.getInitParameter(CUSTOM_HEADER_PARAM);
        if (customHeader != null) {
            headerName = customHeader;
        }
        String customMethodsToIgnore =
                filterConfig.getInitParameter(CUSTOM_METHODS_TO_IGNORE_PARAM);
        if (customMethodsToIgnore != null) {
            parseMethodsToIgnore(customMethodsToIgnore);
        } else {
            parseMethodsToIgnore(METHODS_TO_IGNORE_DEFAULT);
        }

        String agents = filterConfig.getInitParameter(BROWSER_USER_AGENT_PARAM);
        if (agents == null) {
            agents = BROWSER_USER_AGENTS_DEFAULT;
        }
        parseBrowserUserAgents(agents);
    }

    void parseBrowserUserAgents(String userAgents) {
        String[] agentsArray =  userAgents.split(",");
        browserUserAgents = new HashSet<Pattern>();
        for (String patternString : agentsArray) {
            browserUserAgents.add(Pattern.compile(patternString));
        }
    }

    void parseMethodsToIgnore(String mti) {
        String[] methods = mti.split(",");
        methodsToIgnore = new HashSet<String>();
        for (int i = 0; i < methods.length; i++) {
            methodsToIgnore.add(methods[i]);
        }
    }

    /**
     * This method interrogates the User-Agent String and returns whether it
     * refers to a browser.  If its not a browser, then the requirement for the
     * CSRF header will not be enforced; if it is a browser, the requirement will
     * be enforced.
     * <p>
     * A User-Agent String is considered to be a browser if it matches
     * any of the regex patterns from browser-useragent-regex; the default
     * behavior is to consider everything a browser that matches the following:
     * "^Mozilla.*,^Opera.*".  Subclasses can optionally override
     * this method to use different behavior.
     *
     * @param userAgent The User-Agent String, or null if there isn't one
     * @return true if the User-Agent String refers to a browser, false if not
     */
    private boolean isBrowser(String userAgent) {
        if (userAgent == null) {
            return false;
        }
        for (Pattern pattern : browserUserAgents) {
            Matcher matcher = pattern.matcher(userAgent);
            if (matcher.matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Handles a request by applying the filtering logic.
     *
     * @param request the incoming HTTP request from the client
     * @param response the outgoing HTTP response for the filtered request
     * @param chain the chain of configured active filters
     * @throws IOException if there is an I/O error
     * @throws ServletException if the implementation relies on the servlet API
     *     and a servlet API call has failed
     */
    private void handleHttpInteraction(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String csrfToken = loadToken(request);
        if (csrfToken == null) {
            LOG.debug("CSRF token not found in HTTP request, creating new token");
            csrfToken = createNewToken();
            saveToken(csrfToken, request, response);
        }

        if (!isBrowser(request.getHeader(HEADER_USER_AGENT)) || methodsToIgnore.contains(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String actualToken = request.getHeader(headerName);
        if (!csrfToken.equals(actualToken)) {
            LOG.debug("Missing Required Header for CSRF Vulnerability Protection");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing Required Header for CSRF Vulnerability Protection");
            return;
        }
        chain.doFilter(request, response);
    }

    private String readCookieValue(HttpServletRequest request, String key) {
        if (request.getCookies() == null) {
            return null;
        }
        for(Cookie cookie : request.getCookies()){
            if(cookie.getName().equals(key)){
                return cookie.getValue();
            }
        }
        return null;
    }

    private String loadToken(HttpServletRequest request) {
        String token = readCookieValue(request, OOZIE_CSRF_COOKIE_NAME);
        if (token == null || token.length() == 0) {
            return null;
        }
        return token;
    }

    private String createNewToken() {
        return RandomStringUtils.random(20, 0, 0, true, true, null, new SecureRandom());
    }

    private void saveToken(String token, HttpServletRequest request, HttpServletResponse response) {
        String tokenValue = token == null ? "" : token;
        Cookie cookie = new Cookie(OOZIE_CSRF_COOKIE_NAME, tokenValue);
        int maxAge = -1;
        if (token == null) {
            maxAge = 0;
        }
        cookie.setMaxAge(maxAge);
        cookie.setSecure(request.isSecure());
        LOG.debug("Adding new CSRF token to response as {0}", OOZIE_CSRF_COOKIE_NAME);
        response.addCookie(cookie);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         final FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest)request;
        final HttpServletResponse httpResponse = (HttpServletResponse)response;
        handleHttpInteraction(httpRequest, httpResponse, chain);
    }

    @Override
    public void destroy() {
    }

    void setHeaderName(String headerName) {
        this.headerName = headerName;
    }
}
