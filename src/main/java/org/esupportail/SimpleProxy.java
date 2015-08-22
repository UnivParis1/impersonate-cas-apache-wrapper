package org.esupportail;

import java.io.*;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.List;
import java.util.logging.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.*;
import javax.servlet.http.*;

import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.HttpURLConnection;

@SuppressWarnings("serial")
public class SimpleProxy extends HttpServlet {   
    static private String CAS_URL_PREFIX = "http://localhost:8080/cas";
    static private String TICKET_FILE_PREFIX = "/tmp/impersonate-";
    static private String IMPERSONATE_COOKIE = "CAS_TEST_IMPERSONATE";
    static private String CAN_IMPERSONATE_URL = "https://bandeau-ent.univ-paris1.fr/canImpersonate.php?test";
    
    private Logger log;
    
    public void init(ServletConfig servletConfig) throws ServletException {
        log = Logger.getLogger(SimpleProxy.class.getName());
    }
    
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ProtocolException, IOException {
 	handle(request, response);
    }
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ProtocolException, IOException {
 	handle(request, response);
    }
    public void handle(HttpServletRequest request, HttpServletResponse response) throws ProtocolException, IOException {
    	String queryString = request.getQueryString();            
    	String part = request.getRequestURI() + "";
    	String destUrl = CAS_URL_PREFIX + part + (queryString==null ? "" : "?"+queryString);

    	HttpURLConnection con;
    	String body = null;
    	
    	if (part.equals("/login")) {
	    con = proxy(destUrl, request);
	    Cookie impersonate = getCookie(request, IMPERSONATE_COOKIE);
	    if (impersonate == null) {
		log.severe("ERROR login but no impersonate. The apache RewriteCond must be wrong!");
	    } else if (con.getResponseCode() == 302) {
		String ticket = getTicketFromRedirect(con);
		if (ticket != null) {
		    log.info("saving ticket=" + ticket + " to be impersonated to " + impersonate.getValue());
		    outputFile(ticketFile(ticket), impersonate.getValue());
		}
	    } else if (con.getResponseCode() == 301) {
		log.warning("weird redirect permanent response from cas server. It seems to happen on non https services?");
	    }
    	} else if (part.equals("/serviceValidate") || part.equals("/proxyValidate") || part.equals("/validate")) {
	    String ticket = request.getParameter("ticket");
	    String impersonate = ticket == null ? null : getContent(ticketFile(ticket));
	    ticketFile(ticket).delete(); // consume it to ensure no dead-loop

	    con = proxy(destUrl, request);
	    //log.info("got ticket " + ticket);
	    if (impersonate != null) {
		body = body(con);
		boolean casV1 = part.equals("/validate");
		String regexp = casV1 ? "yes\n(.*)" : "<cas:user>(.*?)</cas:user>";
		String user = getFirstMatch(regexp, body);
		String service = request.getParameter("service");
		//log.info("verifying impersonate " + user + " for service " + service + " for ticket " + ticket);
		if (user != null && allowImpersonate(service, user)) {
		    log.info("allowing impersonate " + impersonate + " instead of " + user + " for ticket " + ticket);
		    String bodyPart = casV1 ? "yes\n" + impersonate : "<cas:user>" + impersonate + "</cas:user>";
		    body = body.replaceFirst(regexp, bodyPart);
		}
	    } else {
		log.severe("ERROR serviceValidate but no impersonate. The apache RewriteCond must be wrong!");
	    }
    	} else {
	    log.severe("unknown request " + part + ". giving up otherwise we may dead-loop");
	    return;
    	}

	response.setStatus(con.getResponseCode());            
	copyMostHeaders(con, response);            
    	if (body != null) {
	    response.getOutputStream().print(body);	
    	} else {
	    copyBody(con, response);
    	}
	con.disconnect();
    }

    private boolean allowImpersonate(String service, String user) throws IOException {
	URL url = url(CAN_IMPERSONATE_URL + "&uid=" + urlencode(user) + "&service=" + urlencode(service));
	HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	conn.connect();			
	if (conn.getResponseCode() == 403) return false;
	return true;
    }

    private String getTicketFromRedirect(HttpURLConnection con) {
	String ticket = null;
	String location = con.getHeaderField("Location");
	if (location != null) {
	    ticket = location.replaceFirst(".*ticket=", "");
	    if (ticket.equals(location)) ticket = null;
	}
	return ticket;
    }

    private File ticketFile(String ticket) {
	return new File(TICKET_FILE_PREFIX + ticket);
    }

    private HttpURLConnection proxy(String url, HttpServletRequest request) throws IOException, ProtocolException {
        URL url_ = url(url);
        if (url_ == null) {
	    log.severe("invalid url " + url);
	    return null;
        }
        log.info("Fetching " + url);
	HttpURLConnection con = (HttpURLConnection) url_.openConnection();           
	con.setRequestMethod(request.getMethod());
	copyHeaders(request, con);
        if (request.getMethod().equals("POST")) {
            con.setDoOutput(true);
            copy(request.getInputStream(), con.getOutputStream());
        }
	con.connect();
	return con;
    }

    private void copyMostHeaders(HttpURLConnection con, HttpServletResponse response) {
	for (Map.Entry<String, List<String>> mapEntry : con.getHeaderFields().entrySet()) {
	    String key = mapEntry.getKey();
	    if(key == null || key.equalsIgnoreCase("Content-length")) continue;
	    for (String val : mapEntry.getValue()) {
		response.addHeader(key, val);
	    }
	}
    }

    private void copyHeaders(HttpServletRequest request, HttpURLConnection con) {
	for (String headerName : list(request.getHeaderNames())) {
	    for (String val : list(request.getHeaders(headerName)))
		con.addRequestProperty(headerName, val);
	}
    }

    private String body(HttpURLConnection con) throws IOException {
	InputStream in = bodyInputStream(con);
	return in == null ? null : getContent(in);
    }

    private InputStream bodyInputStream(HttpURLConnection con) {
	InputStream in = con.getErrorStream();
	if (in == null) 
	    try {
		in = con.getInputStream();
	    } catch (Exception e) {
		in = con.getErrorStream();
	    }
	return in;
    }

    private void copyBody(HttpURLConnection con, HttpServletResponse response) throws IOException {
	InputStream in = bodyInputStream(con);			
	if (in != null) copy(in, response.getOutputStream());
    }

    private void copy(InputStream inputStream, OutputStream outputStream) throws IOException {
	BufferedInputStream in = new BufferedInputStream(inputStream);
	BufferedOutputStream out = new BufferedOutputStream(outputStream);

	int oneByte;
	while ((oneByte = in.read()) != -1) 
	    out.write(oneByte);

	out.flush();
	out.close();
	in.close();
    }

    private void outputFile(File filename, String value) throws FileNotFoundException {
	PrintWriter writer = new PrintWriter(filename);
	writer.print(value);
	writer.close();
    }

    static String getContent(File file) throws IOException {
	try {
	    return getContent(new FileInputStream(file));
	} catch (FileNotFoundException e) {
	    return null;
	}
    }
	
    static String getContent(InputStream is) throws IOException {
	int bufferSize = 1024;
	char[] buffer = new char[bufferSize];
	StringBuilder out = new StringBuilder();
	Reader in = new InputStreamReader(is, "UTF-8");
	for (;;) {
	    int rsz = in.read(buffer, 0, buffer.length);
	    if (rsz < 0) break;
	    out.append(buffer, 0, rsz);
	}
	return out.toString();
    }

    private Cookie getCookie(HttpServletRequest request, String name) {
	for (Cookie cookie : request.getCookies())
	    if (cookie.getName().equals(name))
		return cookie;
	return null;
    }

    public static String urlencode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("urlencode failed on '" + s + "'");
        }
    }

    private URL url(String urlString) {
    	try {
	    return new URL(urlString);
	} catch (MalformedURLException e1) {
	    return null;
	}
    }

    private String getFirstMatch(String re, String s) {
	Matcher m = Pattern.compile(re).matcher(s);
	return m.find() ? m.group(1) : null;
    }
    
    @SuppressWarnings("unchecked")
    List<String> list(Enumeration<?> l) {
	return Collections.list((Enumeration<String>) l);    	
    }
    
}
