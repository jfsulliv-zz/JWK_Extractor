package web;

import java.net.URL;
import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Java functionality for index.jsp
 */
public class IndexHelper {
	/**
	 * Passes a request to change the target page to the user session so that
	 * the new target will be used on the next/current page load.
	 * 
	 * @param request
	 *            server request object
	 * @param session
	 *            server session object
	 */
	public static void processPageTarget(HttpServletRequest request,
			HttpSession session) {
		String pageTarget = (String) request.getParameter("pageTarget");

		// Check if new page request exists
		if (pageTarget == null) {
			// If no request, grab the current page saved in session.
			pageTarget = (String) session.getAttribute("pageTarget");
			if (pageTarget == null) {
				pageTarget = "index.jsp"; // Default page target
			}
		}
		session.setAttribute("pageTarget", pageTarget);
	}

	/**
	 * Initialize the session and prepares necessary data.
	 * 
	 * @param session
	 *            server session object
	 */
	public static void init(HttpSession session) {
		Boolean initDone = (Boolean) session.getAttribute("initDone");
	}
}
