SmartClient is a Python 3 designed program to send HTTP requests to the passed URL and output the following:

    1. Supports of HTTPs: Yes
    2. Supports http1.1: Yes
    3. Supports http2: Yes
    4. List of Cookies
    Cookie Name:  session-id, domain: .amazon.com
    Cookie Name:  session-id-time, domain: .amazon.com
    Cookie Name:  i18n-prefs, domain: .amazon.com
    Cookie Name:  sp-cdn, domain: .amazon.com

To execute SmartClient type the following on the command line, while in the same directory as SmartClient.py

    python3 SmartClient.py <url>

**** Read This Section Before Executing ***
*
* SmartClient currently only works on Urls in the form of:
*
*        www.something.(com, ca, org, etc..)
*
* Using a Url in the following format will cause erros:
*
*       http(s)://www.something.(com, ca, org, etc..)/(anything over here)
*
*******************************************