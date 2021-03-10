'''

        CSC 361: Computer Communications and Networks
        Programming Assignment 1: Smart Web Client
                    Prof: Kui Wu
            Developed By: Austin Bassett

'''

# Modules
import ssl
import socket
import sys
import re


# Global http versions support trackers and the list of cookies.
httpsSupported = "No"
http2Supported = "No"
http1Dot1Supported = "No"
cookieJar = []


# Error handling for when program is run with incorrect number of arguments.
if(len(sys.argv) != 2):
    print('Error: Incorrect number of arguments. Please run as SmartClient.py <URL>.')
    exit(0)

# Setting the default time to be 5 seconds.
socket.setdefaulttimeout(5)


def createConnection(targetUrl: str, supportHTTPS: bool) -> socket.socket:
    """
        Creates a socket connection either on port 80 for Http, or port 443 for HTTPS with a ssl wrap on the socket.

        Parameters
        ----------
        targetUrl: str
            The url we are trying to connect to.

        supportHTTPS: bool
            Flag for creating a connection to HTTPS through port 443.

        Returns
        -------
        socket
            A socket connected to the desired Url through the correct port.
    """

    # Initalize the socket.
    socketObject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Check which port to use.
    if supportHTTPS:

        portNumber = 443

    else:

        portNumber = 80

    try:

        # Initalize a connection to the targetUrl through the portNumber.
        socketObject.connect((targetUrl, portNumber))

    except socket.timeout:
        pass

    # Wrap the socket if using HTTPS
    if supportHTTPS:

        try:

            socketObject = ssl.wrap_socket(socketObject)

        except:
            pass

    return socketObject


def requestSender(targetUrl: str, useHTTPS: bool, version: int) -> str:
    """
        Sends the Http request.

        Parameters
        ----------
        targetUrl: str
            The url we are trying to connect to.

        useHTTPS: bool
            Flag indicating if a HTTPS connection is needed.

        version: int
            The version to send in the HTTP request.

        Returns
        -------
        string
            A string containing the response message from the server.
    """

    # Create a socket connection.
    socketObj = createConnection(targetUrl, useHTTPS)

    # Constructing the HTTP message to be sent.
    requestMessage = f"GET / HTTP/{version}\r\nHost: {targetUrl}\r\n\r\n"

    try:

        # Encoding the HTTP message before sending it.
        socketObj.sendall(requestMessage.encode('UTF-8'))

    except:
        pass

    httpResponse = b""

    # Loop for getting the entire response message.
    while True:

        # Try-Except for catching when a socket has timed out.
        try:

            # Storing 4096 bytes of the response in answer.
            answer = socketObj.recv(4096)

            # Checking if the answer is an empty byte string.
            if not answer:
                break

            # Concatenating the answer to the response variable.
            httpResponse = httpResponse + answer

        except:
            break
            
    # Close the socket before returning.
    socketObj.close()

    # Decoded the message back into a normal string before returning.
    return httpResponse.decode('UTF-8', errors="ignore")


def statusParser(responseMessage: str, httpsCheck: bool):
    """
        Extracts the status code and the HTTP version from the response message from the server.

        Parameters
        ----------
        responseMessage: str
            String containing the response message from the server.

        httpsCheck: bool
            Flag indicating wheither to check if server supports HTTPS or not.

        Returns
        -------
        boolean
            Only if httpsCheck was True. Returns True if HTTPS surpported. Otherwise, False.
    """

    # Variables.
    code = 0
    version = ""
    global http1Dot1Supported
    global httpsSupported

    try:

        # Extract the status code and version from the response message.
        code = re.search("^(HTTP/1.[1|0])\s([0-9]+)", responseMessage).group(2)
        version = re.search("^(HTTP/1.[1|0])\s([0-9]+)", responseMessage).group(1)

    except:
        pass
    
    # Grabbing only the integer part of the code.
    code = int(code) // 100
    
    # Check HTTPS and HTTP1.1
    if httpsCheck:

        # Check if HTTP1.1 is supported and if the status code is in the list.
        if version == "HTTP/1.1" and code in [1.0, 2.0, 3.0]:

            # Update global http1.1 variable indicating HTTP1.1 is supported.
            http1Dot1Supported = "Yes"


            # Update global https variable indicating HTTPs is supported.
            httpsSupported = "Yes"

            return True

        return False

    # Else, just check http1.1  
    else:

        if version == "HTTP/1.1" and code in [1.0, 2.0, 3.0]:

            # Update global http1.1 variable indicating HTTP1.1 is supported.
            http1Dot1Supported = "Yes"

    return


def checkHTTPS(checkUrl: str) -> bool:
    """
        Checks if a server supports HTTPS.

        Parameters
        ----------
        checkUrl: str
            The url we are trying to connect to.

        Returns
        -------
        boolean
            True if server supports HTTPS. Otherwise, False.
    """

    # Send a request to the webserver.
    response = requestSender(checkUrl,True, 1.1)
    
    # Extract the status code.
    return statusParser(response, True)


def checkH2(checkUrl: str) -> bool:
    """
        Checks if the server supports Http/2

        Parameters
        ----------
        checkUrl: str
            The url we are trying to connect to.

        Returns
        -------
        boolean
            True if server supports HTTPS. Otherwise, False.
    """
    # Initializing the socket object.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Wrapping the socket before connecting to a security port.
    ctx = ssl.SSLContext()
    ctx.set_alpn_protocols(['h2'])
    conn = ctx.wrap_socket(sock, server_hostname=checkUrl)

    # Trying the connection.
    try:

        conn.connect((checkUrl, 443))

    except:
        pass
    
    # Getting the answer from the protocol return.
    answer = conn.selected_alpn_protocol()

    if answer == "h2":

        # Update global http2 variable indicating HTTP/2 is supported.
        global http2Supported
        http2Supported = "Yes"

        # Close the socket connection.
        conn.close()
        return True

    # Close the socket connection.
    conn.close()
    return False


def cookieParser(responseMessage:str):
    """
        Extracts all the cookie information.

        Parameters
        ----------
        responseMessage: str
            String containing the response message from the server.

    """

    # List for holding each line that contains "Set-Cookie:" in it.
    bakeCookies = []

    # Splitting the response message by new line character.
    cookieBatter = responseMessage.splitlines()

    # Adding each line that starts with Set-Cookie, to the cookie batter.
    for line in cookieBatter:

        # Checking if the line contains the work Set-Cookie.
        containCookie = re.search(r"(?i)Set-Cookie:", line)
        
        if containCookie is not None:

            bakeCookies.append(line)

        # Break out once the html style information is being read. This prevents redundant information.
        if "<!DOCTYPE html" in line:
            break
    
    # Extracting the required information out of the strings in the bakeCookies list.
    for cookie in bakeCookies:

        # Initializing variables to be empty strings.
        domain = ""
        expires = ""

        # Empty list for holding the string.
        finishedCookie = []

        # Getting the data that is before the first equal sign. Example, labeled HERE "Set-Cookie: HERE=".
        cookieName = re.search(r"(?i)Set-Cookie:?(.[a-zA-Z0-9., -:_]*)", cookie).group(1)

        # Check if the string contains a domain= or Domain=.
        checkDomain = re.search(r"(?i)domain=?(.[a-zA-Z0-9.]*)", cookie)

        # Check if the string contains expires=.
        checkExpires = re.search(r"(?i)expires=?(.[a-zA-Z0-9., -:]*)", cookie)

        # If the checkDomain contains a value, build the domain string.
        if checkDomain is not None:
            
            domain = re.search(r"(?i)domain=?(.[a-zA-Z0-9.]*)", cookie).group(1)
            domain = ", domain: " + domain

        # If the checkExpires contains a value, build the expires string.
        if checkExpires is not None:

            expires = re.search(r"(?i)expires=?(.[a-zA-Z0-9., -:]*)", cookie).group(1)
            expires = ", expires time: " + expires

        # Building the cookie string.
        coolingCookie = "Cookie Name: " + cookieName + expires + domain

        # Appending the cookie to the cookie jar.
        cookieJar.append(coolingCookie)
    

def messageSystem(url: str, host: str, requestStatus: str):
    """
        Outputs messages to the command line. Informing users of current situation of their request.

        Parameters
        ----------
        url: str
            String containing the url of the server.

        host: str
            String containing just the "www.website.com" part.

        requestStatus:
            String indicating which message to output.
    """

    # Outputing a message to the command line.
    if requestStatus == "Start":

        message = f'''--Request Begin--\nGET {url} HTTP/1.1\nHost: {host}\n'''

    elif requestStatus == "Wait":

        message = f'''--Request Waiting--\nHTTP request sent, awaiting response\n'''

    else:

        message = f'''--Request Finished--\nResponse recieved\n'''    

    # Print request is beginning.
    print(message)


def output(website: str):
    """
        Outputs all the extracted data.

        Parameters
        ----------
        website: str
            String containing the website name.

    """

    # Building the first part of the output.
    supportsMessage = f'''Website: {website}\n1. Supports of HTTPs: {httpsSupported}\n2. Supports http1.1: {http1Dot1Supported}\n3. Supports http2: {http2Supported}'''

    # Output the data to the command line.
    print(supportsMessage)
    print("4. List of Cookies")

    # Print Cookies.
    for cookie in cookieJar:
        print(cookie)


def buildURL(url: str, https: bool) -> str:
    """
        Appends http(s):// and /index.html to the url.

        Parameters
        ----------
        url: str
            String containing the url of the server.

        https: bool
            Flag indicating wheither or not to add https

        Returns
        -------
        string
            The completed http(s)://website/index.html string
    """

    # Append either http or https to the url.
    if https:

        return "https://" + url + "/index.html"
    
    return "http://" + url + "/index.html"


def main():    
    """
        Calls all the needed functions, in order.
    """

    # Storing the passed url.   
    url = sys.argv[1]

    # Checking if https is supported.
    supportsHTTPS = checkHTTPS(url)

    # Add the http:// and index.html to the url.
    completeUrl = buildURL(url, supportsHTTPS)

    # Printing message to command line informing users the request is starting.
    messageSystem(completeUrl, url, "Start")

    # Checking if the passed website supports http2.
    checkH2(url)

    # Printing message to command line informing user we are waiting for response.
    messageSystem(None, None, "Wait")

    # Send request.
    response = requestSender(url, supportsHTTPS, 1.1)
    
    # If webserver didn't support HTTPS, Check if it supports http/1.1
    if http1Dot1Supported == "No":

        statusParser(response, False)

    # Printing message to command line informing user request has finished.
    messageSystem(None, None, None)

    # Parse all the cookie data
    cookieParser(response)

    # Output all the results.
    output(url)


if __name__ == '__main__':

    # Run main function.
    main()