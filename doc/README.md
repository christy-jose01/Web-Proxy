# Files
Makefile: This file compiles  the proxy server program and runs it. It assumes that you have g++ installed on your system.

src/myproxy.cpp: This file  contains the main function of the proxy server and implements the functionality to handle client requests, forward them toIn this lab, you will create a proxy server. In this lab, you will create a simple proxy.

doc/README: This file is documentation for the lab.

Description:
The project entails developing an HTTP proxy server that facilitates secure communication between web clients and servers. The proxy server must handle HTTP 1.1 requests, supporting concurrent connections from multiple clients. It should convert plain text HTTP requests to HTTPS requests for communication with web servers, and vice versa for responses. Additionally, the server must parse incoming HTTP requests, enforce access control based on a forbidden sites list, reload this list upon receiving a SIGINT signal (Ctrl+C), and log request details to a specified file. The server is invoked with command-line arguments specifying the listen port, path to the forbidden sites file, and path to the access log file.

# How to Run:
Compile the source code into an executable binary. You can use a C++ compiler such as g++:
```g++ -o myproxy myproxy.cpp -lssl -lcrypto -lpthread ```

Once compiled successfully, you can run the executable binary with the required command-line arguments:

```./myproxy listen_port forbidden_sites_file_path access_log_file_path```

Replace listen_port with the port number on which the proxy server will listen for incoming connections. forbidden_sites_file_path should be the path to the file containing the list of forbidden sites. access_log_file_path should be the path to the file where access logs will be written.

For example:

```./myproxy 8080 forbidden_sites.txt access.log```

This command starts the proxy server listening on port 8080, using the forbidden_sites.txt file for access control, and writing access logs to access.log. Adjust the arguments as per your setup and requirements.

To refresh the forbidden sites, press ```Ctrl+C```.
To terminate the program, press ```Ctrl+/```.

# Tests ran:
1. Parsing HTTP Requests: The code tests the ability to parse incoming HTTP requests to extract information such as the request method, destination server, SSL port, and HTTP version.

2. Resolving Destination Servers: It tests the ability to resolve destination server hostnames to their corresponding IP addresses using DNS resolution.

3. Access Control: The code tests whether a destination server IP address is forbidden based on the access control list stored in a file.

4. HTTPS Conversion: It tests the ability to establish SSL/TLS connections to destination servers and forward HTTPS requests from clients to servers.

5. Error Handling: Your code tests various error scenarios, such as invalid HTTP requests, unsupported HTTP versions, connection errors, and forbidden destination servers.

6. Access Logging: It tests whether access log entries are correctly written to the specified log file, including the timestamp, client IP address, request details, response status code, and response size.

7. Signal Handling: The code tests the handling of the SIGINT signal for reloading the forbidden sites file and updating the access control list dynamically.

8. Concurrency: It tests the concurrency mechanism implemented using pthreads, ensuring that multiple client requests can be handled simultaneously without conflicts or race conditions.

9. Resource Management: Your code tests whether resources such as file pointers, sockets, and memory allocations are properly managed and released to prevent leaks and ensure efficient operation.

10. Integration Testing: The code can be tested in an integrated environment with real web clients (e.g., browsers, cURL) and servers to verify end-to-end functionality, including proxying HTTP requests and responses correctly.

# Code design:
Header Files Inclusion: The necessary header files are included, such as <stdio.h>, <iostream>, <fstream>, <cstring>, <string>, <vector>, <unistd.h>, <sstream>, <netinet/in.h>, <arpa/inet.h>, <netdb.h>, <cmath>, and various OpenSSL headers.

Global Variables and Constants: Global variables and constants are declared, including forbiddenIps (vector to store forbidden IP addresses), forbidden_sites_file_path (path to the file containing forbidden sites), outfile (file pointer for the access log), and thread-related variables.

Structures: Two structures are defined: pthread_data for thread-related data and Connection to represent a connection with its file descriptor and client address.

# Function Definitions:

- write_accesslog: Writes access log entries to the specified file.
- is_valid_ip: Checks if a given string represents a valid IP address.
- store_forbidden_sites: Reads forbidden sites from a file and stores them in a vector.
- parseHTTPRequest: Parses an HTTP request to extract method, destination server, SSL port, and HTTP version.
- resolveDestinationServer: Resolves a destination server hostname to its IP address.
- checkForbidden: Checks if a destination server IP is forbidden based on the access control list.
- HTTP_err_response: Generates HTTP error responses for various error types.
- handle_SSL: Handles SSL connections to the destination server.
- handleHTTPreq: Handles HTTP requests received by the proxy server.
- run_ctrl_c and ctrl_c_func: Functions to handle SIGINT signal for reloading the forbidden sites file.
- worker_thread: Function executed by worker threads to handle HTTP requests.
- main: Entry point of the program.
    - Main Function:

        - Parses command-line arguments.
        - Loads forbidden sites from the specified file.
        - Initializes pthread-related variables and opens the access log file.
        - Sets up signal handling for SIGINT.
        - Creates a socket, binds it, and starts listening for incoming connections.
        - Accepts connections, adds them to a connection queue, and signals worker threads.
        - Worker threads pick up connections from the queue and handle HTTP requests.
        - The main function runs indefinitely until terminated.
        - Overall, the code is structured to handle concurrent HTTP requests efficiently using pthreads while implementing features like access control, HTTPS conversion, and access logging. However, there are several areas for improvement, such as error handling, resource management, and code readability.