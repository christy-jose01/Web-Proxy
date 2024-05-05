#include <stdio.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <netdb.h>
#include <cmath>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <pthread.h>
#include <csignal>

using namespace std;

#define BUFFERSIZE 1024
#define MAX_CHILDREN 50


// global/shared variables
vector<string> forbiddenIps;
char forbidden_sites_file_path[BUFFERSIZE];
FILE *outfile;
struct sockaddr_in cli;

void write_accesslog(FILE *accesslog, string request, int status, int response_size, struct sockaddr_in cli) {

    cout << "started writing into access log" << endl;
    // time
    time_t current_time;
    struct tm *time_info;

    time(&current_time);
    time_info = gmtime(&current_time);

    char time_buffer[64];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%dT%H:%M:%SZ", time_info);

    // client ip
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(cli.sin_addr), client_ip, INET_ADDRSTRLEN);

    // request first line
    size_t hostEnd = request.find("\r\n", 0);
    if (hostEnd == string::npos) {
        cerr << "Error: Invalid HTTP request format" << endl;
        return;
    }
    string req_line = request.substr(0, hostEnd);
    // http status code
    // response size in bytes

    fprintf(accesslog, "%s %s %s %d %d\n", time_buffer, client_ip, req_line.c_str(), status, response_size);
    fflush(accesslog);

}

int is_valid_ip(const char *webress) {
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, webress, &ipv4_addr) == 1) {
        return 1;
    }

    struct in6_addr ipv6_addr;
    if (inet_pton(AF_INET6, webress, &ipv6_addr) == 1) {
        return 1;
    }

    return 0;
}

vector<string> store_forbidden_sites(const char *filename){

    vector<string> forbiddenSites;

    // open file
    FILE *forbidden = fopen(filename,"r");
    if(forbidden ==  NULL){
        cerr << "Error opening file" << endl;
        exit(EXIT_FAILURE);
    }
    char web[BUFFERSIZE];

    // parse the file line by line
    while(fgets(web, sizeof(web), forbidden)) {
        // Remove newline character if present
        if (web[strlen(web) - 1] == '\n')
            web[strlen(web) - 1] = '\0';

        char ipstr[INET_ADDRSTRLEN];
        // check if it is an ip address
        if (is_valid_ip(web)) {
            // find hostname
            strcpy(ipstr, web);
        } else {
            // assuming it is a website name
            // find the ip address
            struct hostent *server = gethostbyname(web);
            if (server != nullptr) {
                inet_ntop(AF_INET, server->h_addr_list[0], ipstr, INET_ADDRSTRLEN);
            } else {
                strcpy(ipstr, "no.ip.add.fnd");
                cerr << "Unable to resolve IP address for hostname: " << web << endl;
                continue;
            }
        }
        forbiddenSites.push_back(string(ipstr));
    }
    fclose(forbidden);

    return forbiddenSites;
}

void parseHTTPRequest(const string& httpRequest, string& method, string& destServer, int& SSL_port, float& httpVersion) {
    istringstream iss(httpRequest);

    // Extract method
    if (!(iss >> method)) {
        cerr << "Error: Invalid HTTP request format" << endl;
        return;
    }

    // Extract destination server and port
    size_t hostStart = httpRequest.find("Host: ");
    if (hostStart == string::npos) {
        cerr << "Error: Missing Host header in HTTP request" << endl;
        return;
    }
    size_t hostEnd = httpRequest.find("\r\n", hostStart);
    if (hostEnd == string::npos) {
        cerr << "Error: Invalid HTTP request format" << endl;
        return;
    }
    string hostAndPort = httpRequest.substr(hostStart + 6, hostEnd - (hostStart + 6));

    // Remove the www. prefix if present
    if (hostAndPort.substr(0, 4) == "www.") {
        hostAndPort = hostAndPort.substr(4);
    }

    // Check if port number is specified in the URL
    size_t colonPos = hostAndPort.find(':');
    if (colonPos != string::npos) {
        destServer = hostAndPort.substr(0, colonPos);
        SSL_port = stoi(hostAndPort.substr(colonPos + 1));
    } else {
        destServer = hostAndPort;
        SSL_port = 443; // Default SSL port
    }

    // Extract HTTP version
    size_t versionStart = httpRequest.find("HTTP/");
    if (versionStart == string::npos) {
        cerr << "Error: Missing HTTP version in HTTP request" << endl;
        return;
    }
    size_t versionEnd = httpRequest.find("\r\n", versionStart);
    if (versionEnd == string::npos) {
        cerr << "Error: Invalid HTTP request format" << endl;
        return;
    }
    string versionString = httpRequest.substr(versionStart + 5, versionEnd - (versionStart + 5));

    // Convert HTTP version to float
    httpVersion = stof(versionString);
}

string resolveDestinationServer(const string& destServer) {
    char ipstr[INET_ADDRSTRLEN];
    struct hostent *server = gethostbyname(destServer.c_str());
    if (server == nullptr) {
        cerr << "Unable to resolve IP address for hostname: " << destServer << endl;
        return "";
    }
    inet_ntop(AF_INET, server->h_addr_list[0], ipstr, INET_ADDRSTRLEN);
    return string(ipstr);
}

bool checkForbidden(const string& destIp, const vector<string>* forbiddenIpsPtr) {
    if (forbiddenIpsPtr == nullptr) {
        // Handle null pointer error
        return false;
    }
    const vector<string>& forbiddenIps = *forbiddenIpsPtr;
    bool isForbidden =  find(forbiddenIps.begin(), forbiddenIps.end(), destIp) != forbiddenIps.end();

    return isForbidden;
}

void HTTP_err_response(string response_type, int conn_fd){
    string response;
    // BAD_REQUEST
    if(response_type=="BAD_REQUEST"){
        response = "HTTP/1.1 400 Bad Request\r\n\r\n";
    }
    // FORBIDDEN
    else if(response_type=="FORBIDDEN"){
        response = "HTTP/1.1 403 Forbidden\r\n\r\n";
    }
    // NOT_FOUND
    else if(response_type=="NOT_FOUND"){
        response = "HTTP/1.1 404 Not Found\r\n\r\n";
    }
    // NOT_IMPLEMENTED
    else if(response_type=="NOT_IMPLEMENTED"){
        response = "HTTP/1.1 501 Not Implemented\r\n\r\n";
    }
    // VERSION_NOT_SUPPORTED
    else if(response_type=="VERSION_NOT_SUPPORTED"){
        response = "HTTP/1.1 505 HTTP Version not supported\r\n\r\n";
    } else {
        cout<<"Wrong error type!"<<endl;
    }

    send(conn_fd, response.c_str(), response.length(), 0);
}

void handle_SSL(int SSL_port, int conn_fd, string destIp, string method, string destServer, string HttpRequest, sockaddr_in cli){
    // create SSL connection: client -> proxy -> server
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // method
    const SSL_METHOD *meth = SSLv23_method();

    // context
    SSL_CTX* ctx = SSL_CTX_new(meth);
    if(ctx == NULL){
        cerr << "Error creating SSL context" << endl;
        close(conn_fd);
        return;
    }

    // socket
    SSL *ssl = SSL_new(ctx);
    if(ssl == NULL) {
        cerr << "Error creating new SSL socket" << endl;
        SSL_CTX_free(ctx);
        close(conn_fd);
        return;
    }

    // create new socket
    struct sockaddr_in destSSL_addr;
    int SSL_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(SSL_fd == -1){
        fprintf(stderr, "Create Socket Error");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "Socket created successfully!\n");
    }

    // initialize socket
    memset(&destSSL_addr, '0', sizeof(destSSL_addr));
    destSSL_addr.sin_family = AF_INET;
    destSSL_addr.sin_port = htons(SSL_port);
    cout << "finished initializing SSL socket" << endl;

    // convert ip address string to binary
    cout << "destIp is : " << destIp << "\n";
    if(inet_pton(AF_INET, destIp.c_str(), &destSSL_addr.sin_addr)<= 0){
        fprintf(stderr,"Invalid IP Address!\n");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "Ip Address is Valid.\n");
    }

    // tcp connect to server
    if(connect(SSL_fd, (struct sockaddr*)&destSSL_addr, sizeof(destSSL_addr)) < 0){
        fprintf(stderr, "connect error\n");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "Connected to the Server Successfully!\n");
    }
    
    // set fd
    SSL_set_fd(ssl, SSL_fd);
    cout << "set  file descriptor for SSL socket" << endl;

    // connection
    if (SSL_connect(ssl) <= 0) {
        unsigned long sslError = ERR_get_error();
        char errorString[256];
        ERR_error_string_n(sslError, errorString, sizeof(errorString));
        cerr << "Error connecting via SSL: " << errorString << endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(conn_fd);
        return;
    } else {
        cout << "Connected via SSL!" << endl;
        // get certificate
        SSL_get_peer_certificate(ssl);
        // verify it
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    // Send HTTPS request
    string httpsRequest = method + " / HTTP/1.1\r\nHost: " + destServer + "\r\nConnection: close\r\n\r\n";
    if (SSL_write(ssl, httpsRequest.c_str(), httpsRequest.length()) <= 0) {
        cerr << "Error sending HTTPS request" << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(conn_fd);
        return;
    } else {
        cout << "HTTPS Request Sent." << endl;
    }

    // Pipeline data from server's socket to client's socket
    char read_buffer[BUFFERSIZE];
    int bytes_received;
    int total_bytes_received = 0;

    string http_status_line; // Variable to store the HTTP status line
    bool found_status_line = false; // Flag to indicate if the status line is found
    int status_code;

    do {
        // Read data from the server's socket
        bytes_received = SSL_read(ssl, read_buffer, BUFFERSIZE);
        total_bytes_received += bytes_received;

        if (bytes_received > 0) {
            cout << "Received " << bytes_received << " bytes:" << endl;

            // Write data to the client's socket
            int bytes_sent = send(conn_fd, read_buffer, bytes_received, 0);
            if (bytes_sent <= 0) {
                cerr << "Error sending data to client" << endl;
                break;
            }

            // Search for the HTTP status line
            if (!found_status_line) {
                http_status_line.append(read_buffer, bytes_received); // Append received data to the status line buffer

                // Check if the status line is complete
                size_t pos = http_status_line.find("\r\n");
                if (pos != string::npos) {
                    found_status_line = true;
                    // Extract the HTTP status code
                    string status_line = http_status_line.substr(0, pos);
                    size_t first_space = status_line.find(' ');
                    size_t second_space = status_line.find(' ', first_space + 1);
                    if (first_space != string::npos && second_space != string::npos) {
                        string status_code_str = status_line.substr(first_space + 1, second_space - first_space - 1);
                        status_code = stoi(status_code_str);
                        cout << "HTTP status code: " << status_code << endl;
                        // Now you can do whatever you want with the status code
                    }
                }
            }
        } else if (bytes_received < 0) {
            int ssl_error = SSL_get_error(ssl, bytes_received);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                cerr << "Error reading data from server: " << ssl_error << endl;
                break;
            }
        }
    } while (bytes_received > 0);

    cout << "total_bytes_received: " << total_bytes_received << endl;

    // write to access log
    write_accesslog(outfile, HttpRequest, status_code, total_bytes_received, cli);

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(conn_fd);
}

void handleHTTPreq(int conn_fd) {

    // read HTTP request from socket
    char buffer[BUFFERSIZE];
    ssize_t bytes_received = recv(conn_fd, buffer, BUFFERSIZE, 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        close(conn_fd);
        exit(EXIT_FAILURE);
    }

    string httpRequest(buffer, bytes_received);
    string method, destServer;
    int SSL_port;
    float httpVersion;

    int response_len = 17;
    
    // Parse HTTP request
    parseHTTPRequest(httpRequest, method, destServer, SSL_port, httpVersion);

    cout << "Method:" << method << ", Destination Server: " << destServer;
    cout << ", version: " << httpVersion << ", Port: " << SSL_port << endl;

    // error checking for invalid requests
    if (method.empty() || destServer.empty()) {
        // bad request
        HTTP_err_response("BAD_REQUEST", conn_fd);
        response_len+= 11;
        write_accesslog(outfile, httpRequest, 400, response_len, cli);
        cout << "bad request" << endl;
        close(conn_fd);
        return;
    }
    const float tolerance = 0.001; // Adjust the tolerance as needed
    if (fabs(httpVersion - 1.1) > tolerance) {
        HTTP_err_response("VERSION_NOT_SUPPORTED", conn_fd);
        response_len += 21;
        write_accesslog(outfile, httpRequest, 505, response_len, cli);
        cout << "version not supported" << endl;
        close(conn_fd);
        return;
    }

    if(method!="GET" && method!= "HEAD"){
        HTTP_err_response("NOT_IMPLEMENTED", conn_fd);
        response_len += 15;
        write_accesslog(outfile, httpRequest, 501, response_len, cli);
        cout << "not implemented" << endl;
        close(conn_fd);
        return;
    }

    // Resolve destination server to IP address
    string destIp = resolveDestinationServer(destServer);
    if (destIp.empty()) {
        // not found
        HTTP_err_response("NOT_FOUND", conn_fd);
        response_len += 9;
        write_accesslog(outfile, httpRequest, 404, response_len, cli);
        cout << "not found" << endl;
        close(conn_fd);
        return;
    }

    // Check if destination server is forbidden
    if (checkForbidden(destIp, &forbiddenIps)) {
        // forbidden
        cout <<  "forbidden" << endl;
        HTTP_err_response("FORBIDDEN", conn_fd);
        response_len+= 9;
        write_accesslog(outfile, httpRequest, 404, response_len, cli);
        close(conn_fd);
        return;
    } else {
        cout << destServer << " is allowed :D" << endl;
        // create SSL connection: client -> proxy -> server
        handle_SSL(SSL_port, conn_fd, destIp, method, destServer, httpRequest, cli);
    }
}

void sig_child(int signo) {
    pid_t pid;
    int stat;
    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        cout << "Child process " << pid << " terminated" << endl;
    }
}

void run_ctrl_c(vector<string>& forbiddenIps, char *forbidden_files){
    // clear vectors
    forbiddenIps.clear();
    // rewrite forbiddenIps
    forbiddenIps = store_forbidden_sites(forbidden_files);

    // display it
    cout << "Forbidden Sites:\n";
    for (auto const& ip : forbiddenIps) {
    	cout << ip << endl;
    }

    return;
}

void sig_int(int sigint){
    if(sigint == SIGINT){
        cerr <<  "\rCtrl+C pressed! Exiting..." << endl;
        run_ctrl_c(forbiddenIps, forbidden_sites_file_path);
        cerr << "forbidden sites reloaded successfully" << endl;
    }
}


int main(int argc, char *argv[]){
    // ./myproxy listen_port forbidden_sites_file_path access_log_file_path
    int LISTEN_PORT;
    // char forbidden_sites_file_path[BUFFERSIZE];
    char access_log_file_path[BUFFERSIZE];
    if(argc!=4){
        fprintf(stderr, "Usage: %s listen_port forbidden_sites_file access_log_file\n", argv[0]);
        exit(EXIT_FAILURE);
    } else {
        LISTEN_PORT = atoi(argv[1]);
        strncpy(forbidden_sites_file_path, argv[2], BUFFERSIZE-1);
        forbidden_sites_file_path[BUFFERSIZE-1]='\0';
        strncpy(access_log_file_path, argv[3], BUFFERSIZE -1);
        access_log_file_path[BUFFERSIZE-1]='\0';
    }
    // verify port num: range
    if(LISTEN_PORT < 1024 ||  LISTEN_PORT > 9999){
        fprintf(stderr,"Error: Port number should be between 1024 and 9999.\n");
        exit(EXIT_FAILURE);
    }

    // store the forbidden ips
    forbiddenIps = store_forbidden_sites(forbidden_sites_file_path);

    // store the Signal info
    signal(SIGINT, sig_int);
    signal(SIGCHLD, sig_child);

    int child_count = 0;

    // open the accesslog
    outfile = fopen(access_log_file_path, "wb+");
    if (!outfile) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "Opened %s to start writing\n", access_log_file_path);
    }
    
    // print the forbidden sites
    cout << "Forbidden Sites:\n";
    for (auto const& ip : forbiddenIps) {
    	cerr << ip << endl;
    }

    // create socket 
    struct sockaddr_in proxy_addr;
    int proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(proxy_fd == -1){
        fprintf(stderr, "Create Socket Error");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "Socket created successfully!\n");
    }

    // initialize socket
    memset(&proxy_addr, '0', sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy_addr.sin_port = htons(LISTEN_PORT);

    // bind
    if((bind(proxy_fd, (struct sockaddr*) &proxy_addr, sizeof(proxy_addr)))!= 0){
        fprintf(stderr, "socket bind failed ...\n");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "Binding done successfully!\n");
    }

    // listen
    if((listen(proxy_fd, SOMAXCONN))!= 0){
        fprintf(stderr, "Listen failed ...\n");
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "Server listening\n");
    }


    while(true){
        socklen_t clilen = sizeof(cli);
        // accept connection
        int conn_fd = accept(proxy_fd, (struct sockaddr *)&cli, &clilen);
        if(conn_fd == -1){
            fprintf(stderr, "server accept failed ..\n");
            continue;
        }

        // fork a child process to handle the connection
        pid_t pid = fork();
        if (pid < 0) {
            cerr << "fork failed" << endl;
        } else if (pid == 0) { // Child process
            close(proxy_fd); // Close the listening socket in the child process
            handleHTTPreq(conn_fd);
            close(conn_fd);
            exit(0);
        } else { // Parent process
            close(conn_fd); // Close the connection socket in the parent process
            child_count++;
            if (child_count >= MAX_CHILDREN) {
                // Optionally, you can limit the number of concurrent child processes here
                cerr << "Maximum number of children reached" << endl;
                break;
            }
        }        

    }



    // close connections
    fclose(outfile);
    close(proxy_fd);

    return 0;
}
