#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <queue>
#include <thread>
#include <mutex>
#include <map>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <climits>

// OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

struct URLComponents {
    string protocol;
    string hostname;
    string path;
    int port;
};

struct Result {
    string url;
    string ip;
    int port = 80;

    long dns_ms = -1;
    long connect_ms = -1;
    long total_ms = -1;

    string status_line;
    int status_code = -1;
    string content_type;
    long content_length = -1;
    long response_size = 0;
    long body_size = 0;

    bool ok = false;
    string error;
};

// ---------- URL parse ----------
URLComponents parseURL(const string& url) {
    URLComponents components;
    size_t pos = 0;

    if (url.rfind("http://", 0) == 0) {
        components.protocol = "http";
        pos = 7;
    } else if (url.rfind("https://", 0) == 0) {
        components.protocol = "https";
        pos = 8;
    } else {
        components.protocol = "http";
        pos = 0;
    }

    size_t pathStart = url.find('/', pos);
    if (pathStart != string::npos) {
        components.hostname = url.substr(pos, pathStart - pos);
        components.path = url.substr(pathStart);
    } else {
        components.hostname = url.substr(pos);
        components.path = "/";
    }

    size_t portPos = components.hostname.find(':');
    if (portPos != string::npos) {
        components.port = stoi(components.hostname.substr(portPos + 1));
        components.hostname = components.hostname.substr(0, portPos);
    } else {
        components.port = (components.protocol == "https") ? 443 : 80;
    }

    return components;
}

// ---------- DNS ----------
string resolveDNS(const string& hostname) {
    struct addrinfo hints, *result;
    char ip[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname.c_str(), NULL, &hints, &result);
    if (status != 0) return "";

    struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);

    freeaddrinfo(result);
    return string(ip);
}

// ---------- TCP connect with timeout ----------
int createTCPConnectionWithTimeout(const string& ip, int port, int timeout_sec) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) { close(sockfd); return -1; }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) { close(sockfd); return -1; }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return -1;
    }

    int res = connect(sockfd, (sockaddr*)&server_addr, sizeof(server_addr));
    if (res == 0) {
        // connected immediately
    } else if (res < 0 && errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);

        timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        int sel = select(sockfd + 1, NULL, &wfds, NULL, &tv);
        if (sel <= 0) {
            close(sockfd);
            return -1;
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0) {
            close(sockfd);
            return -1;
        }
    } else {
        close(sockfd);
        return -1;
    }

    // back to blocking
    fcntl(sockfd, F_SETFL, flags);
    return sockfd;
}

// ---------- Build HTTP request ----------
string buildHTTPRequest(const URLComponents& url) {
    string request;
    request += "GET " + url.path + " HTTP/1.1\r\n";

    // Host header: port eklemek 80/443 dışı durumlarda şart; 443/80'de opsiyonel ama zararı yok.
    bool defaultPort = (url.protocol == "http" && url.port == 80) || (url.protocol == "https" && url.port == 443);
    if (!defaultPort) request += "Host: " + url.hostname + ":" + to_string(url.port) + "\r\n";
    else request += "Host: " + url.hostname + "\r\n";

    request += "User-Agent: HTTP-Analyzer/3.0\r\n";
    request += "Accept: */*\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";
    return request;
}

bool sendHTTPRequest(int sockfd, const string& request) {
    ssize_t bytes_sent = send(sockfd, request.c_str(), request.length(), 0);
    return bytes_sent >= 0;
}

string receiveHTTPResponse(int sockfd) {
    string response;
    char buffer[4096];
    ssize_t bytes_received;
    while ((bytes_received = recv(sockfd, buffer, sizeof(buffer), 0)) > 0) {
        response.append(buffer, (size_t)bytes_received);
    }
    return response;
}

// ---------- HTTPS over TLS (OpenSSL) ----------
bool httpsRequestOverTLS(int sockfd, const string& hostname, const string& request, string& out_response) {
    // OpenSSL 1.1+ / 3.x: init is automatic, but these calls are harmless.
    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) return false;

    // Verify server cert
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        SSL_CTX_free(ctx);
        return false;
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return false;
    }

    // SNI is crucial for many modern sites
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    int sent = SSL_write(ssl, request.c_str(), (int)request.size());
    if (sent <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    out_response.clear();
    char buf[4096];
    while (true) {
        int n = SSL_read(ssl, buf, (int)sizeof(buf));
        if (n > 0) out_response.append(buf, (size_t)n);
        else break;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return true;
}

// ---------- Parse response to Result ----------
void parseHTTPResponseToResult(const string& response, Result& r) {
    r.response_size = (long)response.size();

    size_t header_end = response.find("\r\n\r\n");
    if (header_end == string::npos) {
        r.error = "Invalid HTTP response";
        return;
    }

    string headers = response.substr(0, header_end);
    string body = response.substr(header_end + 4);

    r.body_size = (long)body.size();

    size_t first_line_end = headers.find("\r\n");
    r.status_line = headers.substr(0, first_line_end);

    // status code
    size_t s1 = r.status_line.find(' ');
    size_t s2 = r.status_line.find(' ', s1 + 1);
    if (s1 != string::npos && s2 != string::npos) {
        try {
            r.status_code = stoi(r.status_line.substr(s1 + 1, s2 - s1 - 1));
        } catch (...) {}
    }

    // headers: basic (case-sensitive); enough for demo
    size_t pos = (first_line_end == string::npos) ? 0 : (first_line_end + 2);
    while (pos < headers.size()) {
        size_t line_end = headers.find("\r\n", pos);
        if (line_end == string::npos) break;
        string line = headers.substr(pos, line_end - pos);

        if (line.rfind("Content-Type:", 0) == 0) {
            r.content_type = line.substr(strlen("Content-Type:"));
            while (!r.content_type.empty() && r.content_type[0] == ' ') r.content_type.erase(r.content_type.begin());
        } else if (line.rfind("Content-Length:", 0) == 0) {
            string v = line.substr(strlen("Content-Length:"));
            while (!v.empty() && v[0] == ' ') v.erase(v.begin());
            try { r.content_length = stol(v); } catch (...) {}
        }

        pos = line_end + 2;
    }

    r.ok = true;
}

// ---------- Measure one URL ----------
Result measureOne(const string& url) {
    Result r;
    r.url = url;

    URLComponents c = parseURL(url);
    r.port = c.port;

    // DNS timing
    auto dns_start = chrono::high_resolution_clock::now();
    string ip = resolveDNS(c.hostname);
    auto dns_end = chrono::high_resolution_clock::now();
    r.dns_ms = chrono::duration_cast<chrono::milliseconds>(dns_end - dns_start).count();

    if (ip.empty()) {
        r.error = "DNS failed";
        return r;
    }
    r.ip = ip;

    // connect timing
    auto conn_start = chrono::high_resolution_clock::now();
    int sockfd = createTCPConnectionWithTimeout(ip, c.port, 5);
    auto conn_end = chrono::high_resolution_clock::now();
    r.connect_ms = chrono::duration_cast<chrono::milliseconds>(conn_end - conn_start).count();

    if (sockfd < 0) {
        r.error = "Connect failed";
        return r;
    }

    // send/recv timeouts
    timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    string req = buildHTTPRequest(c);

    string response;

    auto total_start = chrono::high_resolution_clock::now();

    if (c.protocol == "https") {
        bool ok = httpsRequestOverTLS(sockfd, c.hostname, req, response);
        auto total_end = chrono::high_resolution_clock::now();
        r.total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - total_start).count();

        close(sockfd);

        if (!ok) {
            r.error = "TLS/HTTPS request failed";
            return r;
        }
    } else {
        if (!sendHTTPRequest(sockfd, req)) {
            close(sockfd);
            r.error = "Send failed";
            return r;
        }

        response = receiveHTTPResponse(sockfd);

        auto total_end = chrono::high_resolution_clock::now();
        r.total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - total_start).count();

        close(sockfd);
    }

    parseHTTPResponseToResult(response, r);
    if (!r.ok && r.error.empty()) r.error = "Parse failed";
    return r;
}

// Priority queue comparator: slowest first
struct SlowestFirst {
    bool operator()(const Result& a, const Result& b) const {
        return a.total_ms < b.total_ms;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Kullanim:\n  " << argv[0] << " <URL1> <URL2> ...\n";
        cout << "Ornek:\n  " << argv[0] << " http://example.com https://www.google.com\n";
        return 1;
    }

    cout << "========== Multi-Target HTTP/HTTPS Request Analyzer ==========\n";
    cout << "Targets: " << (argc - 1) << " URL\n\n";

    vector<Result> results; // DS #1
    unordered_map<string, Result> byURL; // DS #2
    priority_queue<Result, vector<Result>, SlowestFirst> pq; // DS #3

    mutex mtx;
    vector<thread> threads;

    for (int i = 1; i < argc; i++) {
        string url = argv[i];
        threads.emplace_back([&, url]() {
            {
                lock_guard<mutex> lock(mtx);
                cout << "[START] " << url << endl;
            }

            Result r = measureOne(url);

            {
                lock_guard<mutex> lock(mtx);
                cout << "[DONE ] " << url << " total=" << r.total_ms << "ms ok=" << r.ok << " err=" << r.error << endl;

                results.push_back(r);
                byURL[url] = r;
                if (r.total_ms >= 0 && r.ok) pq.push(r);
            }
        });
    }

    for (auto& t : threads) t.join();

    cout << "\n========== RESULTS ==========\n";
    for (const auto& r : results) {
        cout << "\nURL: " << r.url << "\n";
        if (!r.ok) {
            cout << "  ERROR: " << r.error << "\n";
            continue;
        }
        cout << "  IP: " << r.ip << ":" << r.port << "\n";
        cout << "  Status: " << r.status_line << " (code=" << r.status_code << ")\n";
        cout << "  DNS: " << r.dns_ms << " ms | Connect: " << r.connect_ms
             << " ms | Total(send+recv/TLS): " << r.total_ms << " ms\n";
        cout << "  Content-Type: " << (r.content_type.empty() ? "-" : r.content_type) << "\n";
        cout << "  Content-Length(header): " << r.content_length << "\n";
        cout << "  Response Size: " << r.response_size << " byte | Body Size: " << r.body_size << " byte\n";
    }

    // Summary
    int okCount = 0, e2xx = 0, e3xx = 0, e4xx = 0, e5xx = 0;
    map<string, int> contentTypes;

    long best = LONG_MAX, worst = -1;
    string bestURL, worstURL;

    for (const auto& r : results) {
        if (!r.ok) continue;
        okCount++;

        if (r.status_code >= 200 && r.status_code < 300) e2xx++;
        else if (r.status_code >= 300 && r.status_code < 400) e3xx++;
        else if (r.status_code >= 400 && r.status_code < 500) e4xx++;
        else if (r.status_code >= 500 && r.status_code < 600) e5xx++;

        if (!r.content_type.empty()) contentTypes[r.content_type]++;

        if (r.total_ms >= 0 && r.total_ms < best) { best = r.total_ms; bestURL = r.url; }
        if (r.total_ms >= 0 && r.total_ms > worst) { worst = r.total_ms; worstURL = r.url; }
    }

    cout << "\n========== SUMMARY ==========\n";
    cout << "Success: " << okCount << "/" << results.size() << "\n";
    cout << "Status distribution: 2xx=" << e2xx << " 3xx=" << e3xx << " 4xx=" << e4xx << " 5xx=" << e5xx << "\n";

    if (best != LONG_MAX) cout << "Fastest: " << bestURL << " (" << best << " ms)\n";
    if (worst != -1)      cout << "Slowest: " << worstURL << " (" << worst << " ms)\n";

    cout << "Top 3 slowest (priority_queue):\n";
    for (int i = 0; i < 3 && !pq.empty(); i++) {
        Result top = pq.top(); pq.pop();
        cout << "  - " << top.url << " : " << top.total_ms << " ms\n";
    }

    cout << "Content-Type counts:\n";
    for (auto& kv : contentTypes) {
        cout << "  - " << kv.first << " : " << kv.second << "\n";
    }

    cout << "========================================\n";
    cout << "✓ Done.\n";
    return 0;
}
