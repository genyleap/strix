/**
 * @file strix.hpp
 * @brief Header file for the Strix lightweight C++ web server framework.
 * @author Genyleap | compez.eth
 * @date March 2025
 * @version 1.0
 *
 * Strix is a multi-threaded, HTTPS-enabled web server framework designed for simplicity and flexibility.
 * It supports custom request handlers, static file serving, virtual hosts, and rate limiting.
 * This header defines the core classes for configuring and running the server.
 */

#ifndef STRIX_HPP
#define STRIX_HPP

#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <filesystem>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#endif

namespace Strix {

/**
 * @brief Class for logging messages.
 */
class Logger {
public:
    virtual ~Logger() = default;
    /**
     * @brief Logs a message with a specified level.
     * @param message The message to log.
     * @param level The log level (default: "INFO").
     */
    virtual void log(std::string_view message, std::string_view level = "INFO") = 0;
};

/**
 * @brief Class for handling HTTP requests.
 */
class RequestHandler {
public:
    virtual ~RequestHandler() = default;
    /**
     * @brief Processes an HTTP request and returns a response.
     * @param request The incoming request.
     * @return A unique pointer to the response.
     */
    virtual std::unique_ptr<class Response> handle(const class Request& request) = 0;
};

/**
 * @brief Class for handling network connections.
 */
class ConnectionHandler {
public:
    virtual ~ConnectionHandler() = default;
    /**
     * @brief Handles a network connection.
     * @param connection The connection to handle.
     */
    virtual void handle(class Connection& connection) = 0;
};

/**
 * @brief Represents an HTTP request.
 */
class Request {
public:
    enum class Method { GET, POST, PUT, DELETE, HEAD, OPTIONS };
    Method method;
    std::string path;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> queryParams;
    std::string host;

    /**
     * @brief Parses query parameters from the path.
     * Separates the path and query string, populating queryParams.
     */
    void parseQueryParams();
};

/**
 * @brief Represents an HTTP response.
 */
class Response {
public:
    int statusCode{200};
    std::string content;
    std::unordered_map<std::string, std::string> headers;

    /**
     * @brief Sets the Content-Type header.
     * @param type The MIME type (e.g., "text/html").
     */
    void setContentType(std::string_view type);
    /**
     * @brief Enables CORS headers.
     * @param origin The allowed origin (default: "*").
     */
    void enableCors(std::string_view origin = "*");
};

/**
 * @brief Configuration for a virtual host.
 */
struct VirtualHost {
    std::string serverName;
    std::string documentRoot;
    std::unordered_map<std::string, std::unordered_map<Request::Method, std::unique_ptr<RequestHandler>>> routes;
};

/**
 * @brief Server configuration settings.
 */
struct Config {
    std::string host{"127.0.0.1"};
    uint16_t port{8080};
    size_t threadPoolSize{std::thread::hardware_concurrency()};
    std::string certFile;
    std::string keyFile;
    bool enableSsl{true}; ///< Enable SSL if true and cert/key files are provided (default: true).
    std::string accessLog;
    std::string errorLog;
    size_t maxConnections{100};
    size_t bufferSize{8192};
    size_t rateLimitRequests{100};
    std::vector<VirtualHost> virtualHosts;

    Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    Config(Config&&) = default;
    Config& operator=(Config&&) = default;
};

/**
 * @brief Manages a network connection.
 */
class Connection {
public:
    Connection(SOCKET socket, SSL* ssl, bool useSsl) : socket(socket), ssl(ssl), useSsl(useSsl) {}
    ~Connection();

    SOCKET getSocket() const { return socket; }
    SSL* getSsl() const { return ssl; }
    std::string read(size_t bufferSize);
    void write(std::string_view data);

private:
    SOCKET socket;
    SSL* ssl;
    bool useSsl; ///< Whether to use SSL for this connection.
};

/**
 * @brief Core Strix web server class.
 */
class WebServer {
public:
    WebServer(Config config, std::shared_ptr<Logger> logger);
    ~WebServer();

    void addRoute(std::string_view vhost, std::string_view path, Request::Method method,
                  std::unique_ptr<RequestHandler> handler);
    bool start();
    void stop();
    void setConnectionHandler(std::unique_ptr<ConnectionHandler> handler);

    const Config& getConfig() const { return config; }
    bool checkRateLimit(std::string_view ip);
    void log(std::string_view message, std::string_view level = "INFO") {
        logger->log(message, level);
    }
    const std::unordered_map<std::string, VirtualHost>& getVirtualHosts() const { return virtualHosts; }
    std::string serializeResponse(const Response& response);
    bool isSslEnabled() const { return config.enableSsl && sslContext != nullptr; }

private:
    struct Task {
        std::unique_ptr<Connection> connection;
    };

    Config config;
    std::shared_ptr<Logger> logger;
    SOCKET serverSocket{INVALID_SOCKET};
    SSL_CTX* sslContext{nullptr};
    std::atomic<bool> running{false};
    std::vector<std::thread> threadPool;
    std::queue<Task> tasks;
    std::mutex queueMutex;
    std::condition_variable queueCondition;
    std::unordered_map<std::string, VirtualHost> virtualHosts;
    std::unique_ptr<ConnectionHandler> connectionHandler;
    std::mutex rateLimitMutex;
    std::unordered_map<std::string, std::pair<size_t, std::chrono::steady_clock::time_point>> rateLimits;

    void workerThread();
    void acceptConnections();
    void initializeSsl();
    void cleanup();
};

/**
 * @brief Factory class for creating Strix server components.
 */
class ServerFactory {
public:
    static std::unique_ptr<WebServer> createDefaultServer(Config config);
    static std::shared_ptr<Logger> createFileLogger(std::string_view accessLog, std::string_view errorLog);
    static std::unique_ptr<RequestHandler> createStaticFileHandler(std::string_view rootDir);
    static std::unique_ptr<ConnectionHandler> createDefaultConnectionHandler(WebServer* server);
};

} // namespace Strix

#endif // STRIX_HPP
