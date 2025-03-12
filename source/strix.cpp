/**
 * @file WebServer.cpp
 * @brief Implementation of the WebServer web server framework.
 * @author Genyleap | compez.eth
 * @date March 2025
 */

#include "strix.hpp"
#include <sstream>
#include <chrono>
#include <fstream>

namespace Strix {

class FileLogger : public Logger {
public:
    FileLogger(std::string_view accessLog, std::string_view errorLog)
        : accessLogFile(accessLog), errorLogFile(errorLog) {}

    void log(std::string_view message, std::string_view level) override {
        std::ofstream& logFile = (level == "ERROR" || level == "WARNING") ? errorLogFile : accessLogFile;
        auto now = std::chrono::system_clock::now();
        std::time_t tt = std::chrono::system_clock::to_time_t(now);
        std::lock_guard<std::mutex> lock(logMutex);
        logFile << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S") << " [" << level << "] " << message << std::endl;
    }

private:
    std::ofstream accessLogFile;
    std::ofstream errorLogFile;
    std::mutex logMutex;
};

class DefaultConnectionHandler : public ConnectionHandler {
public:
    DefaultConnectionHandler(WebServer* server) : server(server) {}

    void handle(Connection& connection) override {
        std::string requestData = connection.read(server->getConfig().bufferSize);
        if (requestData.empty()) return;

        Request request;
        std::istringstream requestStream(requestData);
        std::string methodStr, path, protocol;
        requestStream >> methodStr >> path >> protocol;

        if (methodStr == "GET") request.method = Request::Method::GET;
        else if (methodStr == "POST") request.method = Request::Method::POST;
        else return;

        request.path = path;
        request.parseQueryParams();

        std::string headerLine;
        while (std::getline(requestStream, headerLine) && headerLine != "\r") {
            auto colonPos = headerLine.find(':');
            if (colonPos != std::string::npos) {
                std::string key = headerLine.substr(0, colonPos);
                std::string value = headerLine.substr(colonPos + 2, headerLine.length() - colonPos - 3);
                request.headers[key] = value;
                if (key == "Host") request.host = value;
            }
        }
        request.body = requestData.substr(requestStream.tellg());

        const auto& vhosts = server->getVirtualHosts();
        const VirtualHost* vhost = nullptr;
        if (vhosts.count(request.host)) vhost = &vhosts.at(request.host);
        else if (vhosts.count("")) vhost = &vhosts.at("");

        Response response;
        if (vhost && vhost->routes.count(request.path) && vhost->routes.at(request.path).count(request.method)) {
            response = *vhost->routes.at(request.path).at(request.method)->handle(request);
        } else {
            response.statusCode = 404;
            response.content = "404 Not Found";
            response.setContentType("text/plain");
        }

        std::string responseStr = server->serializeResponse(response);
        connection.write(responseStr);

        server->log(request.host + " " + methodStr + " " + request.path + " " + std::to_string(response.statusCode));
    }

private:
    WebServer* server;
};

void Request::parseQueryParams() {
    auto queryPos = path.find('?');
    if (queryPos != std::string::npos) {
        std::string query = path.substr(queryPos + 1);
        path = path.substr(0, queryPos);
        std::istringstream queryStream(query);
        std::string pair;
        while (std::getline(queryStream, pair, '&')) {
            auto eqPos = pair.find('=');
            if (eqPos != std::string::npos) {
                queryParams[pair.substr(0, eqPos)] = pair.substr(eqPos + 1);
            }
        }
    }
}

void Response::setContentType(std::string_view type) {
    headers["Content-Type"] = std::string{type};
}

void Response::enableCors(std::string_view origin) {
    headers["Access-Control-Allow-Origin"] = std::string{origin};
    headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "*";
}

WebServer::WebServer(Config config, std::shared_ptr<Logger> logger)
    : config(std::move(config)), logger(logger) {
    if (this->config.enableSsl && !this->config.certFile.empty() && !this->config.keyFile.empty()) {
        initializeSsl();
    }
}

WebServer::~WebServer() {
    cleanup();
}

void WebServer::addRoute(std::string_view vhost, std::string_view path, Request::Method method,
                     std::unique_ptr<RequestHandler> handler) {
    std::lock_guard<std::mutex> lock(queueMutex);
    virtualHosts[std::string(vhost)].routes[std::string(path)][method] = std::move(handler);
    logger->log("Added route for vhost '" + std::string(vhost) + "' path '" + std::string(path) + "'", "INFO");
}

bool WebServer::start() {
    if (running) return false;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        logger->log("Failed to initialize Winsock", "ERROR");
        return false;
    }
#endif

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        logger->log("Failed to create socket", "ERROR");
        return false;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(config.host.c_str());
    serverAddr.sin_port = htons(config.port);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        logger->log("Bind failed", "ERROR");
        cleanup();
        return false;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        logger->log("Listen failed", "ERROR");
        cleanup();
        return false;
    }

    running = true;
    for (size_t i = 0; i < config.threadPoolSize; ++i) {
        threadPool.emplace_back(&WebServer::workerThread, this);
    }
    threadPool.emplace_back(&WebServer::acceptConnections, this);

    logger->log("WebServer server started on " + config.host + ":" + std::to_string(config.port) + " (SSL: " + (isSslEnabled() ? "enabled" : "disabled") + ")", "INFO");
    return true;
}

void WebServer::stop() {
    running = false;
    cleanup();
    for (auto& thread : threadPool) {
        if (thread.joinable()) thread.join();
    }
}

void WebServer::setConnectionHandler(std::unique_ptr<ConnectionHandler> handler) {
    connectionHandler = std::move(handler);
}

bool WebServer::checkRateLimit(std::string_view ip) {
    std::lock_guard<std::mutex> lock(rateLimitMutex);
    auto now = std::chrono::steady_clock::now();
    auto& [count, lastReset] = rateLimits[std::string(ip)];
    if (now - lastReset > std::chrono::seconds(60)) {
        count = 0;
        lastReset = now;
    }
    return ++count <= config.rateLimitRequests;
}

std::string WebServer::serializeResponse(const Response& response) {
    std::ostringstream responseStream;
    responseStream << "HTTP/1.1 " << response.statusCode << " ";
    switch (response.statusCode) {
    case 200: responseStream << "OK"; break;
    case 404: responseStream << "Not Found"; break;
    default: responseStream << "Unknown"; break;
    }
    responseStream << "\r\n";
    for (const auto& [key, value] : response.headers) {
        responseStream << key << ": " << value << "\r\n";
    }
    responseStream << "Content-Length: " << response.content.length() << "\r\n\r\n" << response.content;
    return responseStream.str();
}

void WebServer::workerThread() {
    while (running) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCondition.wait(lock, [this] { return !tasks.empty() || !running; });
            if (!running && tasks.empty()) return;
            task = std::move(tasks.front());
            tasks.pop();
        }
        if (connectionHandler) {
            connectionHandler->handle(*task.connection);
        }
    }
}

void WebServer::acceptConnections() {
    while (running) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            if (running) logger->log("Accept failed", "ERROR");
            continue;
        }

        SSL* ssl = nullptr;
        if (config.enableSsl && sslContext) {
            ssl = SSL_new(sslContext);
            SSL_set_fd(ssl, clientSocket);
            if (SSL_accept(ssl) <= 0) {
                logger->log("SSL accept failed", "ERROR");
                SSL_free(ssl);
#ifdef _WIN32
                closesocket(clientSocket);
#else
                close(clientSocket);
#endif
                continue;
            }
        }

        auto connection = std::make_unique<Connection>(clientSocket, ssl, config.enableSsl);
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            tasks.push({std::move(connection)});
        }
        queueCondition.notify_one();
        logger->log("Connection accepted from " + std::string(inet_ntoa(clientAddr.sin_addr)), "INFO");
    }
}

void WebServer::initializeSsl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    sslContext = SSL_CTX_new(TLS_server_method());
    if (!sslContext) {
        logger->log("Failed to create SSL context", "ERROR");
        return;
    }

    if (SSL_CTX_use_certificate_file(sslContext, config.certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger->log("Failed to load certificate file: " + config.certFile, "ERROR");
        SSL_CTX_free(sslContext);
        sslContext = nullptr;
        return;
    }

    if (SSL_CTX_use_PrivateKey_file(sslContext, config.keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        logger->log("Failed to load private key file: " + config.keyFile, "ERROR");
        SSL_CTX_free(sslContext);
        sslContext = nullptr;
        return;
    }

    logger->log("SSL initialized successfully with certificate: " + config.certFile, "INFO");
}

void WebServer::cleanup() {
    if (serverSocket != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(serverSocket);
        WSACleanup();
#else
        close(serverSocket);
#endif
        serverSocket = INVALID_SOCKET;
    }
    if (sslContext) {
        SSL_CTX_free(sslContext);
        sslContext = nullptr;
    }
}

Connection::~Connection() {
    if (ssl && useSsl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (socket != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(socket);
#else
        close(socket);
#endif
    }
}

std::string Connection::read(size_t bufferSize) {
    std::vector<char> buffer(bufferSize);
    int bytesReceived = useSsl && ssl ? SSL_read(ssl, buffer.data(), bufferSize)
                                        : recv(socket, buffer.data(), bufferSize, 0);
    if (bytesReceived <= 0) return "";
    return std::string(buffer.data(), bytesReceived);
}

void Connection::write(std::string_view data) {
    if (useSsl && ssl) {
        SSL_write(ssl, data.data(), data.size());
    } else {
        send(socket, data.data(), data.size(), 0);
    }
}

std::unique_ptr<WebServer> ServerFactory::createDefaultServer(Config config) {
    auto logger = createFileLogger(config.accessLog, config.errorLog);
    auto server = std::make_unique<WebServer>(std::move(config), logger);
    server->setConnectionHandler(createDefaultConnectionHandler(server.get()));
    return server;
}

std::shared_ptr<Logger> ServerFactory::createFileLogger(std::string_view accessLog, std::string_view errorLog) {
    return std::make_shared<FileLogger>(accessLog, errorLog);
}

std::unique_ptr<RequestHandler> ServerFactory::createStaticFileHandler(std::string_view rootDir) {
    class StaticFileHandler : public RequestHandler {
    public:
        StaticFileHandler(std::string root) : rootDir(root) {}
        std::unique_ptr<Response> handle(const Request& request) override {
            std::filesystem::path filePath = rootDir + request.path;
            auto response = std::make_unique<Response>();
            if (std::filesystem::exists(filePath) && !std::filesystem::is_directory(filePath)) {
                std::ifstream file(filePath, std::ios::binary);
                response->content = std::string(std::istreambuf_iterator<char>(file), {});
                response->setContentType("text/plain");
            } else {
                response->statusCode = 404;
                response->content = "404 Not Found";
                response->setContentType("text/plain");
            }
            return response;
        }
    private:
        std::string rootDir;
    };
    return std::make_unique<StaticFileHandler>(std::string(rootDir));
}

std::unique_ptr<ConnectionHandler> ServerFactory::createDefaultConnectionHandler(WebServer* server) {
    return std::make_unique<DefaultConnectionHandler>(server);
}

} // namespace WebServer
