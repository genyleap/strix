#include "strix.hpp"
#include <print>
#include <iostream>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <chrono>
#include <vector>
#include <mutex>

using namespace Strix;

// Utility function to escape JSON strings
std::string escapeJsonString(const std::string& input) {
    std::ostringstream escaped;
    for (char c : input) {
        switch (c) {
        case '"': escaped << "\\\""; break;
        case '\\': escaped << "\\\\"; break;
        case '\n': escaped << "\\n"; break;
        case '\r': escaped << "\\r"; break;
        case '\t': escaped << "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 32 || c == 127) {
                escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
            } else {
                escaped << c;
            }
            break;
        }
    }
    return escaped.str();
}

// In-memory storage for contact messages
struct Message {
    int id;
    std::string name;
    std::string email;
    std::string message;
};

std::vector<Message> messages;
std::mutex messagesMutex;
int nextMessageId = 1;

// In-memory storage for users
struct User {
    int id;
    std::string username;
    std::string password;
};

std::vector<User> users;
std::mutex usersMutex;
int nextUserId = 1;

// Home Page Handler
class HomePageHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request&) override {
        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 200;
        response->content = R"(
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Home - Strix Demo</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-light bg-light">
                    <div class="container-fluid">
                        <a class="navbar-brand" href="/">Strix Demo</a>
                        <div class="collapse navbar-collapse">
                            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                                <li class="nav-item">
                                    <a class="nav-link active" href="/">Home</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/about">About</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/contact">Contact</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/users">Users</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h1 class="display-4">Welcome to Strix</h1>
                    <p class="lead">This is a demo server built with Strix, styled with Bootstrap via CDN.</p>
                    <p>Explore: <a href="/api/info">API</a>, <a href="/contact">Contact Form</a>, or <a href="/users">User List</a>.</p>
                </div>
            </body>
            </html>
        )";
        response->setContentType("text/html");
        return response;
    }
};

// About Page Handler
class AboutPageHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request&) override {
        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 200;
        response->content = R"(
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>About - Strix Demo</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-light bg-light">
                    <div class="container-fluid">
                        <a class="navbar-brand" href="/">Strix Demo</a>
                        <div class="collapse navbar-collapse">
                            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                                <li class="nav-item">
                                    <a class="nav-link" href="/">Home</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link active" href="/about">About</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/contact">Contact</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/users">Users</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h1 class="display-4">About Strix</h1>
                    <p class="lead">Strix is a lightweight C++ web server framework.</p>
                    <p>Built by xAI, this demo showcases its capabilities with HTML and JSON responses.</p>
                </div>
            </body>
            </html>
        )";
        response->setContentType("text/html");
        return response;
    }
};

// Contact Page Handler (GET)
class ContactPageHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request&) override {
        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 200;
        response->content = R"(
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Contact - Strix Demo</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-light bg-light">
                    <div class="container-fluid">
                        <a class="navbar-brand" href="/">Strix Demo</a>
                        <div class="collapse navbar-collapse">
                            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                                <li class="nav-item">
                                    <a class="nav-link" href="/">Home</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/about">About</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link active" href="/contact">Contact</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/users">Users</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h1 class="display-4">Contact Us</h1>
                    <form method="POST" action="/contact" class="needs-validation" novalidate>
                        <div class="mb-3">
                            <label for="name" class="form-label">Name</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="message" class="form-label">Message</label>
                            <textarea class="form-control" id="message" name="message" rows="3" required></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary">Submit</button>
                    </form>
                </div>
            </body>
            </html>
        )";
        response->setContentType("text/html");
        return response;
    }
};

// Contact Form Submission Handler (POST)
class ContactPostHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request& request) override {
        std::string name, email, message;
        auto parseField = [&](const std::string& field, std::string& out) {
            std::string delimiter = field + "=";
            auto start = request.body.find(delimiter);
            if (start != std::string::npos) {
                start += delimiter.length();
                auto end = request.body.find('&', start);
                if (end == std::string::npos) end = request.body.length();
                out = request.body.substr(start, end - start);
            }
        };

        parseField("name", name);
        parseField("email", email);
        parseField("message", message);

        if (name.empty() || email.empty() || message.empty()) {
            auto response = std::make_unique<Strix::Response>();
            response->statusCode = 400;
            response->content = "{\"error\": \"Missing required fields\"}";
            response->setContentType("application/json");
            return response;
        }

        std::lock_guard<std::mutex> lock(messagesMutex);
        messages.push_back({nextMessageId++, name, email, message});

        std::ostringstream json;
        json << "{"
             << "\"status\": \"success\","
             << "\"id\": " << (nextMessageId - 1) << ","
             << "\"name\": \"" << escapeJsonString(name) << "\","
             << "\"email\": \"" << escapeJsonString(email) << "\","
             << "\"message\": \"" << escapeJsonString(message) << "\""
             << "}";

        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 201;
        response->content = json.str();
        response->setContentType("application/json");
        return response;
    }
};

// JSON API Handler for Server Info
class ApiInfoHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request&) override {
        auto now = std::chrono::system_clock::now();
        std::time_t tt = std::chrono::system_clock::to_time_t(now);
        std::ostringstream json;
        json << "{"
             << "\"status\": \"running\","
             << "\"host\": \"127.0.0.1\","
             << "\"port\": 8080,"
             << "\"timestamp\": \"" << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S") << "\","
             << "\"message\": \"Strix server is operational\""
             << "}";

        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 200;
        response->content = json.str();
        response->setContentType("application/json");
        return response;
    }
};

// JSON API Handler for Messages
class ApiMessagesHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request&) override {
        std::lock_guard<std::mutex> lock(messagesMutex);
        std::ostringstream json;
        json << "[";
        for (size_t i = 0; i < messages.size(); ++i) {
            json << "{"
                 << "\"id\": " << messages[i].id << ","
                 << "\"name\": \"" << escapeJsonString(messages[i].name) << "\","
                 << "\"email\": \"" << escapeJsonString(messages[i].email) << "\","
                 << "\"message\": \"" << escapeJsonString(messages[i].message) << "\""
                 << "}";
            if (i < messages.size() - 1) json << ",";
        }
        json << "]";

        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 200;
        response->content = json.str();
        response->setContentType("application/json");
        return response;
    }
};

// User Registration Handler (POST /api/register)
class RegisterHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request& request) override {
        std::string username, password;
        auto parseJsonField = [&](const std::string& field, std::string& out) {
            std::string delimiter = "\"" + field + "\":\"";
            auto start = request.body.find(delimiter);
            if (start != std::string::npos) {
                start += delimiter.length();
                auto end = request.body.find('"', start);
                if (end != std::string::npos) {
                    out = request.body.substr(start, end - start);
                }
            }
        };

        parseJsonField("username", username);
        parseJsonField("password", password);

        std::cerr << "DEBUG: Register attempt - username: " << username << ", password: " << password << std::endl;

        if (username.empty() || password.empty()) {
            auto response = std::make_unique<Strix::Response>();
            response->statusCode = 400;
            response->content = "{\"error\": \"Missing username or password\"}";
            response->setContentType("application/json");
            return response;
        }

        std::lock_guard<std::mutex> lock(usersMutex);
        for (const auto& user : users) {
            if (user.username == username) {
                auto response = std::make_unique<Strix::Response>();
                response->statusCode = 409;
                response->content = "{\"error\": \"Username already exists\"}";
                response->setContentType("application/json");
                return response;
            }
        }

        users.push_back({nextUserId++, username, password});
        std::cerr << "DEBUG: User added - ID: " << (nextUserId - 1) << ", Total users: " << users.size() << std::endl;

        std::ostringstream json;
        json << "{"
             << "\"status\": \"success\","
             << "\"id\": " << (nextUserId - 1) << ","
             << "\"username\": \"" << escapeJsonString(username) << "\""
             << "}";

        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 201;
        response->content = json.str();
        response->setContentType("application/json");
        return response;
    }
};

// Users List Handler (GET /users)
class UsersListHandler : public Strix::RequestHandler {
public:
    std::unique_ptr<Strix::Response> handle(const Strix::Request&) override {
        std::lock_guard<std::mutex> lock(usersMutex);
        std::cerr << "DEBUG: Rendering users list - Total users: " << users.size() << std::endl;

        std::ostringstream html;
        html << R"(
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Users - Strix Demo</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-light bg-light">
                    <div class="container-fluid">
                        <a class="navbar-brand" href="/">Strix Demo</a>
                        <div class="collapse navbar-collapse">
                            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                                <li class="nav-item">
                                    <a class="nav-link" href="/">Home</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/about">About</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link" href="/contact">Contact</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link active" href="/users">Users</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>
                <div class="container mt-4">
                    <h1 class="display-4">Registered Users</h1>
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th scope="col">ID</th>
                                <th scope="col">Username</th>
                            </tr>
                        </thead>
                        <tbody>
        )";
        for (const auto& user : users) {
            html << "<tr>"
                 << "<td>" << user.id << "</td>"
                 << "<td>" << escapeJsonString(user.username) << "</td>"
                 << "</tr>";
        }
        html << R"(
                        </tbody>
                    </table>
                </div>
            </body>
            </html>
        )";

        auto response = std::make_unique<Strix::Response>();
        response->statusCode = 200;
        response->content = html.str();
        response->setContentType("text/html");
        return response;
    }
};

int main() {
    try {
        Strix::Config config;
        auto server = Strix::ServerFactory::createDefaultServer(std::move(config));

        config.host = "127.0.0.1";
        config.port = 8080;
        config.threadPoolSize = 2;
        if(server->isSslEnabled()) {
            config.certFile = "server.crt";
            config.keyFile = "server.key";
            config.enableSsl = false;
        }

        config.accessLog = "access.log";
        config.errorLog = "error.log";
        config.maxConnections = 100;
        config.bufferSize = 8192;


        // Home page
        server->addRoute("", "/", Strix::Request::Method::GET,
                         std::make_unique<HomePageHandler>());
        server->addRoute("127.0.0.1", "/", Strix::Request::Method::GET,
                         std::make_unique<HomePageHandler>());

        // About page
        server->addRoute("", "/about", Strix::Request::Method::GET,
                         std::make_unique<AboutPageHandler>());
        server->addRoute("127.0.0.1", "/about", Strix::Request::Method::GET,
                         std::make_unique<AboutPageHandler>());

        // Contact page (GET)
        server->addRoute("", "/contact", Strix::Request::Method::GET,
                         std::make_unique<ContactPageHandler>());
        server->addRoute("127.0.0.1", "/contact", Strix::Request::Method::GET,
                         std::make_unique<ContactPageHandler>());

        // Contact form submission (POST)
        server->addRoute("", "/contact", Strix::Request::Method::POST,
                         std::make_unique<ContactPostHandler>());
        server->addRoute("127.0.0.1", "/contact", Strix::Request::Method::POST,
                         std::make_unique<ContactPostHandler>());

        // JSON API - Server Info
        server->addRoute("", "/api/info", Strix::Request::Method::GET,
                         std::make_unique<ApiInfoHandler>());
        server->addRoute("127.0.0.1", "/api/info", Strix::Request::Method::GET,
                         std::make_unique<ApiInfoHandler>());

        // JSON API - Messages
        server->addRoute("", "/api/messages", Strix::Request::Method::GET,
                         std::make_unique<ApiMessagesHandler>());
        server->addRoute("127.0.0.1", "/api/messages", Strix::Request::Method::GET,
                         std::make_unique<ApiMessagesHandler>());

        // User Registration (POST)
        server->addRoute("", "/api/register", Strix::Request::Method::POST,
                         std::make_unique<RegisterHandler>());
        server->addRoute("127.0.0.1", "/api/register", Strix::Request::Method::POST,
                         std::make_unique<RegisterHandler>());

        // Users List (GET)
        server->addRoute("", "/users", Strix::Request::Method::GET,
                         std::make_unique<UsersListHandler>());

        server->addRoute("127.0.0.1", "/users", Strix::Request::Method::GET,
                         std::make_unique<UsersListHandler>());

        if (!server->start()) {
            std::cerr << "Failed to start server.\n";
            return 1;
        }

        const char* protocol = server->isSslEnabled() ? "https" : "http";
        std::cout << "Server running at " << protocol << "://" << config.host << ":" << config.port
                  << "/ (SSL Enabled: " << (server->isSslEnabled() ? "Yes" : "No") << "). Press Enter to stop...\n";
        std::cin.get();
        server->stop();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }




    return 0;
}
