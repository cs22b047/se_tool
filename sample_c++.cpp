#include "crow_all.h"
#include <string>

int main() {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/add")([](const crow::request& req) {
        int value = 10;
        if (auto num = req.url_params.get("num")) {
            // Potential vulnerability: directly converting user input
            value += std::stoi(num);  
        }
        return crow::response(std::to_string(value));
    });

    app.port(8080).multithreaded().run();
}