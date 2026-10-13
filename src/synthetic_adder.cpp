#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Expected two integers\n";
        return 2;
    }
    try {
        const long long left = std::stoll(argv[1]);
        const long long right = std::stoll(argv[2]);
        std::cout << (left + right) << '\n';
        return 0;
    } catch (const std::exception&) {
        std::cerr << "Invalid integers\n";
        return 2;
    }
}
