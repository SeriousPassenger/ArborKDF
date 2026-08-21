#include <exception>
#include <iostream>

void run_codec_tests();
void run_crypto_tests();
void run_entropy_tests();

int main() {
    try {
        run_codec_tests();
        run_crypto_tests();
        run_entropy_tests();
        std::cout << "all tests passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
