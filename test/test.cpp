#include "catch_with_main.hpp"

#include <iostream>

uint32_t Factorial(uint32_t number) {
    return number <= 1 ? 1 : number * Factorial(number - 1);
}

TEST_CASE( "Factorial of 0 is 1 (fail)", "[single-file]" ) {
    REQUIRE( Factorial(0) == 1 );
}

TEST_CASE( "Check Factor Result", "[factorial-test]" ) {
    REQUIRE( Factorial(1) == 1 );
    REQUIRE( Factorial(2) == 2 );
    REQUIRE( Factorial(3) == 6 );
}
