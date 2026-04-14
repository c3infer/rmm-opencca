#ifndef DEBUG_TEST_H
#define DEBUG_TEST_H

#include <stdio.h>

#define INFO(...) do { printf("[INFO] "); printf(__VA_ARGS__); } while(0)

#endif
