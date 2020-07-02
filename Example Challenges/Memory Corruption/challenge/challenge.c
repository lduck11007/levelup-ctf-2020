#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vulnerable() {
    // ============================
    // Put your challenge code here
    // ============================

    // Print Flag on completion
    system("cat flag.txt");
    // ============================
};

int main(int argc, char** argv) {
    
    vulnerable();

    return 0;
}