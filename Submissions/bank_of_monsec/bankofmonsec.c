#include <stdio.h>

void login(){
	char password[20];
        char username[20];
        printf("Name: ");
        gets(username);
        printf("Hello, "); 
        printf(username);
        printf("\n");
        printf("password: ");
        gets(password);
}

int main(){
        printf("+----------------------+\n");
        printf("|                      |\n");
        printf("|    Welcome to the    |\n");
        printf("|    Bank of MonSec    |\n");
        printf("|                      |\n");
        printf("+----------------------+\n");
        printf("Please log in to continue.\n\n");
        login();
        printf("Sorry, no flag for you :(\n");
        return 0;
}
