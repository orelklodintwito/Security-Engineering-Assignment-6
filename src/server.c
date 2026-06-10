#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// This is the file where all users are saved. Each line in the file has the following format: username:password
#define USERS_FILE "data/users.txt" 

// These constants define the maximum sizes that are used in the program. I used constants instead of writing the numbers directly in the code, so it will be easier to change them later if needed.
#define MAX_USERNAME 64
#define MAX_PASSWORD 128
#define MAX_LINE 256

// This function removes the newline character that fgets usually keeps. Without removing it, string comparison may fail because the string  will contain an extra '\n' at the end.
void remove_newline(char *str)
{
    str[strcspn(str, "\n")] = '\0';
}

//    Prints a simple separator line. I use it only to make the output easier to read.
void print_separator()
{
    printf("----------------------------------------\n");
}

/*
    This function prints the content of the users file.
    It is not shown as a regular option in the menu,
    because a real system should not allow a normal user
    to see all usernames and passwords.
    In this assignment, this function is used as a target function.
    It helps demonstrate what an attacker would want the program to run.
*/
void dump_users()
{
    FILE *file;
    char line[MAX_LINE];

    // Open the users file for reading. If the file does not exist, or there is no permission, fopen will return NULL.
    file = fopen(USERS_FILE, "r");

    printf("\n");
    print_separator();
    printf("USERS FILE CONTENT\n");
    print_separator();

    //Check if the file was opened successfully. If not, we cannot continue reading from it.
    if (file == NULL) {
        printf("Could not open users file.\n");
        return;
    }

    //Read the file line by line and print each line to the screen.
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }

    //Close the file after finishing the reading.
    fclose(file);

    print_separator();
    printf("END OF FILE\n");
    print_separator();
}

//This function represents the protected area of the system. The user should reach this area only after a successful login.
void authenticated_area()
{
    printf("\n");
    print_separator();
    printf("Authentication passed.\n");
    printf("Welcome to the protected area.\n");
    print_separator();
}

void win_authenticated() {
    authenticated_area();
    exit(0);
}

void win_dump_users() {
    dump_users();
    exit(0);
}

/*
    This function searches for a username inside the users file.
    Parameters:
    username        - the username we want to search for.
    password_output - the array where the found password will be copied.
    output_size     - the size of the output array.
    Return value:
    1 if the username was found.
    0 if the username was not found or if the file could not be opened.
*/
int get_password_by_username(const char *username, char *password_output, int output_size)
{
    FILE *file;
    char line[MAX_LINE];
    char file_username[MAX_USERNAME];
    char file_password[MAX_PASSWORD];

    //Open the users file for reading.
    file = fopen(USERS_FILE, "r");

    if (file == NULL) {
        printf("Could not open users file.\n");
        return 0;
    }

    // Go over the file line by line.  Each line should be in this format: username:password
    while (fgets(line, sizeof(line), file) != NULL) {

        // sscanf splits the line into two parts. Everything before ':' is copied into file_username. Everything after ':' is copied into file_password. The numbers in the format limit the amount of characters that can be copied, so the arrays will not overflow here.
        if (sscanf(line, "%63[^:]:%127s", file_username, file_password) == 2) {

            // If the username from the file is equal to the username  that was given to the function, we found the correct user.
            if (strcmp(username, file_username) == 0) {

                // Copy the password into the output array. The last cell is set to '\0' to make sure the string is always properly terminated.
                strncpy(password_output, file_password, output_size - 1);
                password_output[output_size - 1] = '\0';

                fclose(file);
                return 1;
            }
        }
    }

    // If we reached this point, the username was not found in the file.
    fclose(file);
    return 0;
}

//Registers a new user into the system. The function asks the user to enter a username and a password, and then appends them to the users file.

void register_user()
{
    FILE *file;
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];

    printf("Choose username: ");
    fgets(username, sizeof(username), stdin);
    remove_newline(username);

    printf("Choose password: ");
    fgets(password, sizeof(password), stdin);
    remove_newline(password);

    //Basic validation. A user should not be created with an empty username or password.
    if (strlen(username) == 0 || strlen(password) == 0) {
        printf("Username and password cannot be empty.\n");
        return;
    }

    // Open the file in append mode. This means the new user will be added to the end of the file,without deleting the existing users.
    file = fopen(USERS_FILE, "a");

    if (file == NULL) {
        printf("Could not open users file.\n");
        return;
    }

    //Save the new user in the file in a simple format: username:password
    fprintf(file, "%s:%s\n", username, password);

    fclose(file);

    printf("User registered successfully.\n");
}

/*
    Regular login function.
    The user enters a username and password.
    The program reads the real password from the file,
    and then compares it with the password that the user entered.
*/
void normal_login()
{
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char real_password[MAX_PASSWORD];

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    remove_newline(username);

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    remove_newline(password);

    // If the username does not exist in the file, there is no reason to compare passwords.
    if (get_password_by_username(username, real_password, sizeof(real_password)) == 0) {
        printf("Login failed.\n");
        return;
    }

    //Compare the password entered by the user with the real password that was found in the file.
    if (strcmp(password, real_password) == 0) {
        authenticated_area();
    } else {
        printf("Login failed.\n");
    }
}

/*
    Attack 1:
    Variable overflow.
    In this example, the password buffer and the authenticated variable
    are placed next to each other inside the same struct.
    The problem is that strcpy does not check the destination size.
    If the input is longer than the password buffer, it may continue
    writing into the next field in memory and change authenticated.
    This demonstrates why unsafe copying functions can be dangerous.
*/
void variable_overflow_login()
{
    // This struct contains a small password buffer  and an integer that represents the login status.
    struct LoginData {
        char password[16];
        int authenticated;
    };

    struct LoginData data;
    char user_input[256];

    //Clear the struct so it will not contain random values from memory.
    memset(&data, 0, sizeof(data));

    //At the beginning, the user is not authenticated.
    data.authenticated = 0;

    printf("\nVariable overflow demo\n");
    printf("Before input: authenticated = %d\n", data.authenticated);

    // Read input from the user. user_input is bigger than the password field inside the struct.
    printf("Enter password input: ");
    fgets(user_input, sizeof(user_input), stdin);
    remove_newline(user_input);

    //Vulnerable line:  strcpy copies the input without checking if it fits inside password.   If the input is too long, it can overwrite memory after password.
    strcpy(data.password, user_input);

    //Print the value after the copy to see if it changed.
    printf("After input: authenticated = %d\n", data.authenticated);

    // If authenticated became different from 0, the program will think that the user is logged in.
    if (data.authenticated != 0) {
        authenticated_area();
    } else {
        printf("Access denied.\n");
    }
}

/*
    Attack 2:
    Stack buffer overflow demonstration.
    This function has a local stack buffer with a fixed size of 64 bytes.
    A payload is copied into it using memcpy.
    Since memcpy copies the number of bytes we give it,
    a payload that is larger than the local buffer can overwrite
    data that is stored after the buffer on the stack.
    In this assignment, this vulnerability is used to demonstrate
    how the saved return address can be overwritten and how the program
    can be redirected to another function.
    This is only for learning purposes.
    In real code, this kind of copy should be avoided.
*/
void return_address_vulnerable(unsigned char *input, size_t input_len) {
    char buffer[64];

    printf("\nInside vulnerable function.\n");
    printf("Local buffer address: %p\n", (void *)buffer);
    printf("Buffer size: %zu bytes\n", sizeof(buffer));
    printf("Payload size: %zu bytes\n", input_len);

    /*
        Vulnerable copy:
        memcpy copies input_len bytes into a 64 byte buffer.
        If input_len is larger than 64, it may overwrite the saved return address.
    */
    memcpy(buffer, input, input_len);

    printf("Function returned normally.\n");
}

void return_address_demo() {
    unsigned char input[512];
    char payload_path[256];
    FILE *payload_file;
    size_t bytes_read;

    printf("\nReturn address overwrite demo\n");

    printf("Target function authenticated_area address: %p\n", (void *)authenticated_area);
    printf("Target function dump_users address: %p\n", (void *)dump_users);

    printf("Clean target win_authenticated address: %p\n", (void *)win_authenticated);
    printf("Clean target win_dump_users address: %p\n", (void *)win_dump_users);

    printf("Enter payload file path: ");
    fgets(payload_path, sizeof(payload_path), stdin);
    remove_newline(payload_path);

    payload_file = fopen(payload_path, "rb");
    if (payload_file == NULL) {
        printf("Could not open payload file.\n");
        return;
    }

    bytes_read = fread(input, 1, sizeof(input), payload_file);
    fclose(payload_file);

    printf("Read %zu bytes from payload file.\n", bytes_read);

    return_address_vulnerable(input, bytes_read);
}
/*
    Insecure password comparison.
    The comparison stops immediately when the first wrong character is found.
    Also, the function waits a short time after every correct character.
    Because of that, the running time can reveal how many first characters
    of the guessed password were correct.
    This is called a timing leak.
*/
int insecure_password_compare(const char *real_password, const char *guess)
{
    int i;

    // Compare the two strings character by character until one of them reaches the end.
    for (i = 0; real_password[i] != '\0' && guess[i] != '\0'; i++) {

        //  If the current character is wrong, the function returns immediately.  This early return creates a timing difference.
        if (real_password[i] != guess[i]) {
            return 0;
        }

        //    If the current character is correct,  wait a little bit. The sleep is added on purpose to make the timing leak visible.
    
        usleep(80000);
    }

    // If both strings ended at the same position, it means the two passwords are equal.
    if (real_password[i] == '\0' && guess[i] == '\0') {
        return 1;
    }

    //  If one string ended before the other, the passwords are not equal.
    return 0;
}

/*
    This function measures how long a password check takes.
    Parameters:
    username     - the username we want to check.
    guess        - the password guess.
    login_result - output parameter that stores whether the login succeeded.
    Return value:
    The elapsed time in microseconds.
*/
long measure_timing_check(const char *username, const char *guess, int *login_result)
{
    char real_password[MAX_PASSWORD];
    struct timespec start_time;
    struct timespec end_time;
    long elapsed_microseconds;

    // First, get the real password of the user from the file.  If the username does not exist, the login result is failed.
    if (get_password_by_username(username, real_password, sizeof(real_password)) == 0) {
        *login_result = 0;
        return 0;
    }

    // Save the start time before checking the password. CLOCK_MONOTONIC is good for measuring elapsed time,  because it is not affected by changes in the system clock.
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Run the vulnerable password comparison.
    *login_result = insecure_password_compare(real_password, guess);

    //Save the end time after the password check.
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    //  Calculate the time difference in microseconds.
    elapsed_microseconds =
        (end_time.tv_sec - start_time.tv_sec) * 1000000L +
        (end_time.tv_nsec - start_time.tv_nsec) / 1000L;

    return elapsed_microseconds;
}

/*
    Manual demo for the timing vulnerability.
    The user enters a username and a password guess.
    The program checks the guess and prints both the login result
    and the time it took to check the password.
*/
void timing_login_demo()
{
    char username[MAX_USERNAME];
    char guess[MAX_PASSWORD];
    long elapsed;
    int result;

    printf("\nTiming attack vulnerable login\n");

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    remove_newline(username);

    printf("Password guess: ");
    fgets(guess, sizeof(guess), stdin);
    remove_newline(guess);

    // Measure the time of the password check.

    elapsed = measure_timing_check(username, guess, &result);

    // Print whether the login succeeded or failed.
    if (result) {
        printf("Login success.\n");
    } else {
        printf("Login failed.\n");
    }

    // Print the measured time. This helps demonstrate that the response time leaks information.
    printf("Measured time: %ld microseconds\n", elapsed);
}

// Prints the main menu of the program. Each number activates a different feature or demo.
void print_menu()
{
    printf("\n");
    printf("========== Vulnerable Login System ==========\n");
    printf("1. Register\n");
    printf("2. Normal login\n");
    printf("3. Variable overflow login\n");
    printf("4. Return address overwrite demo\n");
    printf("5. Timing vulnerable login\n");
    printf("6. Exit\n");
    printf("Choose option: ");
}

/*
    Command mode is used later by timing_attack.c.
    Instead of opening the regular menu,
    the program can be run directly from the command line.
    Example:
    ./bin/server timing admin sec
    In this case:
    argv[1] is "timing"
    argv[2] is the username
    argv[3] is the password guess
*/
int handle_command_mode(int argc, char *argv[])
{
    long elapsed;
    int result;

    // Check if the program received exactly 4 arguments and if the first argument is "timing".
   
    if (argc == 4 && strcmp(argv[1], "timing") == 0) {

        //Run the timing check with the username and guess that were received from the command line.
   
        elapsed = measure_timing_check(argv[2], argv[3], &result);

        // Print the result in a simple format, so another program can read it easily.
        printf("result=%d\n", result);
        printf("time=%ld\n", elapsed);

        return 1;
    }

    // If this is not command mode, return 0 and continue to the regular menu.
    return 0;
}

/*
    The main function of the program.
    First, it checks if the program was started in command mode.
    If not, it opens the regular menu and waits for user input.
*/
int main(int argc, char *argv[])
{
    int choice;
    char input_line[32];

    //If command mode was used, handle it and exit the program.
    if (handle_command_mode(argc, argv)) {
        return 0;
    }
 
    //Print basic information when the program starts. The addresses are printed for the assignment demonstration.
    printf("Program loaded.\n");
    printf("authenticated_area address: %p\n", (void *)authenticated_area);
    printf("dump_users address:        %p\n", (void *)dump_users);
    printf("win_authenticated address: %p\n", (void *)win_authenticated);
    printf("win_dump_users address:    %p\n", (void *)win_dump_users);

    // Main menu loop.  The loop continues until the user chooses option 6.
    while (1) {
        print_menu();

        //Read the user's menu choice as a string, then convert it to an integer using atoi.
        fgets(input_line, sizeof(input_line), stdin);
        choice = atoi(input_line);

        //Run the correct action according to the user's choice.
        if (choice == 1) {
            register_user();
        } else if (choice == 2) {
            normal_login();
        } else if (choice == 3) {
            variable_overflow_login();
        } else if (choice == 4) {
            return_address_demo();
        } else if (choice == 5) {
            timing_login_demo();
        } else if (choice == 6) {
            printf("Goodbye.\n");
            break;
        } else {
            printf("Invalid option.\n");
        }
    }

    return 0;
}