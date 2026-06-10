# Security Engineering - Assignment 6

## Vulnerable Login System in C

This project implements a small vulnerable login system in C.

The purpose of the project is to demonstrate several security attacks that were learned in the course:

1. Bypassing authentication using variable overflow.
2. Bypassing authentication using return address overwrite.
3. Calling a hidden function that prints all usernames and passwords.
4. Recovering a password using a timing attack.

The project is intentionally vulnerable and was written only for academic purposes.

---

## Project Structure

```txt
Security Engineering - Assignment 6/
│
├── src/
│   ├── server.c
│   └── timing_attack.c
│
├── data/
│   └── users.txt
│
├── payloads/
│   ├── variable_overflow_payload.txt
│   ├── return_address_payload.txt
│   └── notes.txt
│
├── docs/
│   ├── README.md
│   └── video_script.md
│
└── bin/
```

---

## Files Explanation

### src/server.c

This is the main vulnerable program.

It includes:

* User registration
* Normal login
* Reading users from a file
* A hidden dump_users function
* Variable overflow demonstration
* Return address overwrite demonstration
* Timing vulnerable login
* Command mode for timing checks

---

### src/timing_attack.c

This file demonstrates the timing attack.

It runs the vulnerable server in command mode and sends password guesses.
For every guess, it reads the time returned by the server.

Because the vulnerable comparison waits after each correct character,
a guess with a longer correct prefix takes more time.

The program uses that information to recover the password one character at a time.

---

### data/users.txt

This file stores the usernames and passwords.

Each line has this format:

```txt
username:password
```

Example:

```txt
admin:secret
```

---

### payloads/variable_overflow_payload.txt

This file contains the payload for the variable overflow attack.

Payload:

```txt
AAAAAAAAAAAAAAAAA
```

The password buffer is 16 bytes.
The 17th character overflows into the authenticated variable.

---

### payloads/return_address_payload.txt

This file contains notes for the return address overwrite payload.

The final payload depends on the offset and target address found in the debugger.

---

### payloads/notes.txt

This file contains explanations, observations, addresses, and notes for the video demonstration.

---

## Compilation

Compile the vulnerable server:

```bash
gcc src/server.c -o bin/server -g -fno-stack-protector -no-pie
```

Compile the timing attack program:

```bash
gcc src/timing_attack.c -o bin/timing_attack -g
```

---

## Running the Program

Run the vulnerable server:

```bash
./bin/server
```

Run one manual timing check:

```bash
./bin/server timing admin s
```

Run another manual timing check:

```bash
./bin/server timing admin se
```

Run the timing attack program:

```bash
./bin/timing_attack
```

---

## Attack 1: Variable Overflow

The vulnerable struct is:

```c
struct LoginData {
    char password[16];
    int authenticated;
};
```

The authenticated variable is initialized to 0.

The vulnerable line is:

```c
strcpy(data.password, user_input);
```

The problem is that strcpy does not check if the input fits inside the destination buffer.

When the input is longer than 16 bytes, it overflows from the password buffer into the authenticated variable.

Payload:

```txt
AAAAAAAAAAAAAAAAA
```

Observed result:

```txt
Before input: authenticated = 0
After input: authenticated = 65
Authentication passed.
```

This means the program entered the protected area without knowing the real password.

---

## Attack 2: Return Address Overwrite

The vulnerable function contains a local stack buffer:

```c
char buffer[64];
```

The vulnerable line is:

```c
strcpy(buffer, input);
```

A long input can overwrite data after the buffer on the stack.

The goal is to use the debugger to inspect the stack layout,
find the offset to the saved return address,
and explain how the payload can redirect the program flow.

Important target functions:

* authenticated_area
* dump_users

The program prints their addresses when it starts.

---

## Attack 3: Calling dump_users

The program contains a function named dump_users.

This function prints the content of:

```txt
data/users.txt
```

The function is not available as a regular menu option.
However, it still exists in memory.

By redirecting the program flow to dump_users,
the attacker can make the program print all saved usernames and passwords.

---

## Attack 4: Timing Attack

The timing vulnerability is caused by an insecure password comparison.

The comparison checks the password character by character.
If a wrong character is found, the function returns immediately.
If a character is correct, the function waits using usleep.

Because of that, guesses with more correct characters at the beginning take more time.

Example measurement:

```txt
Guess: s
Time: about 84039 microseconds

Guess: se
Time: about 176824 microseconds
```

The second guess takes more time because it contains a longer correct prefix.

The timing_attack program uses this timing leak to recover the password.

---

## Debugger Demonstration

The video should include:

1. Running the program normally.
2. Showing successful and failed login.
3. Demonstrating variable overflow.
4. Using the debugger on variable_overflow_login.
5. Disassembling the relevant functions.
6. Showing the vulnerable stack buffer in return_address_vulnerable.
7. Showing the target addresses of authenticated_area and dump_users.
8. Explaining how the return address payload is built.
9. Demonstrating the timing leak.
10. Running the timing attack program.

---

## Important Note

This project is intentionally vulnerable.

The code should not be used as a real login system.
It was created only for a controlled academic assignment in Security Engineering.
