# Implementation of the File Transfer Protocol

This GitHub repo contains the solution for Project 1 for the Computer Networks course taught by Professor Yasir Zaki at NYU Abu Dhabi. Here, we implement a simple file transfer protocol designed to handle multiple concurrent client connections and file transfers. The team members for this project are Avinash Gyawali and Aadim Nepal.

## Running the Repo

To run the code in your terminal, please follow these steps:
1. **Clone the Repository:**

   ```bash
   git clone https://github.com/Tauke190/ComputerNetworksHW1.git
   ```



1. **Navigate to the Server and Client Directories:**
   
   Inspect the directories closely. The server directory contains:
   - Three subdirectories: `Bob`, `Harry`, and `Ron`
   - A text file: `users.txt`

   The subdirectories `Bob`, `Harry`, and `Ron` are for the authenticated users stored on the server. The `users.txt` file contains usernames and passwords that the server authenticates before running the program.

## How to Proceed

1. **Open Four Terminals:**
   - One for the server
   - Three for the clients: `Bob`, `Harry`, and `Ron`

2. **Run the Server Code:**
   - Navigate to the server directory:
     ```bash
     cd server
     ```
   - Compile the makefile.

3. **Run the Client Code:**
   - In each client terminal, navigate to the client directory:
     ```bash
     cd client
     ```
   - Compile the makefile for all three clients.

4. **Start Authenticating:**
   - Follow the procedures displayed by the terminal. Typically, you will input:
     - `USER <username>`
     - `PASS <password>`
     - Commands like `RETR <filename>`, `STOR <filename>`, `CWD <directory>`, `!CWD <directory>`, `LIST <directory>`, `!LIST <directory>`, `QUIT`

The code should handle concurrent connections smoothly.

## Limitations and Assumptions

- **Directory Changes:**
  - Once the client changes the server directory, it cannot revert.
  - Once you change the client directory, you cannot revert.

- **File Overwrites:**
  - If the client attempts to send a filename that already exists, the new file overwrites the existing file.

- **Users.txt Format:**
  - The `users.txt` file should not have a comma between username and password.
  - Each username and password pair should be on one line, separated by a space. Example:
    ```
    Aadim Nepal
    Avinash Gyawali
    ```

## Design Choice for Port

- **Port Selection:**
  - We used port `9013` instead of the default ports `21` and `20` due to availability issues on MacOS.
  - If you encounter a "cannot bind to address" error, change the port by navigating to:
    ```c
    #DEFINE CMD_PORT 9013
    ```
    - You can try different port numbers if necessary.

- **Implementation of PORT Command:**
  - The client sends a PORT command to the server before initiating a new TCP connection for file transfer.
  - We use a random free port provided by the OS instead of implementing `N+i`.
  - This approach was discussed and approved by both the professor and the TA.

# CNHW1
