#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <dirent.h>


#define CMD_PORT 9013 // port for server to set up connection inially
#define BUFFER_SIZE 1024
#define SERVER_IP "127.0.0.1" // IP address of server


// function prototypes
void upload_file(int data_sock, const char* filename);
void download_file(int data_sock, const char* filename);
int handle_data_client(int cmd_sock);
bool file_exists(const char *filename);
void list_Files_In_CurrentDirectory();
void displayCurrentDirectory();
void handle_cd_command(char *command);

int data_port;

int main() {
    int cmd_sock;
    struct sockaddr_in server_addr;
    char command[BUFFER_SIZE];
    char server_response[BUFFER_SIZE];

    // Connect to command socket
    if ((cmd_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Command socket creation failed");
        exit(EXIT_FAILURE);
    }

     int value  = 1;

     //set sock opt, important to handle mutiple addresses

	setsockopt(cmd_sock,SOL_SOCKET,SO_REUSEADDR,&value,sizeof(value)); 

    // define server address, server binds to CMD_port

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CMD_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // convert Ipv4 and IPv6 addresses from text to binary form

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(cmd_sock);
        exit(EXIT_FAILURE);
    }

    // attempt to connect the command socket to the server

    if (connect(cmd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Command socket connection failed");
        close(cmd_sock);
        exit(EXIT_FAILURE);
    }

    // read the server's response into the buffer


    if (read(cmd_sock, server_response, BUFFER_SIZE) > 0) {
        printf("%s\n", server_response);
    }

    while (1) {

        printf("%s","ftp-> ");
        fgets(command, BUFFER_SIZE, stdin);
        command[strcspn(command, "\n")] = '\0';  // Remove newline character

        // if the user presses enter, continue with the loop,
        if(command[0] == '\0'){
            continue;
        }

        char *cmd = strtok(command, " ");   // First argument
        char *filename = strtok(NULL, " "); // Second argument

      
        // if the user input contains two parts
        // we chack for USER PASS STOR RETR CWD and !CWD because we are expecting user to input two strings when they input these in the beginning
        if (cmd && filename) { 
            // if its USER, send the info to server
            if (strcmp(cmd, "USER") == 0) {
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "USER %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
            } 
            // if PASS, send the info to server
            else if (strcmp(cmd, "PASS") == 0) {
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "PASS %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
            } 
            // if STOR, send the info to server, meanwhile check for file existence and authenitcation and at the end, send PORT command to server
            // the function handle_data_client sends the PORT command
            // the PORT command sends the port thats free given by the operating system
            else if(strcmp(cmd, "STOR") == 0) {
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "STOR %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);

                char server_response[BUFFER_SIZE]; //empty string
                recv(cmd_sock , &server_response , sizeof(server_response),0);
              
                send(cmd_sock, "SENDING", strlen("SENDING "), 0);
                
                char user_validity[256]; //empty string
                recv(cmd_sock , &user_validity , sizeof(user_validity),0);
                
            
                if(strcmp(user_validity,"Valid User") == 0 ) { // check if its valid user
                    if(file_exists(filename)){ // check if file exists
                        printf("%s",server_response);
                        // the data client sock is the new socket created via PORT
                        int data_client_sock = handle_data_client(cmd_sock); // handle the data socket, here we close the main socket, create a new socket, send PORT command
                        upload_file(data_client_sock, filename); // function to handle STOR
                        close(data_client_sock);
                        printf("226 Transfer completed");
                    }
                    else{ // if no file, print this message.
                       printf("%s","550 No such file or directory");
                    }
                }
                else{
                    printf("%s",user_validity);
                }
            } 
            // same as STOR, RETR also sends the RETR message, does couple of exchanges with the server and if its valid user, calls the function that handles the PORT command and proceeds with the data transfer in the new socket
            else if (strcmp(cmd, "RETR") == 0) {
                char cmd_buffer[BUFFER_SIZE];  // Send to Server
                snprintf(cmd_buffer, sizeof(cmd_buffer), "RETR %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);

                char new_response[256]; //empty string
                recv(cmd_sock , &new_response , sizeof(new_response),0);
                printf("%s",new_response);

                send(cmd_sock, "SENDING", strlen("SENDING "), 0);
              
                char server_response[256]; //empty string
                recv(cmd_sock , &server_response , sizeof(server_response),0);
                // printf("%s\n",server_response);
                
                if(strcmp(server_response,"Valid User")==0){
                    int data_client_sock = handle_data_client(cmd_sock); // handle the data socket, PORT command sent here
                    download_file(data_client_sock, filename); // function to handle RETR command
                    close(data_client_sock);
                    printf("226 Transfer completed");
                }
            }
            //  sends CWD command to server and server does the needul
            else if (strcmp(cmd, "CWD") == 0) {
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "CWD %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
            }

            // !CWD calls the system directory to change the directory, if there is no direcotry, print the error message

            else if (strcmp(cmd, "!CWD") == 0) {

                if (chdir(filename) < 0) {
                    perror("550 No such file or directory");
                }
                else{
                    printf("200 directory changed to /Users/%s\n",filename);
                }
                continue;
            } 
            else{ // if cmd and filename invalid
                // printf("%s","Invalid command format. Use USER <username> PASS <password> STOR <filename> or RETR <filename>.\n");
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "NOT %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
                char server_response[BUFFER_SIZE];  
                recv(cmd_sock , &server_response , sizeof(server_response),0);
                printf("%s\n",server_response);
                continue;
            }
        } else if(cmd){ // if user inputs only one input, then we check for LIST
        // !LIST, PWD, and QUIT because we are expecting user to input only one string when they input these commands

        // send the LIST command to server
            if (strcmp(cmd, "LIST") == 0) {
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "LIST %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
            }

            // call the function that has code for system directory display for LIST
            else if (strcmp(cmd, "!LIST") == 0) {
                list_Files_In_CurrentDirectory();
                continue;
            }
            // send the PWD command to the server
            else if (strcmp(cmd, "PWD") == 0) {
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "PWD %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
            }
            // call the function that has code for that lists current directory by running the system code
            else if (strcmp(cmd, "!PWD") == 0) {
                displayCurrentDirectory();
                continue; 
            }
            // if QUIT, terminate the session and send the QUIT message to server so that server knows that this client has disconnected 
            else if (strcmp(cmd, "QUIT") == 0) {
               char cmd_buffer[BUFFER_SIZE];  
               snprintf(cmd_buffer, sizeof(cmd_buffer), "QUIT %s", filename);
               send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
               char server_response[BUFFER_SIZE];  
               recv(cmd_sock , &server_response , sizeof(server_response),0);
               printf("%s\n",server_response);
               break;
            }
            else{ // if cmd invalid, then proceed with sending INVALID command to server, server has a block where it handles this
                char cmd_buffer[BUFFER_SIZE];  
                snprintf(cmd_buffer, sizeof(cmd_buffer), "INVALID %s", filename);
                send(cmd_sock, cmd_buffer, strlen(cmd_buffer), 0);
                char server_response[BUFFER_SIZE];  
                recv(cmd_sock , &server_response , sizeof(server_response),0);
                printf("%s\n",server_response);
                continue;
            }
        }

        if (read(cmd_sock, server_response, BUFFER_SIZE) > 0) {  // Any extra message
            printf("%s\n", server_response);
        }
    }
    close(cmd_sock); // close the cmd_sock after everything is over
    return 0;
}

// this function sends PORT command to server
// now client acts as server and server acts as client for opening new socket for file transfer
// client listens for incoming connection
int handle_data_client(int cmd_sock) {
    char commandbuffer[BUFFER_SIZE];
    int port, p1, p2;
    int data_sock;
    struct sockaddr_in data_address;
    socklen_t data_len = sizeof(data_address);

    // Create data socket
    if ((data_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Data socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the data socket to an available port
    data_address.sin_family = AF_INET;
    data_address.sin_addr.s_addr = INADDR_ANY;
    data_address.sin_port = htons(0); // Let the OS choose the port

    if (bind(data_sock, (struct sockaddr*)&data_address, sizeof(data_address)) < 0) {
        perror("Data socket bind failed");
        close(data_sock);
        exit(EXIT_FAILURE);
    }

    // Get the dynamic port assigned
    if (getsockname(data_sock, (struct sockaddr*)&data_address, &data_len) < 0) {
        perror("getsockname failed");
        close(data_sock);
        exit(EXIT_FAILURE);
    }

    // as mentioned in the asignment description, break down the PORT command and send it with IP address and p1 and p2 for PORT, so that the server knows which port to connect to
    port = ntohs(data_address.sin_port);
    p1 = port / 256;
    p2 = port % 256;

    data_port = port;

    // Send the port command


    sprintf(commandbuffer, "PORT 127,0,0,1,%d,%d", p1, p2);
   
    send(cmd_sock, commandbuffer, strlen(commandbuffer), 0);

    // client acts as server now and listens for incming connectoons
    if (listen(data_sock, 1) < 0) {
        perror("Data socket listen failed");
        close(data_sock);
        exit(EXIT_FAILURE);
    }



    // Accept the connection from the server
    int conn_sock = accept(data_sock, (struct sockaddr*)&data_address, &data_len);
    if (conn_sock < 0) {
        perror("Data socket accept failed");
        close(data_sock);
        exit(EXIT_FAILURE);
    }

    // close the data sock and not return the sock of the connected server, which we need to trasnfer files
    close(data_sock);
    return conn_sock;
}

// function that handles the STOR command, opens file in read mode and sends data to server
void upload_file(int data_sock, const char* filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("File open failed");
        close(data_sock);
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        send(data_sock, buffer, bytes_read, 0);
    }

    fclose(file);
    close(data_sock);
}

// function that handles RETR command, opens a file in write mode and writes the data sent my the server into this file
void download_file(int data_sock, const char* filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("File open failed");
        close(data_sock);
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(data_sock, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, bytes_read, file);
    }

    fclose(file);
    close(data_sock);
   
}

// function to check if the file exists
bool file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return true;
    }
    return false;
}

// function to list the files in the current system direcotry
void list_Files_In_CurrentDirectory() {
    DIR *dir;
    struct dirent *entry;

    // Open the current directory
    dir = opendir(".");
    if (dir == NULL) {
        perror("Unable to open directory");
        exit(EXIT_FAILURE);
    }

    printf("%s", "Files in current client directory:\n");

    // Read the directory entries
    while ((entry = readdir(dir)) != NULL) {
        // Skip hidden files (those starting with '.')
        if (entry->d_name[0] == '.') {
            continue;
        }
        printf("%s\n", entry->d_name);
    }

    // Close the directory
    closedir(dir);
}

// functoon to display the path of current direcotry
void displayCurrentDirectory() {
    char buffer[1024]; // Buffer to hold the path
    if (getcwd(buffer, sizeof(buffer)) != NULL) {
        printf("Current Directory: %s\n", buffer);
    } else {
        perror("getcwd() error");
    }
}

// function that handles "CD" command, changes directory if it exists and prints error message if the direcotry does not exist
void handle_cd_command(char *command) {
    if (chdir(command) < 0) {
        perror("chdir failed");
    }	
}