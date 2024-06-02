#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <dirent.h>
#include <ctype.h>


#define USERMAX 1024  // max number of users that can be read from file
#define MAX_LENGTH 256

#define CMD_PORT 9013 // 21, 20 not available, so we connect to 9013
#define CONNECT_PORT 5025 // when establishing new connection for file transfer, server binds to this port
#define BUFFER_SIZE 1024

// function prototypes
void handle_client(int cmd_sock , char buffer[BUFFER_SIZE]);
void handle_file_store(int data_sock, const char* filename);
void handle_file_retrieve(int data_sock, const char* filename);
void handle_User_Command(int i, char *resDat);
void handle_Pass_Command(int i, char *resDat);
bool isUserAuthenticated(int i) ;
bool file_exists(const char *filename);
char* list_Files_In_Current_Directory();
char* get_Current_Directory_Path();
void handle_cd_command(char *command);
void process_Input(const char *input_string, char **cmd, char **arg);
void load_User_from_file();
void set_user(int i, char *resDat, int n);
void logged_in(int i);
void not_logged_in(int i);
char* append_to_buffer(char *buffer, size_t *buffer_size, size_t *buffer_length, const char *str);
void ensure_arg_termination(char **arg, char *input_copy, char **cmd);
void ensure_arg_termination(char **arg, char *input_copy, char **cmd);
bool first_step_authenticate(int i);
bool second_step_authenticate(int i);



char * server_root; 
// structure to keep track of clients
struct Client{
    int indexofuser;
    int userDataport;
    bool username;
    bool password;
    char currDir[256];
    char usernameString[256];
    bool hasauthenticated;
};

// structure to keep track of user name and password to load
struct Account { 
  char user[256];
  char pw[256];
};

// structure to keep track of client data
struct Client connectedclients[FD_SETSIZE];

// strcuture to keep track of usernames and password
static struct Account AccountFile[USERMAX];

// to keep track of the users
int userCount = 0;

int main()
{
  server_root  = get_Current_Directory_Path(); // Get the server root directory
  load_User_from_file(); // load username and password into Account structure


    // create a socket
	int server_socket = socket(AF_INET,SOCK_STREAM,0);
	printf("Server fd = %d \n",server_socket);
	
	//check for fail error
	if(server_socket<0)
	{
		perror("socket:");
		exit(EXIT_FAILURE);
	}

	//setsock
	int value  = 1;
	setsockopt(server_socket,SOL_SOCKET,SO_REUSEADDR,&value,sizeof(value)); 

	
    // define server address
	struct sockaddr_in server_address;
	bzero(&server_address,sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(CMD_PORT);
	server_address.sin_addr.s_addr = INADDR_ANY;

    // bind the socket to server address
	if(bind(server_socket, (struct sockaddr*)&server_address,sizeof(server_address))<0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
    
    // listen for incoming connections
	if(listen(server_socket,5)<0)
	{
		perror("listen failed");
		close(server_socket);
		exit(EXIT_FAILURE);
	}
	

	//DECLARE 2 fd sets (file descriptor sets : a collection of file descriptors)
	fd_set all_sockets;
	fd_set ready_sockets;


	//zero out/iniitalize our set of all sockets
	FD_ZERO(&all_sockets);

	//adds one socket (the current socket) to the fd set of all sockets
	FD_SET(server_socket,&all_sockets);


	printf("Server is listening...\n");

	while(1)
	{		
		//so that is why each iteration of the loop, we copy the all_sockets set into that temp fd_set
		ready_sockets = all_sockets;

		if(select(FD_SETSIZE,&ready_sockets,NULL,NULL,NULL)<0)
		{
			// perror("select error");
			exit(EXIT_FAILURE);
		}

		for(int fd = 0 ; fd < FD_SETSIZE; fd++)
		{
			//check to see if that fd is SET
			if(FD_ISSET(fd,&ready_sockets))
			{
        // if the fd is the current server socket listening for new connection
				if(fd==server_socket)
				{
					//accept that new connection
					int client_sd = accept(server_socket,0,0);
					printf("Client Connected fd = %d \n",client_sd);
					//add the newly accepted socket to the set of all sockets that we are watching
					FD_SET(client_sd,&all_sockets);

          char message[BUFFER_SIZE] = "220 Service ready for new user\nUSER <username>\nPASS <password>\nSTOR <filename>\nRETR <filename> \nLIST : List server directory files\n!LIST :List client directory files\nPWD : Show server path\n!PWD : Show client path \nCWD : Change directory in server\n!CWD : Change directory in client\n QUIT : quit ";
          send(client_sd,message,sizeof(message),0);
				}
				//2nd case: when the socket that is ready to read from is one from the all_sockets fd_set
				//in this case, we just want to read its data
				else
				{
          char buffer[256];
          bzero(buffer,sizeof(buffer));
          int bytes = recv(fd,buffer,sizeof(buffer),0);

          if(bytes==0)   //client has closed the connection
          {
            printf("connection closed from client side \n");
            connectedclients[fd].username = false;
            connectedclients[fd].username = false;
            connectedclients[fd].hasauthenticated = false;
            close(fd);
            FD_CLR(fd,&all_sockets);  // remove the socket from the list of file descriptors that we are watching
          }
          else{
             handle_client(fd,buffer);
          }
				}
			}
		}
	}
// free up sockets in case while loop comes to this point.
  free(server_root);
	close(server_socket);
	return 0;
}

// this function handles client input sent from the client socket
void handle_client(int cmd_sock , char *buffer){
    struct sockaddr_in data_addr;
    int data_sock = 0;
    int data_port;

    bool isupload;
    char filename[20];
    
    char *cmd = NULL;
    char *arg = NULL;
    process_Input(buffer, &cmd, &arg); // breakdown the input to cmd and arg, cmd contains the first input and arg second input in the same input
    if (strcmp(cmd, "STOR") == 0) // if client sends STOR command
    {
        printf("Received STOR command: %s\n", arg);
        if (isUserAuthenticated(cmd_sock)) { // check for authentication
            isupload = true;
            strcpy(filename,arg);
            // receive the port command and send PORT command success message. 
            char message_1[BUFFER_SIZE] = "200 PORT command successful\n150 File status okay; about to open. data connection\n\0";
            send(cmd_sock,message_1, strlen(message_1), 0);
            char new_response[256]; 
            recv(cmd_sock , &new_response , sizeof(new_response),0);
            char corResponse[BUFFER_SIZE] = "Valid User"; // If it is authenticated user
            send(cmd_sock, corResponse, sizeof(corResponse), 0);
        }
        else{
            // if not authenticated, send not logged in message.
          char message_1[BUFFER_SIZE] = "530 Not logged in.";
          send(cmd_sock,message_1, strlen(message_1), 0);
          char new_response[256]; 
          recv(cmd_sock , &new_response , sizeof(new_response),0);
          char corResponse[BUFFER_SIZE] = "530 Not logged in.";
          send(cmd_sock, corResponse, sizeof(corResponse), 0);
        }
    }
    if (strcmp(cmd, "RETR") == 0) // if the client sends RETR message
    {
      printf("Received RETR command: %s\n", arg);
      if (isUserAuthenticated(cmd_sock)) { // check for authentication
          if(chdir(connectedclients[cmd_sock].currDir) >= 0){ // If file exists in the server
            if(file_exists(arg)){
              isupload = false;
              strcpy(filename,arg);
              // receve and send PORT command
              char message_1[BUFFER_SIZE] = "200 PORT command successful\n150 File status okay; about to open. data connection\n\0";
              send(cmd_sock,message_1, strlen(message_1), 0);
              char new_response[256]; 
              recv(cmd_sock , &new_response , sizeof(new_response),0);
              char corResponse[BUFFER_SIZE] = "Valid User\0";
              send(cmd_sock, corResponse, sizeof(corResponse), 0);
             
            }
            else{ // if the file does not exists, send no such file message to client
                char corResponse[BUFFER_SIZE] = "550 No such file or directory\0";
                send(cmd_sock, corResponse, sizeof(corResponse), 0);
            }
            chdir(server_root); // change directory to root because by design of our program, the server is always at the root and only goes to specified folders during data transfer and instantanesouly reverts back to the root
          }
          else{ // if cant change directory, no such file exists.
                char corResponse[BUFFER_SIZE] = "550 No such file or directory\0";
                send(cmd_sock, corResponse, sizeof(corResponse), 0);
          }
      }
      else{ // if not authenticated, send not logged in message
        char corResponse[BUFFER_SIZE] = "530 Not logged in.";
        send(cmd_sock, corResponse, sizeof(corResponse), 0);
      }
    }
    if (strcmp(cmd, "USER") == 0) 
    {
        connectedclients[cmd_sock].hasauthenticated = false; // a flag to keep track, just because you input USER info does not mean that you have logged in
        // connectedclients[cmd_sock].username = false; // Automatically logs out the  user if the client wants to login with the different user
        // connectedclients[cmd_sock].password = false;
        printf("Received USER command: %s\n", arg);
        handle_User_Command(cmd_sock,arg); // arg = username, calls a functions that handles this command
    }
    if(strcmp(cmd, "PASS") == 0) 
    {
        printf("Received PASS command: %s\n", arg);
        handle_Pass_Command(cmd_sock,arg); // arg = password, // calls a function that handles PASS command
    }
    if(strcmp(cmd, "QUIT") == 0) 
    {
        // if QUIT, send service closing message to client and update the flags. 
      printf("Received QUIT command: %s\n", arg);
      char corResponse[BUFFER_SIZE] = "221 Service closing control connection\n\0";
      send(cmd_sock, corResponse, sizeof(corResponse), 0);
      connectedclients[cmd_sock].username = false;
      connectedclients[cmd_sock].username = false;
      connectedclients[cmd_sock].hasauthenticated = false;
      // close(data_sock);
      // close(cmd_sock);
    }
    if(strcmp(cmd, "PORT") == 0) // if client sends PORT command 
    {
        if(isUserAuthenticated(cmd_sock)){ // check first for authentication

        // receive the available port info, which is stored in arg
          
           int ip1, ip2, ip3, ip4, p1, p2;
           sscanf(arg, "%d,%d,%d,%d,%d,%d", &ip1, &ip2, &ip3, &ip4, &p1, &p2);
           data_port = p1 * 256 + p2;        
           connectedclients[cmd_sock].userDataport = data_port;

          pid_t pid = fork(); // fork this process, the reason why this works is because PORT command is only sent during RETR and STOR, so it forks just RETR and STOR, thats the design of our code, see below
          if(pid == 0) {
                close(cmd_sock);
                printf("Received PORT command: %s\n", arg);
                // Prepare data socket for connection
                data_sock = socket(AF_INET, SOCK_STREAM, 0);

                if (data_sock == -1) {
                    perror("Data socket creation failed");   
                }
                // define data_address
                data_addr.sin_family = AF_INET;
                data_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                data_addr.sin_port = htons(data_port);

                int reuse = 1;
                // since we are handling multiple addresses, this is important
                if (setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
                  perror("setsockopt(SO_REUSEADDR) failed");
                  exit(EXIT_FAILURE);
                }

                // define server address, note we are connecting to a different server port now
                struct sockaddr_in server_addr;
                server_addr.sin_family = AF_INET;
                server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                server_addr.sin_port = htons(CONNECT_PORT);

                // bind data_sock to server address
                if(bind(data_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
                    printf("Error: socket bind failed.\n");
                    exit(0);
                }
                // accept incoming connection

                if (connect(data_sock, (struct sockaddr*)&data_addr, sizeof(data_addr)) < 0) {
                    perror("Data socket connect failed");
                    close(data_sock);  
                }
                
                printf("Data socked opened on port :%d\n",data_port);
                chdir(connectedclients[cmd_sock].currDir);
                if(isupload){ // we have set the flag isupload inside RETR and STOR, see above, this specifies the type of command
                    handle_file_store(data_sock, filename);// STOR 
                }
                else{
                    handle_file_retrieve(data_sock, filename);  // RETR
                }
                printf("Data socked closed on port :%d\n",data_port);
                send(cmd_sock, "226 Transfer Completed \n\0", strlen("226 Transfer Completed \n\0"), 0);
              }
              else { // else if parent directory
                close(data_sock);
                chdir(server_root); 
              }
        }
    }
    // Note that we do not fork LIST, instead we instantneously change the direcotry, list files and revert back to root server directory
    if(strcmp(cmd, "LIST") == 0) {
      printf("Received LIST command: %s\n", arg);

        if(isUserAuthenticated(cmd_sock)){ // check for authentication
            if(chdir(connectedclients[cmd_sock].currDir) >= 0){ // check if the file exists
              char *files = list_Files_In_Current_Directory();
              size_t length = strlen(files);
              files[length] = '\0';

              char corResponse[BUFFER_SIZE] = "200 PORT command successful.\n150 File status okay; about to open. data connection.\n\0";
              strcat(corResponse,files);
              strcat(corResponse,"226 Transfer Completed");

              send(cmd_sock,corResponse , sizeof(corResponse),0);

              free(files); // free the allocated memory
              chdir(server_root);
            }
            else{ // if the direcotry does not change which means no such file
                char corResponse[BUFFER_SIZE] = "550 No Such file or directory\0";
                send(cmd_sock, corResponse, sizeof(corResponse), 0);
            }
        }
        else{ // condition if user is not authenticated 
            char corResponse[BUFFER_SIZE] = "530 Not logged in.\0";
            send(cmd_sock, corResponse, sizeof(corResponse), 0);
        }
    }
    // condition for PWD, first check authentication and then do the needful
    if(strcmp(cmd, "PWD") == 0) {
        if(isUserAuthenticated(cmd_sock)){
           printf("Received PWD command: %s\n", connectedclients[cmd_sock].currDir);

           char res[BUFFER_SIZE] = "257 ";
           strcat(res,connectedclients[cmd_sock].currDir);
           send(cmd_sock, res, sizeof(res), 0);
        }
        else{
            char corResponse[BUFFER_SIZE] = "530 Not logged in.\0";
            send(cmd_sock, corResponse, sizeof(corResponse), 0);
        }
    }
    // condition for CWD, first check for authentication and do the needful
    if(strcmp(cmd, "CWD") == 0) {
      printf("Received LIST command: %s\n", arg);
        if(isUserAuthenticated(cmd_sock)){
            char checkdir[1024];
            checkdir[0] = '\0';
            strcpy(checkdir,connectedclients[cmd_sock].currDir);
            strcat(checkdir,"/");
            strcat(checkdir,arg);
            checkdir[strlen(checkdir)] = '\0';

            
            // Checks the file in the server by the changing the dir in the server
            if(chdir(checkdir) >= 0){

               // Add the name of the arg in the path of the director and adds "/"
               strcat(connectedclients[cmd_sock].currDir,"/");
               strcat(connectedclients[cmd_sock].currDir,arg);
               printf("%s\n",connectedclients[cmd_sock].currDir);

               char corResponse[BUFFER_SIZE] = "200 directory changed to /Users/\0";
               strcat(corResponse,connectedclients[cmd_sock].currDir);
               send(cmd_sock, corResponse, sizeof(corResponse), 0);
                // If the file is in the directory , it reverts back to the root server path
               chdir(server_root);
            }
            else{
                char corResponse[BUFFER_SIZE] = "550 No Such file or directory\0";
                send(cmd_sock, corResponse, sizeof(corResponse), 0);
            }
        
        } else {
              char corResponse[BUFFER_SIZE] = "530 Not logged in.\0";
              send(cmd_sock, corResponse, sizeof(corResponse), 0);
          }
      }
      if(strcmp(cmd, "NOT") == 0) { // Get the message of the client NOT with invalid format of COMMAND and message
         printf("Received INVALID command: %s\n", arg);
         char corResponse[BUFFER_SIZE] = "202 Command not implemented\0";
         send(cmd_sock, corResponse, sizeof(corResponse), 0);

     }
      if(strcmp(cmd, "INVALID") == 0) {  //Get the message of INVALID from the client when client enters gibberish commands
         printf("Received INVALID command: %s\n", arg);
         char corResponse[BUFFER_SIZE] = "503 Bad Sequence of commands\0";
         send(cmd_sock, corResponse, sizeof(corResponse), 0);
     }
}

// function to handle STOR command, i.e. this functions opens a new file, and writes into it by reading data from client
void handle_file_store(int data_sock, const char* filename) {

    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("File open failed");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;

    // read data from client and write into the filename

    while ((bytes_read = read(data_sock, buffer, BUFFER_SIZE)) > 0) {
         fwrite(buffer, 1, bytes_read, file);
    }
    fclose(file);
    close(data_sock);
}

// function to handle RETR command, opend a file in read move and sends the data to client

void handle_file_retrieve(int data_sock, const char* filename) {

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("File open failed");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        write(data_sock, buffer, bytes_read);
    }
    
    fclose(file);
    close(data_sock);

}

// function to load username and password from users.txt

void load_User_from_file() {
  FILE *userFile = fopen("users.txt", "r");
    if (!userFile) {
        // if user file does not exist
        userCount = 0;
        printf("users.txt file not found. \n");
        return;
    }

    char buffer[2 * 100 + 2]; // Adjust the buffer size to accommodate two strings and a space
    while (fgets(buffer, sizeof(buffer), userFile)) {
        if (sscanf(buffer, "%s %s", AccountFile[userCount].user, AccountFile[userCount].pw) == 2) {
            userCount += 1;
        }
    }
    fclose(userFile);
}

// if user exists, function that updates the strcutre for that user to true and sends confirmation to client
void set_user(int i, char *resDat, int n){

      connectedclients[i].indexofuser = n;  // found at nth pos in array
      connectedclients[i].username = true;
      char res[BUFFER_SIZE] = "331 Username OK, need password.\0";
      strcpy(connectedclients[i].usernameString,resDat);
      send(i, res, sizeof(res), 0);

}

// function to handle "USER" command
void handle_User_Command(int i, char *resDat) {
  bool foundDat = 0;
  // loop to check if user exists
  int n = 0;
  while(n < userCount){
    if (strcmp(resDat, AccountFile[n].user) == 0) {
      // if found
      foundDat = 1;
      set_user(i, resDat, n);
      break;
    }
    n = n + 1;
  }
  // if not found
  if (foundDat == 0) {
    char res[BUFFER_SIZE] = "530 Not logged in.\0";
    send(i, res, sizeof(res), 0);
  }
}

// we broke down the authentication process to two steps
// this funtion handles the case were there is username of password flag in the structure
bool first_step_authenticate(int i){
    bool authenticate = (!connectedclients[i].password || !connectedclients[i].username);
    return authenticate;
}

// second step in authentication, a function that returns if the client has authenticated 
bool second_step_authenticate(int i){
    bool authenticate = (!connectedclients[i].hasauthenticated);
    return authenticate;
}

// function that combines first step and second step authentication to return ultimately if the given user is authenticated
bool isUserAuthenticated(int i) {
  if (first_step_authenticate(i)) {  // not authenticated
    return false;
  }
  else{
      if (second_step_authenticate(i)){ // if it is a new socket from a new terminal
          strcpy(connectedclients[i].currDir,connectedclients[i].usernameString);
          connectedclients[i].hasauthenticated = true;
      }
    return true;
  }
}

// a function to check if the file exists or not
bool file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return true;
    }
    return false;
}

// helper function for list_Files_In_Current_Directory
char* append_to_buffer(char *buffer, size_t *buffer_size, size_t *buffer_length, const char *str) {
    size_t str_length = strlen(str) + 1; // +1 for the newline character
    // Check if we need more space
    if (*buffer_length + str_length + 1 > *buffer_size) { // +1 for the null terminator
        *buffer_size *= 2; // Double the buffer size
        buffer = realloc(buffer, *buffer_size);
        if (!buffer) {
            perror("Unable to reallocate memory");
            exit(EXIT_FAILURE);
        }
    }
    strcat(buffer, str);
    strcat(buffer, "\n");
    *buffer_length += str_length;
    return buffer;
}

// Function to list files in the current directory, this function skips the hidden files, does not list them
char* list_Files_In_Current_Directory() {
    DIR *directory;
    struct dirent *entry;
    size_t buffer_size = 1024;
    size_t buffer_length = 0;
    char *file_list = malloc(buffer_size);
    if (!file_list) {
        perror("Unable to allocate memory");
        exit(EXIT_FAILURE);
    }
    file_list[0] = '\0'; // Start with an empty string

    directory = opendir(".");
    if (directory == NULL) {
        perror("Unable to open directory");
        free(file_list);
        exit(EXIT_FAILURE);
    }

    for (entry = readdir(directory); entry != NULL; entry = readdir(directory)) {
        // Skip "." and ".." entries and hidden files
        if (entry->d_name[0] == '.') {
            continue;
        }
        file_list = append_to_buffer(file_list, &buffer_size, &buffer_length, entry->d_name);
    }
    closedir(directory);
    return file_list;
}

// function to get the current directory path
char* get_Current_Directory_Path() {
    char *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        perror("Unable to allocate buffer");
        return NULL;
    }
    if (getcwd(buffer, BUFFER_SIZE) != NULL) {
        return buffer;
    } else {
        perror("getcwd() error");
        free(buffer);
        return NULL;
    }
}

// function to handle CWD command, change the directory or display an error
void handle_cd_command(char *command) {
    if (chdir(command) < 0) {
        perror("chdir failed");
    }
}

// helper function for process_input, to break down the input to two parts
void ensure_cmd_termination(char **cmd, char *input_copy){

    if (*cmd != NULL) {
        *cmd = strdup(*cmd);
        if (*cmd == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input_copy);
            exit(1);
        }
    }


}

// helper function for process_input, to break down the input to two parts
void ensure_arg_termination(char **arg, char *input_copy, char **cmd){

    
        if (*arg != NULL) {
                *arg = strdup(*arg);
                if (*arg == NULL) {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(input_copy);
                    free(*cmd);
                    exit(1);
                }
            }
    

}

// function that takes in user input and breaks down the input, storing one in cmd and the other in arg
void process_Input(const char *input_string, char **cmd, char **arg) {
    // Duplicate the input string because strtok modifies the string
    char *input_copy = strdup(input_string);
    if (input_copy == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // Tokenize the string
    *cmd = strtok(input_copy, " ");
    *arg = strtok(NULL, " ");

    // Ensure both cmd and arg are properly null-terminated

    ensure_cmd_termination(cmd, input_copy);
    ensure_arg_termination(arg, input_copy, cmd);
    // Free the duplicated input string
    free(input_copy);
}

// helper function to send not logged in message to client if user hasn't logged in
void not_logged_in(int i){

    char res[BUFFER_SIZE] = "530 Not logged in.\0";
    send(i, res, sizeof(res), 0);

}

// // helper function to send not logged in message to client if user has logged in
void logged_in(int i){

    char res[BUFFER_SIZE] = "230 User logged in, proceed.\0"; // if it is the password
    connectedclients[i].password = true;
    send(i, res, sizeof(res), 0);

}

// handle PASS command, checks the password against the databse and sends messages to server accordinly, authentication or no authentication
void handle_Pass_Command(int i, char *resDat) {
  if (connectedclients[i].username) {
     if (strcmp(resDat, AccountFile[connectedclients[i].indexofuser].pw) != 0) { // if not the password
        not_logged_in(i);
    } else {
        logged_in(i);
    }
  } else {  // check if username is not valid
      not_logged_in(i);
  }
}