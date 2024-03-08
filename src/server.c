#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUF_SIZE 30
#define MAX_CLIENTS 10
#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define BACKLOG 5

#define MAX_SIZE_ARG 16

static void           parse_arguments(int argc, char *argv[], char **address, char **port);
static void           handle_arguments(const char *binary_name, const char *address, const char *port_str, in_port_t *port);
static in_port_t      parse_in_port_t(const char *binary_name, const char *port_str);
static void           convert_address(const char *address, struct sockaddr_storage *addr);
static int            socket_create(int domain, int type, int protocol);
static void           socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void           start_listening(int server_fd, int backlog);
_Noreturn static void usage(const char *program_name, int exit_code, const char *message);
void                 *handle_client(void *arg);
void                  convert_cmd(char *cmd);

// int             clnt_socks[MAX_CLIENTS];    // Array to store client sockets
// pthread_mutex_t mutex;                      // Mutex to synchronize access to the client sockets array

struct ThreadArgs
{
    int             *clnt_sock_ptr;
    pthread_mutex_t *mutex;
    int             *clnt_socks;
};

int main(int argc, char *argv[])
{
    char                   *ip_address;
    char                   *port_str;
    in_port_t               port;
    struct sockaddr_storage addr;
    int                     sockfd;
    socklen_t               adr_sz;
    pthread_t               thread;
    int                     clnt_socks[MAX_CLIENTS];
    pthread_mutex_t         mutex;

    ip_address = NULL;
    port_str   = NULL;

    parse_arguments(argc, argv, &ip_address, &port_str);

    handle_arguments(argv[0], ip_address, port_str, &port);

    // Initialize the client sockets array
    for(int i = 0; i < MAX_CLIENTS; ++i)
    {
        clnt_socks[i] = 0;
    }

    // Initialize the mutex
    pthread_mutex_init(&mutex, NULL);

    // convert_address
    convert_address(ip_address, &addr);
    sockfd = socket_create(addr.ss_family, SOCK_STREAM, 0);

    // binding
    socket_bind(sockfd, &addr, port);

    start_listening(sockfd, BACKLOG);
    puts("Server is On...");
    // struct sockaddr_in clnt_adr = {0};
    adr_sz = sizeof(addr);

    while(1)
    {
        int *clnt_sock_ptr = (int *)malloc(sizeof(int));
        *clnt_sock_ptr     = accept(sockfd, (struct sockaddr *)&addr, &adr_sz);
        if(*clnt_sock_ptr == -1)
        {
            free(clnt_sock_ptr);
            continue;
        }

        puts("new client connected...");

        // Add the new client to the array
        pthread_mutex_lock(&mutex);
        for(int i = 0; i < MAX_CLIENTS; ++i)
        {
            if(clnt_socks[i] == 0)
            {
                clnt_socks[i] = *clnt_sock_ptr;
                break;
            }
        }
        pthread_mutex_unlock(&mutex);

        // Create a new thread to handle the client

        struct ThreadArgs *thread_args = (struct ThreadArgs *)malloc(sizeof(struct ThreadArgs));
        thread_args->clnt_sock_ptr     = clnt_sock_ptr;
        thread_args->mutex             = &mutex;
        thread_args->clnt_socks        = clnt_socks;

        if(pthread_create(&thread, NULL, handle_client, (void *)thread_args) != 0)
        {
            perror("Thread creation failed");
            close(*clnt_sock_ptr);
            free(clnt_sock_ptr);
            free(thread_args);
            continue;
        }

        // Detach the thread to allow it to run independently
        pthread_detach(thread);
    }

    close(sockfd);
    pthread_mutex_destroy(&mutex);
    return 0;
}

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port)
{
    int opt;

    opterr = 0;

    while((opt = getopt(argc, argv, "h")) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(argv[0], EXIT_FAILURE, message);
            }
            default:
            {
                usage(argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if(optind >= argc)
    {
        usage(argv[0], EXIT_FAILURE, "The IP address or hostname is required.");
    }

    if(optind < argc - 2)
    {
        usage(argv[0], EXIT_FAILURE, "Too many arguments.");
    }

    *ip_address = argv[optind];
    *port       = argv[optind + 1];
}

in_port_t parse_in_port_t(const char *binary_name, const char *str)
{
    char     *endptr;
    uintmax_t parsed_value;

    errno        = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        usage(binary_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    // Check if the parsed value is within the valid range for in_port_t
    if(parsed_value > UINT16_MAX)
    {
        usage(binary_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t)parsed_value;
}

static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

static int socket_create(int domain, int type, int protocol)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if(sockfd == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void     *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr               = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr                = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
    }
    else
    {
        fprintf(stderr, "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if(bind(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

static void start_listening(int server_fd, int backlog)
{
    if(listen(server_fd, backlog) == -1)
    {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Listening for incoming connections...\n");
}

_Noreturn static void usage(const char *program_name, int exit_code, const char *message)
{
    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] <IP address or hostname> <port>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);
    exit(exit_code);
}

static void handle_arguments(const char *binary_name, const char *address, const char *port_str, in_port_t *port)
{
    if(address == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "The IP address or hostname is required.");
    }

    if(port_str == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "Port argument is missing.");
    }

    *port = parse_in_port_t(binary_name, port_str);
}

void *handle_client(void *arg)
{
    struct ThreadArgs *args       = (struct ThreadArgs *)arg;
    int                clnt_sock  = *(args->clnt_sock_ptr);
    pthread_mutex_t   *mutex      = args->mutex;
    int               *clnt_socks = args->clnt_socks;
    char               buffer[BUF_SIZE];

    char *argv[MAX_SIZE_ARG];

    // Initialize argv array with NULL
    for(int j = 0; j < MAX_SIZE_ARG; j++)
    {
        argv[j] = NULL;
    }

    while(1)
    {
        memset(buffer, 0, sizeof(buffer));
        int str_len = (int)read(clnt_sock, buffer, sizeof(buffer));
        if(str_len <= 0)
        {
            break;
        }
        printf("shell> %s", buffer);
        if((strlen(buffer) > 0) && (buffer[strlen(buffer) - 1] == '\n'))
        {
            buffer[strlen(buffer) - 1] = '\0';
        }
        // bypass empty commands
        if(!strcmp("", buffer))
        {
            continue;
        }

        // check for "exit" command
        if(!strcmp("exit", buffer))
        {
            break;
        }
        // convert
        char *ptr;
        char *saveptr;
        int   i = 0;
        ptr     = strtok_r(buffer, " ", &saveptr);
        while(ptr != NULL)
        {
            // printf("%s\n", ptr);
            argv[i] = ptr;
            i++;
            ptr = strtok_r(NULL, " ", &saveptr);
        }

        // Check for "&"
        if(!strcmp("&", argv[i - 1]))
        {
            argv[i - 1] = NULL;    // Remove the "&" from argv

            // Dynamically allocate memory for "&" and copy it
            argv[i] = strdup("&");
            if(argv[i] == NULL)
            {
                perror("strdup");
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            argv[i] = NULL;
        }

        // fork and execute the command
        pid_t pid = fork();
        if(-1 == pid)
        {
            printf("failed to create a child\n");
        }
        else if(0 == pid)
        {
            // printf("hello from child\n");
            // execute a command

            // 최대 문자열 크기 + 2 (더블 쿼테이션을 포함하여 저장하기 위해)
            char str_with_quotes[BUF_SIZE];

            // 변수 값을 포함하여 문자열 생성
            sprintf(str_with_quotes, "/bin/%s", argv[0]);

            // 문자열 출력
            printf("%s\n", str_with_quotes);

            // Execute the command via execv
            if(execv(str_with_quotes, argv) == -1)
            {
                perror("Error executing command");
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            // printf("hello from parent\n");
            // wait for the command to finish if "&" is not present
            if(argv[i] == NULL)
            {
                waitpid(pid, NULL, 0);
            }
        }
    }

    // Remove the disconnected client from the array
    pthread_mutex_lock(mutex);
    for(int i = 0; i < MAX_CLIENTS; ++i)
    {
        if(clnt_socks[i] == clnt_sock)
        {
            clnt_socks[i] = 0;
            break;
        }
    }
    pthread_mutex_unlock(mutex);
    free(arg);
    close(clnt_sock);
    return NULL;
}