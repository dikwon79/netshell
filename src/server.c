#include <arpa/inet.h>
#include <errno.h>
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

static void           parse_arguments(int argc, char *argv[], char **address, char **port);
static void           handle_arguments(const char *binary_name, const char *address, const char *port_str, in_port_t *port);
static in_port_t      parse_in_port_t(const char *binary_name, const char *port_str);
static void           convert_address(const char *address, struct sockaddr_storage *addr);
static int            socket_create(int domain, int type, int protocol);
static void           socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void           start_listening(int server_fd, int backlog);
_Noreturn static void usage(const char *program_name, int exit_code, const char *message);
void                 *handle_client(void *arg);

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
    char               buf[BUF_SIZE];

    // char buf[BUF_SIZE];
    // int  clnt_sock = *((int *)arg);
    free(arg);    // Free the allocated memory

    while(1)
    {
        int str_len = (int)read(clnt_sock, buf, sizeof(buf));
        if(str_len <= 0)
        {
            break;
        }

        // Write the received message to all connected clients
        pthread_mutex_lock(mutex);
        for(int i = 0; i < MAX_CLIENTS; ++i)
        {
            if(clnt_socks[i] != 0 && clnt_socks[i] != clnt_sock)
            {
                write(clnt_socks[i], buf, (size_t)str_len);
            }
        }
        pthread_mutex_unlock(mutex);
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

    close(clnt_sock);
    return NULL;
}