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
#define OUT_BUF 2048
#define MODE 0644
#define POSITION1 26
#define POSITION2 46
#define POSITION3 15

static void           parse_arguments(int argc, char *argv[], char **address, char **port);
static void           handle_arguments(const char *binary_name, const char *address, const char *port_str, in_port_t *port);
static in_port_t      parse_in_port_t(const char *binary_name, const char *port_str);
static void           convert_address(const char *address, struct sockaddr_storage *addr);
static int            socket_create(int domain, int type, int protocol);
static void           socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void           start_listening(int server_fd, int backlog);
_Noreturn static void usage(const char *program_name, int exit_code, const char *message);
void                 *handle_client(void *arg);
void                  sigint_handler();

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

    signal(SIGINT, sigint_handler);
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
    char *argv2[MAX_SIZE_ARG];

    // Initialize argv array with NULL
    for(int j = 0; j < MAX_SIZE_ARG; j++)
    {
        argv[j] = NULL;
    }

    // Initialize argv2 array with NULL
    for(int j = 0; j < MAX_SIZE_ARG; j++)
    {
        argv2[j] = NULL;
    }

    while(1)
    {
        int redirect_output = 0;
        int redirect_append = 0;
        int redirect_input  = 0;

        char *output_file = NULL;
        char *input_file  = NULL;
        int   fd_out      = 0;
        int   fd_in       = 0;

        // Find the position of ">" or ">>"
        int redirect_index = 0;
        memset(buffer, 0, sizeof(buffer));
        int str_len = (int)read(clnt_sock, buffer, sizeof(buffer));
        if(str_len <= 0)
        {
            break;
        }
        // printf("shell> %s", buffer);
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
        int   pipe_input = 0;

        int i = 0;
        ptr   = strtok_r(buffer, " ", &saveptr);
        while(ptr != NULL)
        {
            argv[i] = ptr;
            printf("%s\n", argv[i]);
            i++;
            ptr = strtok_r(NULL, " ", &saveptr);
        }

        for(int j = 0; j < i; j++)
        {
            if(!strcmp("|", argv[j]))
            {
                pipe_input = j;
                argv[j]    = NULL;
                i          = j;
                // Copy the characters after '|' to cmd2
                int k;
                int l;
                for(k = pipe_input + 1, l = 0; argv[k] != NULL; ++k, ++l)
                {
                    argv2[l] = argv[k];
                    argv[k]  = NULL;
                }
                argv2[l] = NULL;    // Null-terminate cmd2
                break;
            }
        }

        // redirection check

        for(int j = 0; j < i; j++)
        {
            if(!strcmp(">", argv[j]))
            {
                redirect_output = 1;
                redirect_append = 0;
                output_file     = argv[j + 1];
                redirect_index  = j;
            }
            else if(!strcmp(">>", argv[j]))
            {
                redirect_output = 1;
                redirect_append = 1;
                output_file     = argv[j + 1];
                redirect_index  = j;
            }
            else if(!strcmp("<", argv[j]))
            {
                redirect_input = 1;
                input_file     = argv[j + 1];
                redirect_index = j;
            }
        }

        if(redirect_index > 0)
        {
            // Dynamically allocate memory for the command after redirection symbol and copy it

            argv[redirect_index]     = NULL;    // Terminate the argv array after redirection symbol
            argv[redirect_index + 1] = NULL;    // Set the next element to NULL to avoid overflow

            // Open output file if output redirection is needed
            if(redirect_output)
            {
                if(redirect_append)
                {
                    fd_out = open(output_file, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, MODE);
                }
                else
                {
                    fd_out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, MODE);
                }

                if(fd_out == -1)
                {
                    perror("open");
                    exit(EXIT_FAILURE);
                }
            }

            // Open input file if input redirection is needed
            if(redirect_input)
            {
                fd_in = open(input_file, O_RDONLY | O_CLOEXEC);
                if(fd_in == -1)
                {
                    perror("open");
                    exit(EXIT_FAILURE);
                }
            }
        }
        else
        {
            redirect_index = i;
        }

        if(!strcmp("&", argv[redirect_index - 1]))    // Check for "&"
        {
            argv[redirect_index - 1] = NULL;    // Remove the "&" from argv
            // Dynamically allocate memory for "&" and copy it
            argv[redirect_index] = strdup("&");
            if(argv[redirect_index] == NULL)
            {
                perror("strdup");
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            argv[redirect_index] = NULL;
        }

        // fork and execute the command

        int pipefd[2];

        // 파이프 생성 - pipe2() 함수 사용
        if(pipe2(pipefd, O_CLOEXEC) == -1)
        {
            perror("pipe2");
            exit(EXIT_FAILURE);
        }

        pid_t pid = fork();

        if(pid == -1)
        {
            printf("failed to create a child\n");
        }
        else if(pid == 0)
        {
            // redirection
            if(pipe_input)
            {
                // write end = 1, read end= 0

                // Redirect stdin to the read end of the pipe
                dup2(pipefd[1], STDOUT_FILENO);
                // Close the read end of the pipe (not needed anymore)
                close(pipefd[0]);

                char str_with_quotes[BUF_SIZE];

                // 변수 값을 포함하여 문자열 생성
                sprintf(str_with_quotes, "/bin/%s", argv[0]);

                // Execute the command via execv
                if(execv(str_with_quotes, argv) == -1)
                {
                    fprintf(stderr, "Failed to execute '%s'\n", argv[0]);
                    exit(1);
                }
            }
            else
            {
                if(redirect_output)
                {
                    if(dup2(fd_out, STDOUT_FILENO) == -1)
                    {
                        perror("dup2");
                        exit(EXIT_FAILURE);
                    }

                    close(fd_out);
                }
                else if(redirect_input)    // Redirect stdin from input file if input redirection is needed
                {
                    if(dup2(fd_in, STDIN_FILENO) == -1)
                    {
                        perror("dup2");
                        exit(EXIT_FAILURE);
                    }

                    close(fd_in);
                    dup2(pipefd[1], STDOUT_FILENO);
                }
                else
                {
                    dup2(pipefd[1], STDOUT_FILENO);
                }

                // printf("hello from child\n");
                // execute a command

                close(pipefd[0]);    // 파이프의 읽기측 닫음

                char str_with_quotes[BUF_SIZE];

                // 변수 값을 포함하여 문자열 생성
                sprintf(str_with_quotes, "/bin/%s", argv[0]);

                // 문자열 출력
                // printf("%s\n", str_with_quotes);

                // Execute the command via execv
                if(execv(str_with_quotes, argv) == -1)
                {
                    perror("Error executing command");
                    exit(EXIT_FAILURE);
                }
            }
        }
        else
        {
            if(pipe_input)
            {
                int fd[2];

                // 파이프 생성 - pipe2() 함수 사용
                if(pipe2(fd, O_CLOEXEC) == -1)
                {
                    perror("pipe2");
                    exit(EXIT_FAILURE);
                }

                pid = fork();

                if(pid == 0)
                {
                    dup2(pipefd[0], STDIN_FILENO);
                    close(pipefd[1]);

                    dup2(fd[1], STDOUT_FILENO);
                    close(fd[0]);

                    char str_with_quotes[BUF_SIZE];

                    // 변수 값을 포함하여 문자열 생성
                    sprintf(str_with_quotes, "/bin/%s", argv2[0]);

                    // Execute the command via execv
                    if(execv(str_with_quotes, argv2) == -1)
                    {
                        fprintf(stderr, "Failed to execute '%s'\n", argv2[0]);
                        exit(1);
                    }
                }
                else
                {
                    int status;
                    close(pipefd[0]);
                    close(pipefd[1]);

                    waitpid(pid, &status, 0);

                    close(fd[1]);

                    char    outbuffer[OUT_BUF];
                    ssize_t bytes_read;
                    printf("Received data from child process:\n");

                    while((bytes_read = read(fd[0], outbuffer, sizeof(outbuffer))) > 0)
                    {
                        // 읽은 데이터를 출력함
                        write(STDOUT_FILENO, outbuffer, (size_t)bytes_read);

                        // 각 클라이언트 소켓에 데이터를 전송합니다.

                        pthread_mutex_lock(mutex);
                        for(int k = 0; k < MAX_CLIENTS; ++k)
                        {
                            if(clnt_socks[k] != 0)
                            {
                                ssize_t bytes_written = write(clnt_socks[k], outbuffer, (size_t)bytes_read);
                                if(bytes_written != bytes_read)
                                {
                                    perror("write");
                                    // 오류 처리를 추가하세요.
                                }
                            }
                        }
                        pthread_mutex_unlock(mutex);
                    }

                    if(bytes_read == -1)
                    {
                        perror("read");
                        exit(EXIT_FAILURE);
                    }

                    close(fd[0]);
                }
            }
            else
            {
                // printf("hello from parent\n");
                // wait for the command to finish if "&" is not present
                close(pipefd[1]);    // 파이프의 쓰기측 닫음

                if(NULL == argv[i])
                {
                    waitpid(pid, NULL, 0);

                    char    outbuffer[OUT_BUF];
                    ssize_t bytes_read;
                    printf("Received data from child process:\n");

                    while((bytes_read = read(pipefd[0], outbuffer, sizeof(outbuffer))) > 0)
                    {
                        // 읽은 데이터를 출력함
                        write(STDOUT_FILENO, outbuffer, (size_t)bytes_read);

                        // 각 클라이언트 소켓에 데이터를 전송합니다.

                        pthread_mutex_lock(mutex);
                        for(int k = 0; k < MAX_CLIENTS; ++k)
                        {
                            if(clnt_socks[k] != 0)
                            {
                                ssize_t bytes_written = write(clnt_socks[k], outbuffer, (size_t)bytes_read);
                                if(bytes_written != bytes_read)
                                {
                                    perror("write");
                                    // 오류 처리를 추가하세요.
                                }
                            }
                        }
                        pthread_mutex_unlock(mutex);
                    }

                    if(bytes_read == -1)
                    {
                        perror("read");
                        exit(EXIT_FAILURE);
                    }
                }
                close(pipefd[0]);    // 파이프의 읽기측 닫음
            }
        }
    }
    free(arg);
    close(clnt_sock);
    return NULL;
}

void sigint_handler()
{
    write(STDOUT_FILENO, "\nCtrl-C you've pressed!!\n", POSITION1);    // 28
    write(STDOUT_FILENO, "if you press that key, it will terminate....\n", POSITION2);
    write(STDOUT_FILENO, "Server is On...", POSITION3);
    signal(SIGINT, SIG_DFL);
}