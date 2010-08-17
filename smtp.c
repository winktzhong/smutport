/*
 * smutport - some smtp serving code
 * Copyright (C) 2010 Kostas Michalopoulos
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * Kostas Michalopoulos <badsector@runtimeterror.com>
 */

#include "smutport.h"

/*
 * This structure is used to hold information about in-progress mail delivery.
 */
typedef struct _delivery_status_t
{
    char* from; /* the value in MAIL FROM:... */
    char** to; /* array with the accepted users in RCPT TO:... */
    size_t to_size; /* size of the "to" array */
} delivery_status_t;

/* A flag that notifies the main listening loop that there are children waiting
 * for attention. */
static int sigchld_issued;

/* The listening socket used by the server. */
socket_t smtp_server_socket;

/*
 * SIGCHLD handler. Simply raises the sigchld_issued flag.
 */
static void sigchld_handler(int s)
{
    sigchld_issued = 1;
}

/*
 * Release the given delivery status structure's contents.
 */
static void delst_release(delivery_status_t* delst)
{
    size_t i;
    for (i=0; i<delst->to_size; i++) free(delst->to[i]);
    free(delst->to);
    free(delst->from);
}

/*
 * Initialize the given delivery status structure.
 */
static void delst_init(delivery_status_t* delst)
{
    delst_release(delst);
    memset(delst, 0, sizeof(delivery_status_t));
}

/*
 * Add a recipient to the given delivery status structure. Returns 0 on failure
 * and non-zero otherwise.
 */
static int delst_add_to(delivery_status_t* delst, const char* name)
{
    char* namecopy;
    char** new_to;
    namecopy = strdup(name);
    if (!namecopy) return 0;
    new_to = realloc(delst->to, sizeof(char*)*(delst->to_size + 1));
    if (!new_to) {
        free(namecopy);
        return 0;
    }
    delst->to = new_to;
    new_to[delst->to_size++] = namecopy;
    return 1;
}

/*
 * Returns 1 if the given user is acceptable, 0 if not. This works by calling
 * the lil function "accept-user" with the given username as argument.
 */
static int accept_user(const char* user)
{
    char* tmpcode = malloc(strlen(user) + 64);
    lil_value_t val;
    int r;
    if (!tmpcode) return 0;
    sprintf(tmpcode, "accept-user {%s}", user);
    val = script_run_command(tmpcode);
    r = lil_to_integer(val);
    free(tmpcode);
    lil_free_value(val);
    return r;
}

/*
 * Helper function that sends data until everything is really sent. Returns 0
 * on failure.
 */
static int send_data(socket_t socket, const void* data, size_t len)
{
    size_t total_sent = 0;
    while (total_sent < len) {
        size_t sent = send(socket, data + total_sent, len - total_sent, 0);
        if (sent < 1) return 0; /* connection closed or something went wrong */
        total_sent += sent;
    }
    return 1;
}

/*
 * Helper for string data. <CRLF> is assumed part of the string and is not
 * sent.
 */
static int send_string(socket_t socket, const char* str)
{
    return send_data(socket, str, strlen(str));
}

/*
 * Composes and sends the greeting message to the given client socket.
 */
static int send_greeting(socket_t socket)
{
    /* compose the greeting message using the related lil variables */
    const char* domain = script_get_var("domain", "localhost");
    const char* greeting = script_get_var("greeting", "smutport mail server is ready");
    char* full_greeting = malloc(strlen(domain) + strlen(greeting) + 32);
    if (!full_greeting) {
        /* ah, we ran out of memory */
        send_string(socket, "421 Hi and bye, i'm too exhausted right now...\r\n");
        return 0;
    }
    sprintf(full_greeting, "220 %s %s\r\n", domain, greeting);
    send_data(socket, full_greeting, strlen(full_greeting));
    free(full_greeting);
    return 1;
}

/*
 * Process the RCPT field. This scans the field for the user name. The expected
 * format for the field is "<"["@"<domain>":"]<username>"@"<domain>">". Only
 * the username is used, the rest are ignored.
 */
static void process_rcpt(socket_t socket, delivery_status_t* delst, const char* field)
{
    size_t h;
    char* user = NULL;
    char* new_user;
    size_t user_len = 0;

    /* find the opening angle */
    for (h=0; field[h]; h++)
        if (field[h] == '<') break;
    if (!field[h]) {
        /* bracket not found, complain */
        send_string(socket, "553 Where is my bracket? The username is malformed!\r\n");
        return;
    }

    /* skip the bracket and check for the first domain '@' symbol */
    if (field[++h] == '@') {
        /* skip whatever follows up to the ':' symbol... */
        for (; field[h]; h++)
            if (field[h] == ':') break;
        /* ... and the ':' symbol itself */
        if (field[h] == ':') h++;
    }

    /* do we still have data? */
    if (!field[h]) {
        /* nope :-( - let's complain! */
        send_string(socket, "553 Where is my user? This isn't right. This is wrong!\r\n");
        return;
    }

    /* we have data - let's scan the username */
    for (; field[h]; h++)
        if (field[h] == '>' || field[h] == '@') {
            /* end of interesting data, let's stop */
            break;
        } else {
            /* add char in username */
            new_user = realloc(user, user_len + 1);
            if (!new_user) {
                send_string(socket, "451 I've ran out of memory. I don't know you.\r\n");
                free(user);
                return;
            }
            user = new_user;
            user[user_len++] = field[h];
        }
    /* add terminator in username */
    new_user = realloc(user, user_len + 1);
    if (!new_user) {
        send_string(socket, "451 Just while i was doing fine, i forgot who you are.\r\n");
        free(user);
        return;
    }
    user = new_user;
    user[user_len] = 0;

    /* check if the user string is valid (ie. not empty) */
    if (!user[0]) {
        send_string(socket, "553 I need a user. A USER! Do you understand me?!\r\n");
        free(user);
        return;
    }

    /* check if the user is acceptable */
    if (!accept_user(user)) {
        /* ...no, this user is not acceptable */
        send_string(socket, "550 There is nobody named like this here.\r\n");
        free(user);
        return;
    }

    /* all fine, add the user to the delivery structure */
    delst_add_to(delst, user);

    free(user);
    send_string(socket, "250 Ok\r\n");
}

/*
 * Gathers the data in a message.
 */
static void gather_data(socket_t socket, delivery_status_t* delst)
{
    char mailfile[128];
    char* line = NULL;
    char* new_line;
    int line_len = 0;
    int max_text_line_length;
    int tries = 0;
    size_t i;
    const char* mailboxes_directory;
    char** user_mail_file;
    FILE** umf_handle;
    int send_ok = 0;
    int looping = 1;

    /* check if there is at least one recipient in the delivery */
    if (delst->to_size < 1) {
        send_string(socket, "501 Actually, i need some users to send the mail to first\r\n");
        return;
    }

    /* get mailbox configuration */
    mailboxes_directory = script_get_var("mailboxes-directory", "mailboxes");

    /* fill the user_mail_file with the user mailboxes and create missing
     * mailbox directories */
    user_mail_file = malloc(sizeof(char*)*delst->to_size);
    umf_handle = malloc(sizeof(FILE*)*delst->to_size);
    if (!user_mail_file || !umf_handle) {
        /* out of memory */
        free(user_mail_file);
        free(umf_handle);
        send_string(socket, "451 There is nothing i can do, i have no memory\r\n");
        return;
    }
    for (i=0; i<delst->to_size; i++) {
        struct timeval tv;
        uint64_t ms;

        user_mail_file[i] = malloc(strlen(mailboxes_directory) + strlen(delst->to[i]) + 128);
        if (!user_mail_file[i]) {
            /* ran out of memory... */
            size_t j;
            for (j=0; j<i; j++) {
                fclose(umf_handle[j]);
                free(user_mail_file[j]);
            }
            free(user_mail_file);
            free(umf_handle);
            send_string(socket, "451 Out of memory, out of options\r\n");
            return;
        }
        sprintf(user_mail_file[i], "%s/%s", mailboxes_directory, delst->to[i]);

        /* we use the temporary value of user_mail_file[i] without the mail
         * filename to force the mailbox directory creation. We ignore the
         * result of the call since most likely the directory will exist.*/
        mkdir(user_mail_file[i], 0750);

        /* calculate a filename for the mail based on the microseconds since
         * the epoch - and a random number just in case. */
        gettimeofday(&tv, NULL);
        ms = tv.tv_sec*1000000 + tv.tv_usec;
        sprintf(mailfile, "%llu.%i.mail", (long long unsigned int)ms, rand()&0xFFFF);
        strcat(user_mail_file[i], "/");
        strcat(user_mail_file[i], mailfile);

        /* open the mail file for writing */
        umf_handle[i] = fopen(user_mail_file[i], "wt");
        if (!umf_handle[i]) {
            /* failed to create mail file... */
            size_t j;
            for (j=0; j<i; j++) {
                fclose(umf_handle[j]);
                free(user_mail_file[j]);
            }
            free(user_mail_file);
            free(umf_handle);
            send_string(socket, "554 Failed to create mail file\r\n");
            return;
        }
    }

    /* get maximum command length value */
    max_text_line_length = atoi(script_get_var("max-text-line-length", "1024"));
    if (max_text_line_length < 1001) max_text_line_length = 1001;

    /* inform the client to start sending bytes */
    send_string(socket, "354 Ok buddy, start typing. End the email with <CRLF>.<CRLF>\r\n");

    /* reader loop */
    while (looping) {
        char buff[1024];
        int bytes_read;
        int i;

        /* try to read some data */
        bytes_read = read(socket, buff, sizeof(buff));
        if (bytes_read == 0) {
            /* connection closed, let's break */
            break;
        }
        if (bytes_read == -1) {
            /* something went wrong, let's retry a few times and break later*/
            if (++tries == 32) break;
            continue;
        }
        tries = 0;

        /* process the data */
        for (i=0; i<bytes_read; i++) {
            if (buff[i] == '\n') {
                /* found a newline! */
                new_line = realloc(line, line_len + 1);
                if (!new_line) {
                    /* out of memory, abort */
                    send_string(socket, "451 The memory is out, i know nothing\r\n");
                    looping = 0;
                    break;
                }
                line = new_line;
                line[line_len] = 0;
                /* write the line to the mail files */
                if (line[0] == '.' && !line[1]) {
                    /* the line is an end-of-data dot */
                    send_ok = 1;
                    looping = 0;
                    break;
                } else {
                    /* write the line to all open mail files */
                    size_t j;
                    for (j=0; j<delst->to_size; j++)
                        fprintf(umf_handle[j], "%s\n", line[0] == '.' ? (line + 1) : line);
                }
                /* prepare for a new one */
                free(line);
                line = NULL;
                line_len = 0;
            } else if (buff[i] == '\r') {
                /* ignore CRs */
            } else {
                /* found... something else - put it in the line, as long as
                 * the line's length is not as large as the maximum value */
                if (max_text_line_length > line_len) {
                    new_line = realloc(line, line_len + 1);
                    if (!new_line) {
                        /* out of memory, abort */
                        send_string(socket, "451 There is nothing in my mind i forgot everything\r\n");
                        looping = 0;
                        break;
                    }
                    line = new_line;
                    line[line_len++] = buff[i];
                }
            }
        }
    }

    for (i=0; i<delst->to_size; i++) {
        fflush(umf_handle[i]);
        fclose(umf_handle[i]);
        free(user_mail_file[i]);
    }
    free(user_mail_file);
    free(umf_handle);
    free(line);

    if (send_ok) {
        send_string(socket, "250 Ok: saved as ");
        send_string(socket, mailfile);
        send_string(socket, "\r\n");
        delst_init(delst);
    }
}

/*
 * Parses a SMTP command sent in the given client socket.
 */
static void parse_smtp_command(socket_t socket, delivery_status_t* delst, const char* cmd, size_t cmd_len)
{
    char base_cmd[5];
    size_t i, field_begin;
    const char* field;

    /* smtp commands always are always four characters long, so if a shorter
     * command is found, complain a bit. */
    if (cmd_len < 4) {
        send_string(socket, "500 What the hell are you smoking? SMTP commands are not that short!\r\n");
        return;
    }

    /* copy the base command string from the command code and convert it to
     * lowercase characters. */
    base_cmd[0] = tolower(cmd[0]);
    base_cmd[1] = tolower(cmd[1]);
    base_cmd[2] = tolower(cmd[2]);
    base_cmd[3] = tolower(cmd[3]);
    base_cmd[4] = 0;

    /* find the beginning of the field data, ignoring what is in between */
    field_begin = 0;
    if (cmd[4] == ' ') {
        for (i=5; i<cmd_len; i++)
            if (cmd[i] == ':') {
                field_begin = i + 1;
                break;
            }
    }
    field = field_begin ? (cmd + field_begin) : NULL;

    /* now let's check the command */
    if (!strcmp(base_cmd, "quit")) {
        /* QUIT issued, done and exit */
        goto done;
    }
    if (!strcmp(base_cmd, "helo")) {
        /* HELO issued, respond with a greeting */
        send_string(socket, "250 Hi to you too!\r\n");
        goto done;
    }
    if (!strcmp(base_cmd, "turn")) {
        /* TURN issued, refuse to turn */
        send_string(socket, "502 Not today honey\r\n");
        goto done;
    }
    if (!strcmp(base_cmd, "noop")) {
        /* NOOP issued, do nothing */
        send_string(socket, "250 Ok\r\n");
        goto done;
    }
    if (!strcmp(base_cmd, "rset")) {
        /* RSET issued, let's forget what we were doing */
        delst_init(delst);
        send_string(socket, "250 Ok\r\n");
        goto done;
    }
    if (!strcmp(base_cmd, "mail")) {
        /* MAIL issued, let's check it and begin a new mail delivery */
        if (!field || !field[0]) {
            /* no field data, complain */
            send_string(socket, "501 Nice try but you forgot to tell me who you are\r\n");
            goto done;
        }
        /* currently we don't care from where the data came but anyway */
        delst_init(delst);
        delst->from = strdup(field);
        send_string(socket, "250 Ok\r\n");
        goto done;
    }
    if (!strcmp(base_cmd, "rcpt")) {
        /* RCPT issued, let's check it and add the recipients to delst */
        process_rcpt(socket, delst, field);
        goto done;
    }
    if (!strcmp(base_cmd, "vrfy")) {
        /* VRFY issued, let's check the username */
        if (accept_user(field)) {
            /* user is known, compose the reply */
            const char* domain = script_get_var("domain", "localhost");
            char* full = malloc(strlen(field) + strlen(domain) + 16);
            if (!full) {
                /* out of memory, abort */
                send_string(socket, "451 I've ran out of memory, oh no!\r\n");
                goto done;
            }
            sprintf(full, "250 %s@%s\r\n", field, domain);
            send_string(socket, full);
            free(full);
        } else {
            /* unknown user, but let's assume its ok */
            send_string(socket, "252 I couldn't find the user around, but anyway we're all friends here aren't we?\r\n");
        }
        goto done;
    }
    if (!strcmp(base_cmd, "data")) {
        /* DATA issued, let's gather said data! */
        gather_data(socket, delst);
        goto done;
    }

    send_string(socket, "502 I haven't been bothered yet to implement this command, sorry...\r\n");

    /* common release code */
done: ;
}

/*
 * Communicates with the given client socket.
 */
static void communicate(socket_t socket)
{
    char* cmd = NULL;
    char* new_cmd;
    int cmd_len = 0;
    int tries = 0;
    int max_smtp_command_length;
    delivery_status_t delst;
    int looping = 1;

    /* initialize the delivery status structure even if this will be done later
     * again when the MAIL command is parsed because it is possible to get
     * commands which use it before the MAIL command - probably in error */
    memset(&delst, 0, sizeof(delivery_status_t));

    /* get maximum command length value */
    max_smtp_command_length = atoi(script_get_var("max-smpt-command-length", "1024"));
    if (max_smtp_command_length < 512) max_smtp_command_length = 512;

    /* send the initial greeting */
    if (!send_greeting(socket)) return;

    /* command loop */
    while (looping) {
        char buff[1024];
        int bytes_read;
        int i;

        /* try to read some data */
        bytes_read = read(socket, buff, sizeof(buff));
        if (bytes_read == 0) {
            /* connection closed, let's break */
            break;
        }
        if (bytes_read == -1) {
            /* something went wrong, let's retry a few times and break later*/
            if (++tries == 32) break;
            continue;
        }
        tries = 0;

        /* process the data */
        for (i=0; i<bytes_read; i++) {
            if (buff[i] == '\n') {
                /* found a newline \n */
                new_cmd = realloc(cmd, cmd_len + 1);
                if (!new_cmd) {
                    /* out of memory, abort */
                    send_string(socket, "451 I've ran out of memor... what?\r\n");
                    looping = 0;
                    break;
                }
                cmd = new_cmd;
                cmd[cmd_len] = 0;
                /* parse the command */
                parse_smtp_command(socket, &delst, cmd, cmd_len);
                /* prepare for a new one */
                free(cmd);
                cmd = NULL;
                cmd_len = 0;
            } else if (buff[i] == '\r') {
                /* ignore CRs */
            } else {
                /* found... something else - put it in the command, as long as
                 * the command's length is not as large as the maximum value */
                if (max_smtp_command_length > cmd_len) {
                    new_cmd = realloc(cmd, cmd_len + 1);
                    if (!new_cmd) {
                        /* out of memory, abort */
                        send_string(socket, "451 I've ran out of memo... who are you?\r\n");
                        looping = 0;
                        break;
                    }
                    cmd = new_cmd;
                    cmd[cmd_len++] = buff[i];
                }
            }
        }
    }

    delst_release(&delst);

    free(cmd);
}

/*
 * Starts listening for incoming SMTP connections. This call blocks the
 * program.
 */
int smtp_start_listening(void)
{
    struct addrinfo hints;
    struct addrinfo* servinfo = NULL;
    struct addrinfo* p = NULL;
    int yes = 1, listen_queue_size;
    struct sigaction sa;

    /* close previous socket, if any */
    if (smtp_server_socket) close(smtp_server_socket);
    smtp_server_socket = 0;

    /* get local address info */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, script_get_var("port", "25"), &hints, &servinfo) != 0) goto cleanup;

    /* find a usable address */
    for (p=servinfo; p; p=p->ai_next) {
        /* create smtp listening socket */
        smtp_server_socket = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
        if (smtp_server_socket == -1) continue;

        /* inform the system that the sockets can reuse addresses - this is done so
         * that in the case the server exits or crashes it will be able to reuse
         * the address immediatelly instead of waiting for a while until being able
         * to do so */
        if (setsockopt(smtp_server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            close(smtp_server_socket);
            smtp_server_socket = 0;
            continue;
        }

        /* bind the socket to the address */
        if (bind(smtp_server_socket, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
            close(smtp_server_socket);
            smtp_server_socket = 0;
            continue;
        }

        /* all nice */
        break;
    }

    /* abort if all addresses were not available */
    if (!p) goto cleanup;

    /* release unneeded resource */
    freeaddrinfo(servinfo);
    servinfo = NULL;

    /* start listening for incoming connections */
    listen_queue_size = atoi(script_get_var("listen-queue-size", "5"));
    if (!listen_queue_size) listen_queue_size = 5;
    if (listen(smtp_server_socket, listen_queue_size) == -1) goto cleanup;

    /* setup SIGCHLD so that we wait for childrens and avoid zombies */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) goto cleanup;

    /* inform the user we're listening */
    printf("smutport: listening for connections at port %s\n", script_get_var("port", "25"));

    /* main listening loop */
    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        int r;

        /* if there are children waiting for attention, give them some */
        if (sigchld_issued) {
            while (waitpid(-1, NULL, WNOHANG) > 0);
            sigchld_issued = 0;
        }

        /* wait for a connection and accept it once it comes */
        socket_t client_socket = accept(smtp_server_socket, (struct sockaddr*)&client_addr, &client_addr_size);
        if (client_socket == -1) continue;

        /* a connection came, let's fork */
        r = fork();
        if (r == -1) { /* fail */
            close(client_socket);
            continue;
        } else if (r == 0) {
            /* close unneeded listening server socket */
            close(smtp_server_socket);
            /* communicate with the client */
            communicate(client_socket);
            /* done, cleanup and go away */
            close(client_socket);
            exit(0);
        } else {
            /* close the client socket */
            close(client_socket);
        }
    }

    return 1;

    /* cleanup code in case something went wrong */
cleanup:
    if (smtp_server_socket) close(smtp_server_socket);
    smtp_server_socket = 0;
    if (servinfo) freeaddrinfo(servinfo);
    return 0;
}
