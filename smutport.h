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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <netdb.h>
#include <ctype.h>
#include <lil.h>

#define INIT_SCRIPT_PATH "smutportrc"

typedef int socket_t;

extern lil_t lil;
extern socket_t smtp_server_socket;

void script_init(void);
void script_shutdown(void);
const char* script_get_var(const char* name, const char* defvalue);
lil_value_t script_run_command(const char* command);
void script_run_file(const char* filename);

int smtp_start_listening(void);
