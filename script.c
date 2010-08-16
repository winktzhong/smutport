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

lil_t lil;

/*
 * Registers script functions.
 */
static void register_functions(void)
{
}

/*
 * Initialize scripting.
 */
void script_init(void)
{
    if (lil) script_shutdown();
    lil = lil_new();
    register_functions();
    script_run_file(INIT_SCRIPT_PATH);
}

/*
 * Shutdown scripting.
 */
void script_shutdown(void)
{
    lil_free(lil);
    lil = NULL;
}

/*
 * Returns the value of the lil variable with the given name. Returns the
 * "defvalue" value if the variable is not defined or has an empty string.
 */
const char* script_get_var(const char* name, const char* defvalue)
{
    const char* r = lil_to_string(lil_get_var(lil, name));
    return r[0] ? r : defvalue;
}

/*
 * Runs a LIL script command. Returns the lil value or NULL. If there is an
 * error it is printed in stderr.
 */
lil_value_t script_run_command(const char* command)
{
    lil_value_t retval = lil_parse(lil, command, 0, 0);
    size_t pos;
    const char* msg;
    if (lil_error(lil, &msg, &pos)) {
        fprintf(stderr, "lil error at %i: %s\n", (int)pos, msg);
        lil_free_value(retval);
        return NULL;
    }
    return retval;
}

/*
 * Runs a LIL script file.
 */
void script_run_file(const char* filename)
{
    /* the script execution is done in a very simple way: we compose a
     * temporary [source {<filename>}] command and execute it via lil which
     * goes through the whole pain to load and parse the code. */
    char* tmpcode = malloc(strlen(filename) + 256);
    lil_value_t retval;
    if (!tmpcode) return; /* failed :-( */
    sprintf(tmpcode, "source {%s}", filename);
    retval = script_run_command(tmpcode);
    free(tmpcode);
    lil_free_value(retval);
}
