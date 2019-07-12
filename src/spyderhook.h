#ifndef __SPYDERHOOK_H__
#define __SPYDERHOOK_H__

#include <sys/types.h>
#include <sys/reg.h>

/* architecture specific definitions */

#ifdef __x86_64__
 #define SH_SYSCALL_NR ORIG_RAX
 #define SH_SYSCALL_RESULT RAX
 #define SH_FIRST_ARG RDI
 #define SH_SECOND_ARG RSI
 #define SH_THIRD_ARG RDX
 #define SH_FOURTH_ARG R10
 #define SH_FIFTH_ARG R8
 #define SH_SIXTH_ARG R9
#elif __i386__
 #define SH_SYSCALL_NR ORIG_EAX
 #define SH_SYSCALL_RESULT EAX
 #define SH_FIRST_ARG EBX
 #define SH_SECOND_ARG ECX
 #define SH_THIRD_ARG EDX
 #define SH_FOURTH_ARG ESI
 #define SH_FIFTH_ARG EDI
#endif

/* globals */

extern const char * const spyderhook_version;

/* enums */

enum {
    /* attach a specific pid */
    SHOPT_PID,

    /* filename for execute */
    SHOPT_FILENAME,

    /* set args to pass from execve */
    SHOPT_ARGV,

    /* set enviroment variables */
    SHOPT_ENVP,

    /* callback to execute before the syscall */
    SHOPT_ENTER_CALLBACK,

    /* callback to execute when the syscall return */
    SHOPT_RESULT_CALLBACK,

    /* an auxiliary pointer passed to callbacks */
    SHOPT_AUXPTR,

    /* additional options to ptrace */
    SHOPT_PTRACE_OPTS,

    /* print some information */
    SHOPT_VERBOSE,

    /* follow fork, vfork and clone */
    SHOPT_FOLLOW_ALL
};

enum {
    /* continue the program normally */
    SH_CONTINUE,

    /* dont execute the syscall */
    SH_SKIP_SYSCALL,

    /* detach all pids, and exit from sh_mainloop */
    SH_EXIT_LOOP,

    /* detach the current pid */
    SH_DETACH,

    /* sigkill the current pid */
    SH_KILL
};

enum {
    /* no errors */
    SH_SUCCESS,

    /* missing pid or filename to exec */
    SH_MISSING_OPT,

    /* pid and filename are set */
    SH_ATTACH_CONFLICT,

    /* failed to attach the pid */
    SH_ATTACH_PID_ERROR,

    /* fork failed */
    SH_FORK_ERROR
};

/* types */

typedef struct {
    pid_t pid;
    int status;
    int sig;
    int flags;
} pidinfo_t;

typedef struct plist {
    pidinfo_t info;
    struct plist *next;
} plist_t;

typedef int (*sh_callback_t)(pidinfo_t *, unsigned long, void *);

typedef struct sh_handle {
    /* pid to attach */
    pid_t pid;

    /* ptrace options */
    long ptrace_opts;

    /* aux ptr */
    void *aux_ptr;

    /* options for execve */
    char *filename;
    char * const *argv;
    char * const *envp;

    /* callbacks */
    sh_callback_t syscall_enter;
    sh_callback_t syscall_leave;
} spyderhook_t;

/* functions */

spyderhook_t *sh_init(void);
void sh_free(spyderhook_t *hook);

int sh_setopt(spyderhook_t *hook, int opt, ...);
int sh_mainloop(spyderhook_t *hook);

const char *sh_strerror(int err);

unsigned long sh_setreg(pid_t pid, int reg, unsigned long data);
unsigned long sh_getreg(pid_t pid, int reg);

#endif /* __SPYDERHOOK_H__ */
