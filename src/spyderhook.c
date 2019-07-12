#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "spyderhook.h"
#include "pidlist.c"

const char * const spyderhook_version = "0.1.0";

#define debug(fmt, args...) do { \
    if(verbose){ \
        fprintf(stderr, "* " fmt, ##args); \
    } \
} while(0)

#define default_opts \
    PTRACE_O_TRACESYSGOOD | \
    PTRACE_O_TRACEEXEC | \
    PTRACE_O_TRACEEXIT

enum {
    syscall_enter = 1,
    syscall_stop,
    syscall_leave
};

struct event_desc {
    int event;
    char *desc;
};

static long attach_opts = default_opts;
static int verbose;

static int execve_attach(spyderhook_t *hook);
static plist_t *wait_syscall(plist_t **list, plist_t *cpid);
static int ptrace_seize(pid_t pid, unsigned long opts);

spyderhook_t *sh_init(void){
    return calloc(1, sizeof(spyderhook_t));
}

void sh_free(spyderhook_t *hook){
    free(hook);
}

const char *ptrace_str_event(int ev){
    static struct event_desc ed[]={
        {PTRACE_EVENT_FORK, "PTRACE_EVENT_FORK"},
        {PTRACE_EVENT_VFORK, "PTRACE_EVENT_VFORK"},
        {PTRACE_EVENT_CLONE, "PTRACE_EVENT_CLONE"},
        {PTRACE_EVENT_EXEC, "PTRACE_EVENT_EXEC"},
        {PTRACE_EVENT_VFORK_DONE, "PTRACE_EVENT_VFORK_DONE"},
        {PTRACE_EVENT_EXIT, "PTRACE_EVENT_EXIT"},
        {PTRACE_EVENT_SECCOMP, "PTRACE_EVENT_SECCOMP"},
        {PTRACE_EVENT_STOP, "PTRACE_EVENT_STOP"},
    };

    size_t i;
    for(i=0; i<sizeof(ed)/sizeof(struct event_desc); i++){
        if(ev == ed[i].event){
            return ed[i].desc;
        }
    }

    return "unknown";
}

const char *sh_strerror(int err){
    static const char *str[]={
        "success",
        "missing pid/filename",
        "you can't set a pid and a filename at same time",
        "failed to attach pid",
        "fork failed",
        "unknown"
    };

    if((size_t)err >= sizeof(str)/sizeof(char *) || err < 0){
        err = sizeof(str)/sizeof(char *)-1;
    }

    return str[err];
}

int sh_setopt(spyderhook_t *hook, int opt, ...){
    va_list ap;
    va_start(ap, opt);

    switch(opt){
        case SHOPT_PID:
            hook->pid = va_arg(ap, pid_t);
            break;

        case SHOPT_FILENAME:
            hook->filename = va_arg(ap, char *);
            break;

        case SHOPT_ARGV:
            hook->argv = va_arg(ap, char * const *);
            break;

        case SHOPT_ENVP:
            hook->envp = va_arg(ap, char * const *);
            break;

        case SHOPT_ENTER_CALLBACK:
            hook->syscall_enter = va_arg(ap, sh_callback_t);
            break;

        case SHOPT_RESULT_CALLBACK:
            hook->syscall_leave = va_arg(ap, sh_callback_t);
            break;

        case SHOPT_AUXPTR:
            hook->aux_ptr = va_arg(ap, void *);
            break;

        case SHOPT_PTRACE_OPTS:
            hook->ptrace_opts = va_arg(ap, long);
            break;

        case SHOPT_VERBOSE:
            verbose = 1;
            break;

        case SHOPT_FOLLOW_ALL:
            attach_opts |= PTRACE_O_TRACECLONE|
                PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK;
            break;

        default:
            va_end(ap);
            return 1;
    }

    va_end(ap);
    return 0;
}

unsigned long sh_getreg(pid_t pid, int reg){
    return ptrace(PTRACE_PEEKUSER, pid, reg*sizeof(long), 0);
}

unsigned long sh_setreg(pid_t pid, int reg, unsigned long data){
    return ptrace(PTRACE_POKEUSER, pid, reg*sizeof(long), data);
}

static int ptrace_seize(pid_t pid, unsigned long opts){
    return ptrace(PTRACE_SEIZE, pid, NULL, opts);
}

int execve_attach(spyderhook_t *hook){
    pid_t pid;
    int status;

    pid = fork();
    if(pid == 0){
        kill(getpid(), SIGSTOP);

        execve(hook->filename, hook->argv, hook->envp);
        exit(1);
    }

    else if(pid == -1){
        return SH_FORK_ERROR;
    }

    waitpid(pid, &status, WSTOPPED);
    hook->pid = pid;

    return SH_SUCCESS;
}

int sh_mainloop(spyderhook_t *hook){
    plist_t *list = NULL;
    pidinfo_t *info;
    int status;
    pid_t pid;

    if(!hook->pid && !hook->filename)
        return SH_MISSING_OPT;

    if(hook->pid && hook->filename)
        return SH_ATTACH_CONFLICT;

    if(hook->filename){
        if((status = execve_attach(hook)) != SH_SUCCESS){
            return status;
        }
    }

    pid = hook->pid;

    debug("attaching pid: %d\n", pid);

    /* setting some ptrace options */
    if(ptrace_seize(pid, attach_opts|hook->ptrace_opts)){
        debug("failed to attach: %s\n", strerror(errno));
        return SH_ATTACH_PID_ERROR;
    }

    if(!hook->filename){
        ptrace(PTRACE_INTERRUPT, pid);
    }

    plist_t *cpid = plist_insert(&list, pid);

    /* 1 == main pid */
    cpid->info.flags = 1;

    while((cpid = wait_syscall(&list, cpid))){
        info = &(cpid->info);

        if(info->status == syscall_enter){
            if(hook->syscall_enter){
                status = hook->syscall_enter(info,
                    sh_getreg(info->pid, SH_SYSCALL_NR), hook->aux_ptr);
            }
        }

        else if(info->status == syscall_leave){
            info->status = 0;

            if(hook->syscall_leave){
                status = hook->syscall_leave(info,
                    sh_getreg(info->pid, SH_SYSCALL_NR), hook->aux_ptr);
            }
        }

        switch(status){
            case SH_CONTINUE:
                break;

            case SH_SKIP_SYSCALL:
                /* set syscall to an invalid number */
                sh_setreg(info->pid, SH_SYSCALL_NR, -1L);
                break;

            case SH_KILL:
                kill(info->pid, SIGKILL);
                cpid = NULL;
                break;

            case SH_DETACH:
                ptrace(PTRACE_CONT, info->pid, 0, 0);
                ptrace(PTRACE_DETACH, info->pid, 0, 0);
                plist_delete(&list, info->pid);
                cpid = NULL;
                break;

            default:
                debug("unknown status code from callback: %d\n", status);
        }
    }

    plist_destroy(list);

    return SH_SUCCESS;
}

plist_t *wait_syscall(plist_t **list, plist_t *cpid){
    int status, event;
    pidinfo_t *info;
    pid_t pid;

    while(*list){
        if(cpid)
            ptrace(PTRACE_SYSCALL, cpid->info.pid, 0, cpid->info.sig);

        wpid:
        if((pid = waitpid(-1, &status, __WALL)) == -1)
            break;

        cpid = plist_search(*list, pid);
        if(cpid == NULL){
            debug("new pid [%d] attached\n", pid);
            cpid = plist_insert(list, pid);

            /* should I use PTRACE_SETOPTIONS ? */
        }

        info = &(cpid->info);

        if(WIFSTOPPED(status)){
            info->sig = WSTOPSIG(status);
            if(info->sig == (SIGTRAP | 0x80)){
                info->sig = 0;

                if(info->status == 0){
                    info->status = syscall_enter;
                }

                else {
                    info->status = syscall_leave;
                }

                return cpid;
            }

            if(info->status == syscall_enter){
                info->status = syscall_stop;
            }
        }

        else if(WIFSIGNALED(status)){
            debug("[%d] +++ terminated with signal %d +++\n", pid, WTERMSIG(status));
            plist_delete(list, pid);
            cpid = NULL;

            continue;
        }

        else if(WIFEXITED(status)){
            debug("[%d] +++ exited with status %d +++\n", pid, WEXITSTATUS(status));
            plist_delete(list, pid);
            cpid = NULL;

            continue;
        }

        else {
            info->sig = 0;
        }

        /* there is no event, continue ... */
        if((event = status >> 16) == 0){
            if(info->sig){
                debug("[%d] signal received: %d\n", pid, info->sig);
            }

            continue;
        }

        debug("event: %d (%s), sig: %d\n", event, ptrace_str_event(event), info->sig);

        switch(event){
            case PTRACE_EVENT_STOP:
                switch(info->sig){
                    case SIGSTOP:
                    case SIGTSTP:
                    case SIGTTIN:
                    case SIGTTOU:
                        debug("ptrace_listen(%d)\n", pid);
                        ptrace(PTRACE_LISTEN, pid);
                        info->sig = 0;
                        goto wpid;
                    break;

                    default:
                        info->sig = 0;
                }
                break;

            default:
                info->sig = 0;
        }
    }

    return NULL;
}
