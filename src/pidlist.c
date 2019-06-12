#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

static plist_t *plist_insert(plist_t **list, pid_t);
static void plist_delete(plist_t **list, pid_t pid);
static plist_t *plist_search(plist_t *list, pid_t pid);
static void plist_destroy(plist_t *list);

plist_t *plist_insert(plist_t **list, pid_t pid){
    plist_t *aux;

    aux = calloc(1, sizeof(plist_t));
    if(aux == NULL){
        goto end;
    }

    aux->info.pid = pid;
    aux->next = *list;
    *list = aux;

    end:
    return aux;
}

plist_t *plist_search(plist_t *list, pid_t pid){
    plist_t *ret = NULL;

    while(list){
        if(list->info.pid == pid){
            ret = list;
            break;
        }

        list = list->next;
    }

    return ret;
}

void plist_delete(plist_t **list, pid_t pid){
    plist_t *prev, *aux;

    if(pid == 0)
        return;

    aux = *list;

    for(prev=NULL; aux; prev=aux, aux=aux->next){
        if(aux->info.pid == pid){
            if(prev == NULL){
                *list = aux->next;
            } else {
                prev->next = aux->next;
            }

            free(aux);
            break;
        }
    }

}

void plist_destroy(plist_t *list){
    plist_t *aux;

    while(list){
        aux = list->next;
        free(list);
        list = aux;
    }
}
