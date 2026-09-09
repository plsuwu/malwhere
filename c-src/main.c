#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define PID_STRLEN_MAX 64
#define PROC_DIR "/proc"
#define NUL_TERM '\0'

#define CURR_DIR "."
#define PREV_DIR ".."

int is_relative_dir(const char *dirname) {
    int res_curr;
    int res_prev;

    if ((res_curr = memcmp(CURR_DIR, dirname, 1) != 0)
        && (res_prev = memcmp(PREV_DIR, dirname, 2)) != 0)
    {
        return -1;
    }

    return 0;
}

int is_all_ascii_digit(const char *str, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return -1;
        }
    }

    return 0;
}

typedef struct {
    int start;
    int end;
} line_bounds;

int get_line_size(char *line, line_bounds *bounds) {
    if (bounds == NULL || line == NULL) {
        perror("get_line_size");
        return -1;
    }

    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == ' ') {
            if (bounds->start == -1) {
                bounds->start = i + 1;
            } else {
                bounds->end = i;
                break;
            }
        }
    }

    return 0;
}

int get_protections_from_line(char *line, char *buf, line_bounds *bounds) {
    if (buf == NULL || bounds == NULL) {
        perror("get_protections_from_line");
        return -1;
    }

    for (size_t i = bounds->start, j = 0; i < (size_t)bounds->end; i++, j++) {
        buf[j] = line[i];
    }

    buf[bounds->end - bounds->start] = '\0';
    return 0;
}

void init_bounds(line_bounds *b) {
    b->start = -1;
    b->end = -1;
}

/// Retrieve a list of running processes
int mctl_get_proclist(void) {
    struct dirent *entry;
    char maps_fpath[PATH_MAX + 1];
    DIR *procdir;
    FILE *maps_file;
    size_t maps_line_len;
    char *protections;
    line_bounds maps_line_bounds;
    char *maps_line = NULL;

    procdir = opendir(PROC_DIR);
    if (procdir == NULL) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(procdir)) != NULL) {
        if (is_relative_dir(entry->d_name) == 0) {
            continue;
        }

        if (!(entry->d_type & DT_DIR)) {
            printf("%s: not a directory\n", entry->d_name);
            continue;
        }

        if (snprintf(
                maps_fpath,
                PID_STRLEN_MAX,
                "%s/%s/maps",
                PROC_DIR,
                entry->d_name
            )
            < 0)
        {
            perror("snprintf");
            return -1;
        }

        if (access(maps_fpath, F_OK) < 0) {
            printf("%s: not a file\n", maps_fpath);
            continue;
        }

        printf("maps_fpath=%s\n", maps_fpath);

        errno = 0;
        if ((maps_file = fopen(maps_fpath, "r")) == NULL) {
            if (errno == EACCES) {
                printf("%s: permission denied\n", maps_fpath);
                continue;
            }

            perror("fopen");
            return -1;
        }

        while (getline(&maps_line, &maps_line_len, maps_file) != -1) {
            init_bounds(&maps_line_bounds);

            if (get_line_size(maps_line, &maps_line_bounds) < 0
                || maps_line_bounds.start == -1 || maps_line_bounds.end == -1)
            {
                perror("get_line_size");
                return -1;
            }

            protections =
                malloc(maps_line_bounds.end - maps_line_bounds.start + 1);
            if (protections == NULL) {
                perror("malloc (protections buffer)");
                return -1;
            }

            if ((get_protections_from_line(
                    maps_line,
                    protections,
                    &maps_line_bounds
                ))
                < 0)
            {
                continue;
            }
            
            if (protections[0] == 'r' && protections[2] == 'x') {
                
            }
            // printf("prot -> %s\n", protections);
        }
    }

    closedir(procdir);
    return 0;
}

int main(void) {
    if (mctl_get_proclist() < 0) {
        perror("mctl_list_procs");
        return 1;
    }

    return 0;
}
