#ifndef SECURE_FILE_REGISTRY_H
#define SECURE_FILE_REGISTRY_H

#include <stdio.h>

typedef enum {
    SFILE_STD,
    SFILE_NORMAL,
    SFILE_WIDE,
    SFILE_COOKIE,
    SFILE_MMAPED
} secure_file_type;

int secure_file_system_init(void);
int secure_file_register(FILE *fp, secure_file_type type);
int secure_file_update(FILE *fp, secure_file_type new_type);
int secure_file_validate(FILE *fp);
int secure_file_delete(FILE *fp);

#endif