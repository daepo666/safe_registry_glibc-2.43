#include "libioP.h"
#include "secure_file_registry.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

typedef enum {
    SFILE_EMPTY = 0,
    SFILE_ALIVE = 1,
    SFILE_CLOSED = 2
} secure_file_state;

typedef struct secure_file_meta {
    FILE *fp;
    secure_file_type type;
    secure_file_state state;

    void *vtable;
    void *wide_data;
    void *wide_vtable;
} secure_file_meta;

#define MAX_SECURE_FILES 0x1000

typedef struct secure_registry_area {
    void *io_list_all_original;
    secure_file_meta entries[MAX_SECURE_FILES];
} secure_registry_area;

static secure_registry_area *secure_area;
static size_t secure_area_size;
static int secure_registry_initialized;

#define registry (secure_area->entries)

static size_t page_align_up(size_t size);
static void secure_registry_init(void);
static void secure_registry_write_begin(void);
static void secure_registry_write_end(void);
static secure_file_meta *registry_find(FILE *fp);
static int registry_find_empty_slot(void);
static size_t page_align_up(size_t size) {
    size_t page_size = 0x1000;
    return (size + page_size - 1) & ~(page_size - 1);
}

static void secure_registry_init(void) {
    if (secure_registry_initialized)
        return;

    secure_area_size = page_align_up(sizeof(secure_registry_area));

    secure_area = mmap(NULL,
                       secure_area_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);

    if (secure_area == MAP_FAILED)
        abort();

    memset(secure_area, 0, secure_area_size);

    if (mprotect(secure_area, secure_area_size, PROT_READ) != 0)
        abort();

    secure_registry_initialized = 1;
}

static void secure_registry_write_begin(void) {
    if (!secure_registry_initialized)
        abort();

    if (mprotect(secure_area, secure_area_size,
                 PROT_READ | PROT_WRITE) != 0)
        abort();
}

static void secure_registry_write_end(void) {
    if (!secure_registry_initialized)
        abort();

    if (mprotect(secure_area, secure_area_size,
                 PROT_READ) != 0)
        abort();
}

int secure_file_register(FILE *fp, secure_file_type type) {
    if (fp == NULL)
        return -1;

    if (!secure_registry_initialized)
        abort();

    if (registry_find(fp) != NULL)
        abort();

    int idx = registry_find_empty_slot();
    if (idx < 0)
        abort();

    secure_registry_write_begin();

    secure_file_meta *m = &registry[idx];

    m->fp = fp;
    m->type = type;
    m->state = SFILE_ALIVE;

    m->vtable = ((struct _IO_FILE_plus *)fp)->vtable;
    m->wide_data = fp->_wide_data;
    m->wide_vtable = fp->_wide_data ? fp->_wide_data->_wide_vtable : NULL;

    secure_registry_write_end();

    return 0;
}

int secure_file_system_init(void) {
    secure_registry_init();

    secure_file_register((FILE *)&_IO_2_1_stdin_,  SFILE_STD);
    secure_file_register((FILE *)&_IO_2_1_stdout_, SFILE_STD);
    secure_file_register((FILE *)&_IO_2_1_stderr_, SFILE_STD);

    secure_registry_write_begin();
    secure_area->io_list_all_original = _IO_list_all;
    secure_registry_write_end();

    return 0;
}

int secure_file_update(FILE *fp, secure_file_type new_type) {
    if (fp == NULL)
        return -1;

    if (!secure_registry_initialized)
        abort();

    secure_file_meta *m = registry_find(fp);
    if (m == NULL)
        abort();

    secure_registry_write_begin();

    m->type = new_type;
    m->vtable = ((struct _IO_FILE_plus *)fp)->vtable;
    m->wide_data = fp->_wide_data;
    m->wide_vtable = fp->_wide_data ? fp->_wide_data->_wide_vtable : NULL;

    secure_registry_write_end();

    return 0;
}

int secure_file_validate(FILE *fp) {
    if (fp == NULL)
        return -1;

    if (!secure_registry_initialized)
        abort();

    secure_file_meta *m = registry_find(fp);
    if (m == NULL)
        abort();

    if (m->state != SFILE_ALIVE)
        abort();

    if (m->vtable != ((struct _IO_FILE_plus *)fp)->vtable)
        abort();

    if (m->wide_data != fp->_wide_data)
        abort();

    void *cur_wide_vtable =
        fp->_wide_data ? fp->_wide_data->_wide_vtable : NULL;

    if (m->wide_vtable != cur_wide_vtable)
        abort();

    return 1;
}

int secure_file_delete(FILE *fp) {
    if (fp == NULL)
        return -1;

    if (!secure_registry_initialized)
        abort();

    secure_file_meta *m = registry_find(fp);

    if (m == NULL)
        abort();

    secure_registry_write_begin();

    memset(m, 0, sizeof(secure_file_meta));

    secure_registry_write_end();

    return 0;
}

static secure_file_meta *registry_find(FILE *fp) {
    if (!secure_registry_initialized)
        abort();

    for (int i = 0; i < MAX_SECURE_FILES; i++) {
        if (registry[i].state == SFILE_ALIVE &&
            registry[i].fp == fp) {
            return &registry[i];
        }
    }

    return NULL;
}

static int registry_find_empty_slot(void) {
    if (!secure_registry_initialized)
        abort();

    for (int i = 0; i < MAX_SECURE_FILES; i++) {
        if (registry[i].state != SFILE_ALIVE)
            return i;
    }

    return -1;
}