#include <ctype.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifndef DEBUGGING
    #define DEBUGGING 0
#endif
#define DEBUG(fmt, ...) \
            do { if (DEBUGGING) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

#define DEFAULT "a.out"
#define OK +1
#define KO -1
#define ESIGN "invalid file signature"
#define EHEAD "invalid header"

typedef struct symbol {
    bool            used;
    unsigned char   bind;
    unsigned char   type;
    Elf64_Addr      addr;
    const char      *name;
}   s_symbol;

typedef struct Elf32 {
    const Elf32_Ehdr    *ehdr;
    const Elf32_Phdr    *phdr; 
    const Elf32_Shdr    *shdr;
    const Elf32_Sym     *symb;
    s_symbol            *sort;
}   s_Elf32;

typedef struct Elf64 {
    const Elf64_Ehdr    *ehdr;
    const Elf64_Phdr    *phdr; 
    const Elf64_Shdr    *shdr;
    const Elf64_Sym     *symb;
    s_symbol            *sort;
}   s_Elf64;

typedef union ElfN {
    s_Elf32 e32; 
    s_Elf64 e64; 
}   u_ElfN;

typedef struct meta {
    u_ElfN          meta;
    unsigned char   arch;
    const char      *secNames;
    const char      *symNames;
} s_meta; 


void error(const char *filename)
{
    dprintf(STDERR_FILENO, "ft_nm: '%s': %s\n",
            filename, strerror(errno));
}

void fatal(const char *filename, const char *msg)
{

    dprintf(STDERR_FILENO, "ft_nm: '%s': %s\n",
            filename, msg);
}

void swap_symbols(s_symbol *s1, s_symbol *s2)
{
    s_symbol tmp = *s1;

    *s1 = *s2;
    *s2 = tmp;
}

int symb_cmpr(const char *s1, const char *s2)
{
    while (*s1 == '_') { s1++; };
    while (*s2 == '_') { s2++; };
    while (*s1 && *s2 && tolower(*s1) == tolower(*s2))
    {
        s1++;
        s2++; 
    }
    return tolower(*s1) - tolower(*s2);
}

void sort_symbols(s_meta *meta)
{
    s_symbol *sym = meta->meta.e64.sort;

    for (unsigned int i = 0; meta->meta.e64.sort[i].used ; i++)
    {
        for (unsigned int j = 0; meta->meta.e64.sort[j].used ; j++)
            if (symb_cmpr(sym[i].name, sym[j].name) < 0)
            {
                DEBUG("[DEBUG] - swapping %s with %s\n", sym[i].name, sym[j].name);
                swap_symbols(&sym[i], &sym[j]);
            }
    }
}

int is_valid_phdr(s_meta *meta, long unsigned int fileSize)
{

    if (meta->arch == ELFCLASS32)
    {
        Elf32_Off programHeaderOffset = meta->meta.e32.ehdr->e_phoff;

        if (programHeaderOffset > fileSize || 
            programHeaderOffset + sizeof(Elf32_Phdr) * meta->meta.e32.ehdr->e_phnum > fileSize ||
            meta->meta.e32.ehdr->e_phentsize != sizeof(Elf32_Phdr))
            return KO;
        else
            return OK;
    }
    if (meta->arch == ELFCLASS64)
    {
        Elf64_Off programHeaderOffset = meta->meta.e64.ehdr->e_phoff;

        if (programHeaderOffset > fileSize || 
            programHeaderOffset + sizeof(Elf64_Phdr) * meta->meta.e64.ehdr->e_phnum > fileSize ||
            meta->meta.e64.ehdr->e_phentsize != sizeof(Elf64_Phdr))
            return KO;
        else
            return OK;
    }
    return KO;
}

int is_valid_shdr(s_meta *meta, long unsigned int fileSize)
{
    if (meta->arch == ELFCLASS32)
    {
        Elf32_Off sectionHeaderOffset = meta->meta.e32.ehdr->e_shoff;

        if (sectionHeaderOffset > fileSize ||
            sectionHeaderOffset + sizeof(Elf32_Shdr) * meta->meta.e32.ehdr->e_shnum > fileSize ||
            meta->meta.e32.ehdr->e_shentsize != sizeof(Elf32_Shdr))
            return KO;
        else
            return OK;
    }
    if (meta->arch == ELFCLASS64)
    {
        Elf64_Off sectionHeaderOffset = meta->meta.e64.ehdr->e_shoff;

        if (sectionHeaderOffset > fileSize || 
            sectionHeaderOffset + sizeof(Elf64_Shdr) * meta->meta.e64.ehdr->e_shnum > fileSize ||
            meta->meta.e64.ehdr->e_shentsize != sizeof(Elf64_Shdr))
            return KO;
        else
            return OK;
     
    }
    return KO;
}


char *initElf32(s_meta *meta, const uint8_t *mapped_file,
                long unsigned int fileSize)
{
    /* we do not need to check file size because we already
       checked it when entering parse() */
    meta->arch = ELFCLASS32;
    meta->meta.e32.ehdr = (Elf32_Ehdr *)mapped_file;
    /* === PROGRAM HEADER === */
    if (!is_valid_phdr(meta, fileSize)) return EHEAD;
    Elf32_Off programHeaderOffset = meta->meta.e32.ehdr->e_phoff;
    DEBUG("[DEBUG] - phdr is @0x%x\n", programHeaderOffset);
    /* === SECTION HEADER === */
    if (!is_valid_shdr(meta, fileSize)) return EHEAD;
    Elf32_Off sectionHeaderOffset = meta->meta.e32.ehdr->e_shoff;
    DEBUG("[DEBUG] - shdr is @0x%x\n", sectionHeaderOffset);
    return NULL;
}

char *initElf64(s_meta *meta, const uint8_t *mapped_file,
                long unsigned int fileSize)
{
    if (fileSize < sizeof(Elf64_Ehdr))
        return EHEAD;
    meta->arch = ELFCLASS64;
    meta->meta.e64.ehdr = (Elf64_Ehdr *)mapped_file;
    /* === PROGRAM HEADER === */
    if (!is_valid_phdr(meta, fileSize)) return EHEAD;
    Elf64_Off programHeaderOffset = meta->meta.e64.ehdr->e_phoff;
    meta->meta.e64.phdr = (Elf64_Phdr *)&mapped_file[programHeaderOffset];
    DEBUG("[DEBUG] - phdr is @0x%lx\n", programHeaderOffset);
    /* === SECTION HEADER === */
    if (!is_valid_shdr(meta, fileSize)) return EHEAD;
    Elf64_Off sectionHeaderOffset = meta->meta.e64.ehdr->e_shoff;
    meta->meta.e64.shdr = (Elf64_Shdr *)&mapped_file[sectionHeaderOffset];  
    DEBUG("[DEBUG] - shdr is @0x%lx\n", sectionHeaderOffset);
    /* === SYMBOL TABLE === */
    const unsigned int index = meta->meta.e64.ehdr->e_shstrndx;
    if (index > meta->meta.e64.ehdr->e_shnum)
        return EHEAD;
    const unsigned int offset = meta->meta.e64.shdr[index].sh_offset;
    if (offset > fileSize)
        return EHEAD;
    meta->secNames = (const char *)&mapped_file[offset];
    for (unsigned int i = 0; i < meta->meta.e64.ehdr->e_shnum; i++)
    {
        /* .bss SHT_NOBITS SHF_ALLOC + SHF_WRITE */
        if (meta->meta.e64.shdr[i].sh_type == SHT_NOBITS &&
            (meta->meta.e64.shdr[i].sh_flags ==  (SHF_ALLOC | SHF_WRITE)) &&
            !strcmp(".bss", &meta->secNames[meta->meta.e64.shdr[i].sh_name]))
        {

            DEBUG("[DEBUG] - bss section(%s) @%lx\n",
                &meta->secNames[meta->meta.e64.shdr[i].sh_name],
                meta->meta.e64.shdr[i].sh_offset);
        }
        /* text */
        else if (meta->meta.e64.shdr[i].sh_type == SHT_PROGBITS &&
            !strcmp(".text", &meta->secNames[meta->meta.e64.shdr[i].sh_name]))
        {

            DEBUG("[DEBUG] - text section(%s) @%lx\n",
                &meta->secNames[meta->meta.e64.shdr[i].sh_name],
                meta->meta.e64.shdr[i].sh_offset);
        }
        /* symbol */
        else if (meta->meta.e64.shdr[i].sh_type == SHT_SYMTAB &&
            !strcmp(".symtab", &meta->secNames[meta->meta.e64.shdr[i].sh_name]))
        {
            DEBUG("[DEBUG] - symbol section(%s) @%lx\n",
                &meta->secNames[meta->meta.e64.shdr[i].sh_name],
                meta->meta.e64.shdr[i].sh_offset);
            /* sh_link contains symbols name sections index */
            meta->meta.e64.symb = (Elf64_Sym *)&mapped_file[meta->meta.e64.shdr[i].sh_offset];
            
            meta->symNames = (const char *)&mapped_file[
                                        meta->meta.e64.shdr[meta->meta.e64.shdr[i].sh_link]
                                        .sh_offset];
            const unsigned int symbols_nbr = meta->meta.e64.shdr[i].sh_size /
                                            meta->meta.e64.shdr[i].sh_entsize;
            meta->meta.e64.sort = malloc(sizeof(s_symbol) * (symbols_nbr + 1));
            for (unsigned int j = 0; j < symbols_nbr; j++)
                meta->meta.e64.sort[j] = (s_symbol) {.used = false} ;
            for (unsigned int j = 0, k = 0; j < symbols_nbr; j++)
            {
                unsigned char   bind = ELF64_ST_BIND(meta->meta.e64.symb[j].st_info);
                unsigned char   type = ELF64_ST_TYPE(meta->meta.e64.symb[j].st_info);

                if (meta->meta.e64.symb[j].st_name && type != STT_FILE)
                {
                    const char*     name = &meta->symNames[meta->meta.e64.symb[j].st_name];
                    unsigned long   addr = meta->meta.e64.symb[j].st_value;

                    meta->meta.e64.sort[k++] = (s_symbol) {true, bind, type, addr, name};

               }
            }
            sort_symbols(meta);
            for (unsigned int j = 0; meta->meta.e64.sort[j].used ; j++)
            {
                const s_symbol current = meta->meta.e64.sort[j];

                if (current.addr)
                    printf("%42s %016lx %d %d\n", current.name, current.addr, current.bind, current.type);
                else
                    printf("%42s %16s %d %d\n", current.name, "", current.bind, current.type);
            }
        }
    }
    return NULL;
}

char *parse(const uint8_t *mapped_file, long unsigned int fileSize)
{
    s_meta  meta;
    char    *err;

    /* file size should be checked according to the ELF file 
    standard, whats the minimum valid file, Ehdr + Phdr + Shdr ? */
    (void)fileSize;

    /* check minimal size, magic number and signature */
    if (fileSize < sizeof(Elf32_Ehdr) ||
        mapped_file[0] != 0x7f ||
        strncmp((const char *)&mapped_file[1], "ELF", 3))
        return ESIGN;
    /* architecture */
    switch (mapped_file[4]) 
    {
        case ELFCLASS32:
            DEBUG("[DEBUG] - 32 bit\n");
            if ((err = initElf32(&meta, mapped_file, fileSize)))
                return err;
            break ;
        case ELFCLASS64:
            DEBUG("[DEBUG] - 64 bit\n");
            if ((err = initElf64(&meta, mapped_file, fileSize)))
                return err;
            break ;
        case ELFCLASSNONE:
        default:
            return ESIGN;
    }
    return NULL;
}

int magic(const char *filename)
{
    char        *err;
    void        *mapped_file;
    struct stat fileInfo;
    long int    fileSize;
    int         fd;

    if ((fd = open(filename, O_RDONLY)) == -1)
        return KO;
    /* retrieve file size */
    if (fstat(fd, &fileInfo) == -1)
    {
        close(fd);
        return KO;
    }
    fileSize = fileInfo.st_size;
    /* st_size is a "off_t" which is an alias for 
       typedef long int __off_t (UBUNTU 5.14) */
    if (fileSize <= 0)
    {
        fatal(filename, "invalid file size");
        close(fd);
        return KO;
    }
    /* map file into memory */
    if ((mapped_file = mmap(NULL, fileSize, PROT_READ,
                            MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        close(fd);
        return KO;
    }
    if ((err = parse(mapped_file, fileSize)) != NULL)
        fatal(filename, err);
    munmap(mapped_file, fileSize);
    close(fd);
    return OK;
}

int main(int argc, char *argv[])
{
    if (argc == 1)
    {   
        if (magic("a.out") == -1)
            error("a.out");
    }
    else 
    {  
        for (int i = 1; i < argc; i++)
        {
            if (magic(argv[i]) == -1)
                error(argv[i]);
        }
    }
    return 0;
}
