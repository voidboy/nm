#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
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

typedef struct Elf32 {
    const Elf32_Ehdr *ehdr;
    const Elf32_Phdr *phdr; /* unused */
    const Elf32_Shdr *shdr;
}   s_Elf32;

typedef struct Elf64 {
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr; /* unused */
    const Elf64_Shdr *shdr;
}   s_Elf64;

typedef union ElfN {
    s_Elf32 e32; 
    s_Elf64 e64; 
}   u_ElfN;

typedef struct meta {
    u_ElfN          meta;
    unsigned char   arch;
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

char *initElf32(s_meta *meta, const uint8_t *mapped_file,
                long unsigned int fileSize)
{
    /* we do not need to check file size because we already
       checked it when entering parse() */
    meta->arch = ELFCLASS32;
    meta->meta.e32.ehdr = (Elf32_Ehdr *)mapped_file;
    /* === PROGRAM HEADER === */
    Elf32_Off programHeaderOffset = meta->meta.e32.ehdr->e_phoff;
    /* phdr won't be used */
    if (programHeaderOffset > fileSize ||
        programHeaderOffset + sizeof(Elf32_Phdr) * meta->meta.e32.ehdr->e_phnum > fileSize ||
        meta->meta.e32.ehdr->e_phentsize != sizeof(Elf32_Phdr))
        return EHEAD;
    DEBUG("[DEBUG] - phdr is @0x%x\n", programHeaderOffset);
    /* === SECTION HEADER === */
    Elf32_Off sectionHeaderOffset = meta->meta.e32.ehdr->e_shoff;
    if (sectionHeaderOffset > fileSize ||
        sectionHeaderOffset + sizeof(Elf32_Shdr) * meta->meta.e32.ehdr->e_shnum > fileSize ||
        meta->meta.e32.ehdr->e_shentsize != sizeof(Elf32_Shdr))
        return EHEAD;
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
    Elf64_Off programHeaderOffset = meta->meta.e64.ehdr->e_phoff;
    /* phdr won't be used */
    if (programHeaderOffset > fileSize || 
        programHeaderOffset + sizeof(Elf64_Phdr) * meta->meta.e64.ehdr->e_phnum > fileSize ||
        meta->meta.e64.ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return EHEAD;
    meta->meta.e64.phdr = (Elf64_Phdr *)&mapped_file[programHeaderOffset];
    DEBUG("[DEBUG] - phdr is @0x%lx\n", programHeaderOffset);
    /* === SECTION HEADER === */
    Elf64_Off sectionHeaderOffset = meta->meta.e64.ehdr->e_shoff;
    if (sectionHeaderOffset > fileSize || 
        sectionHeaderOffset + sizeof(Elf64_Shdr) * meta->meta.e64.ehdr->e_shnum > fileSize ||
        meta->meta.e64.ehdr->e_shentsize != sizeof(Elf64_Shdr))
        return EHEAD;
    meta->meta.e64.shdr = (Elf64_Shdr *)&mapped_file[sectionHeaderOffset];  
    DEBUG("[DEBUG] - shdr is @0x%lx\n", sectionHeaderOffset);
    /* === SYMBOL TABLE === */
    const unsigned int index = meta->meta.e64.ehdr->e_shstrndx;
    if (index > meta->meta.e64.ehdr->e_shnum)
        return EHEAD;
    const unsigned int offset = meta->meta.e64.shdr[index].sh_offset;
    if (offset > fileSize)
        return EHEAD;
    const char *names = (const char *)&mapped_file[offset];
    if (DEBUGGING)
        for (const char *name = &names[1]; *name; name++)
            DEBUG("[DEBUG] - @%p %s\n", name, name);
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
