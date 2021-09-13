#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>

#define NAME_LEN 128
#define buf_SZ 10000

int Currentfd = -1;
void *map_start; // will point to the start of the memory mapped file
struct stat fdBuff;

typedef struct
{
    char debug_mode;
    char file_name[NAME_LEN];
    int unit_size;
    unsigned char mem_buf[buf_SZ];
    size_t mem_count;
    Elf32_Ehdr *hdr;

} state;

struct fun_desc
{
    char *name;
    void (*fun)(state *);
};

void toggle_debug_mode(state *s)
{
    if (s->debug_mode == '0')
    {
        s->debug_mode = '1';
        printf("Debug flag now on\n");
    }
    else
    {
        s->debug_mode = '0';
        printf("Debug flag now off\n");
    }
}

void examine_elf_file(state *s)
{
    printf("please enter ELF file name: ");
    char buf_new_name[100];
    fgets(buf_new_name, 100, stdin);
    buf_new_name[strlen(buf_new_name) - 1] = '\0'; // replace the \n of the user input with null termination
    strcpy(s->file_name, buf_new_name);
    printf("\n");
    if (s->debug_mode == '1')
    {
        printf("Debug: ELF file name set to %s\n", s->file_name);
    }
    if (Currentfd > -1)
    {
        close(Currentfd);
    }
    Currentfd = open(s->file_name, O_RDWR);
    if (Currentfd < 0)
    {
        fprintf(stderr, "ERROR: couldn't open the file\n");
        return;
    }

    if (fstat(Currentfd, &fdBuff) < 0)
    {
        fprintf(stderr, "ERROR: couldn't read the file into fdBuff\n");
        close(Currentfd);
        Currentfd = -1;
        return;
    }
    if ((map_start = mmap(0, fdBuff.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, Currentfd, 0)) == MAP_FAILED)
    {
        fprintf(stderr, "ERROR: couldn't map the file\n");
        close(Currentfd);
        Currentfd = -1;
        return;
    }
    s->hdr = (Elf32_Ehdr *)map_start;
    if (s->hdr->e_ident[1] != 'E' || s->hdr->e_ident[2] != 'L' || s->hdr->e_ident[3] != 'F')
    {
        fprintf(stderr, "ERROR: File is not an ELF file");
        close(Currentfd);
        Currentfd = -1;
        munmap(map_start, fdBuff.st_size);
        return;
    }
    printf("------------------------------------\n");
    printf("Magic numbers: %x %x %x\n", s->hdr->e_ident[1], s->hdr->e_ident[2], s->hdr->e_ident[3]);
    printf("Data encoding scheme: %d\n", s->hdr->e_ident[5]);
    printf("Entry point: %#08x\n", s->hdr->e_entry);
    printf("Section header file offset: %#08x\n", s->hdr->e_shoff);
    printf("Number of section headers: %d\n", s->hdr->e_shnum);
    printf("Size of section headers: %d\n", s->hdr->e_shentsize);
    printf("Program header table offset: %d\n", s->hdr->e_phoff);
    printf("Number of program headers: %d\n", s->hdr->e_phnum);
    printf("Size of program headers: %d\n", s->hdr->e_phentsize);
}

void print_section_names(state *s)
{

    Elf32_Shdr *first_section = (Elf32_Shdr *)((int)(s->hdr) + (s->hdr->e_shoff));                          // pointer to the first section in the "section headers"
    int shstrtab_off = (((Elf32_Shdr *)((int)(s->hdr) + (s->hdr->e_shoff)))[s->hdr->e_shstrndx]).sh_offset; // the offset of the sections name
    char *shstrtab_start = (map_start + shstrtab_off);                                                      // pointer to the first spot of the shstrtab
    if (s->debug_mode == '1')
    {
        fprintf(stderr, "DEBUG:");
        fprintf(stderr, "we have %d sections\n", s->hdr->e_shnum);
        fprintf(stderr, "Section Header String Table Index(shstrndx): %d\n", s->hdr->e_shstrndx);
    }
    printf("Section Headers:\n");
    printf("[Nr] Name                  Addr      Offset    Size      Type\n");
    for (int i = 0; i < s->hdr->e_shnum; i++)
    {
        Elf32_Shdr *curr = &first_section[i];
        printf("[%2d] %-22s%-10x%-10x%-10x%-10x\n", i, shstrtab_start + first_section[i].sh_name, curr->sh_addr, curr->sh_offset, curr->sh_size, curr->sh_type);
    }
}

void print_symbols(state *s)
{
    Elf32_Shdr *first_section = (Elf32_Shdr *)((int)(s->hdr) + (s->hdr->e_shoff));                          // pointer to the first section in the "section headers"
    int shstrtab_off = (((Elf32_Shdr *)((int)(s->hdr) + (s->hdr->e_shoff)))[s->hdr->e_shstrndx]).sh_offset; // the offset of the sections name
    char *shstrtab_start = (map_start + shstrtab_off);                                                      // pointer to the first spot of the shstrtab
    Elf32_Shdr *symtab_sctn = NULL, *strtab_sctn = NULL;
    int sym_amount = 0;
    for (int i = 0; i < s->hdr->e_shnum; i++) // go throu all the sections in the section header
    {
        Elf32_Shdr *curr = &first_section[i];
        char *curr_name = shstrtab_start + curr->sh_name;
        if (strcmp(curr_name, ".symtab") == 0)
        {
            symtab_sctn = &first_section[i];
            sym_amount = (symtab_sctn->sh_size) / symtab_sctn->sh_entsize; // num_of_symbols = sections_size div section_entsize (Entry size if section holds ta)
        }
        else if (strcmp(curr_name, ".strtab") == 0)
        {
            strtab_sctn = (Elf32_Shdr *)&first_section[i];
        }
    }
    if (s->debug_mode == '1')
    {
        fprintf(stderr, "DEBUG:");
        fprintf(stderr, "Symbol Table Size: %d bytes.\n", symtab_sctn->sh_size);
        fprintf(stderr, "we have %d symbols\n", sym_amount);
    }
    if (symtab_sctn == NULL || symtab_sctn->sh_size <= 0)
    {
        fprintf(stderr, "ERROR: symtab is empty\n");
        return;
    }
    Elf32_Sym *first_sym = (Elf32_Sym *)((int)(s->hdr) + symtab_sctn->sh_offset);
    printf("Symbol table:\n");
    printf("[idx] Value      Section_Index   Section_Name          Symbol_Name\n");
    char *strtble_start = (char *)(map_start + strtab_sctn->sh_offset);
    for (int i = 0; i < sym_amount; i++)
    {
        Elf32_Sym *curr_sym = &first_sym[i];
        if (curr_sym->st_shndx == SHN_ABS)
        {
            printf("[%2d]  %-11x%-16s%-24s%-20s\n",
                   i, curr_sym->st_value, "ABS", "",
                   strtble_start + curr_sym->st_name);
        }
        else if (curr_sym->st_shndx == 0)
        {
            printf("[%2d]  %-11x%-16s%-24s%-20s\n",
                   i, curr_sym->st_value, "UND", "",
                   strtble_start + curr_sym->st_name);
        }
        else
        {
            printf("[%2d]  %-11x%-16d%-24s%-20s\n",
                   i, curr_sym->st_value, curr_sym->st_shndx,
                   shstrtab_start + first_section[curr_sym->st_shndx].sh_name,
                   //curr_sym->st_shndx gives us the sectin number of the current symbol
                   //first_section in that location gives us the relevant secation
                   strtble_start + curr_sym->st_name);
        }
    }
}

void relocation_tables(state *s)
{
    printf("not implemented yet\n");
}

void quit(state *s)
{
    if (s->debug_mode == '1')
    {
        printf("quitting\n");
    }
    if (Currentfd != -1)
    {
        munmap(map_start, fdBuff.st_size);
        close(Currentfd);
        Currentfd = -1;
    }
    free(s);
    exit(0);
}

void menu()
{
    state *s = malloc(sizeof(state *));
    s->debug_mode = '0';
    s->unit_size = 1;
    struct fun_desc func_menu[] = {{"Toggle Debug Mode", toggle_debug_mode}, {"Examine ELF File", examine_elf_file}, {"Print Section Names", print_section_names}, {"Print Symbols", print_symbols}, {"Relocation Tables", relocation_tables}, {"Quit", quit}, {NULL, NULL}};
    int lower_bound = 0, option_id;
    int upper_bound = sizeof(func_menu) / sizeof(func_menu[0]) - 2;
    char c;
    while (1)
    {
        if (s->debug_mode == '1')
        {
            printf("DEBUG: unit size is: %d\n", s->unit_size);
            printf("DEBUG: file name is: %s\n", s->file_name);
            printf("DEBUG: mem count is: %d\n", s->mem_count);
        }
        printf("Choose action:\n");
        int i = 0;
        while (func_menu[i].name != NULL)
        {
            printf("%d-%s\n", i, func_menu[i].name);
            i++;
        }
        printf("action: ");

        c = fgetc(stdin);
        getchar(); // skips the \n char
        option_id = c - '0';

        if (option_id < lower_bound || option_id > upper_bound)
        {
            free(s);
            printf("Not within bounds\n");
            exit(0);
        }
        func_menu[option_id].fun(s);
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    menu();
}