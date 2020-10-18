#ifndef ELFUTIL_H
#define ELFUTIL_H

#include <cstdio>

#include <iostream>
#include <string_view>
#include <utility>
#include <vector>
#include <variant>

#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

enum class Analyzetype{
    DEF = 0x0001,
    UNDEF = 0x0002,
};

enum class Machinebit{
    B32,
    B64,
};

template<Machinebit bit>
struct util_elf_typedef;

template<>
struct util_elf_typedef<Machinebit::B32>{
    using Elf_Ehdr = Elf32_Ehdr;
    using Elf_Shdr = Elf32_Shdr;
    using Elf_Sym = Elf32_Sym;
};

template<>
struct util_elf_typedef<Machinebit::B64>{
    using Elf_Ehdr = Elf64_Ehdr;
    using Elf_Shdr = Elf64_Shdr;
    using Elf_Sym = Elf64_Sym;
};

template<Analyzetype type, Machinebit bit>
class Elfanalyzer{
    using util_elf_t = util_elf_typedef<bit>;

    public:
    constexpr Elfanalyzer(){}

    std::variant<int, std::vector<std::pair<char, std::string_view>>>
        AnalyzeStart(const char * filename){
            auto fd = open(filename, O_RDONLY);
            if(fd == -1){
                return -1;
            }
            
            auto ptr = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_SHARED, fd, 0);
            if(ptr == nullptr){
                return -2;
            }
            
            auto ehdr = static_cast<typename util_elf_t::Elf_Ehdr *>(ptr);

            //if (((char*)elf->ehdr + elf->ehdr->e_shoff) > _64_addrEnd_Ehdr(elf))
                //return (-1);
            auto shdr = reinterpret_cast<typename util_elf_t::Elf_Shdr*>((char*)ehdr + ehdr->e_shoff);
            std::cout << ehdr->e_shnum << std::endl;
            for(int i=0;i < ehdr->e_shnum; ++i){
                if (shdr[i].sh_type != SHT_SYMTAB){
                    continue;
                }
                auto sym = reinterpret_cast<typename util_elf_t::Elf_Sym*>((char*)ehdr + shdr[i].sh_offset);
                char * sym_tab = (char*)ehdr + shdr[shdr[i].sh_link].sh_offset;

                if(shdr[i].sh_entsize == 0){continue;}
                std::size_t size = shdr[i].sh_size / shdr[i].sh_entsize;

                printf("%p,%p,%p\n",(void *)ehdr, (void *)shdr, (void *)sym_tab);

                for(int j=0; j < size; ++j){
                    if (ELF64_ST_BIND(sym[j].st_info) != STB_GNU_UNIQUE &&
                        ELF64_ST_BIND(sym[j].st_info) != STB_WEAK && 
                        ELF64_ST_TYPE(sym[j].st_info) != STT_OBJECT &&
                        ELF64_ST_BIND(sym[j].st_info) != STB_LOCAL &&
                        sym[j].st_shndx == SHN_UNDEF && sym[j].st_name != 0)
                        {
                            std::cout << &sym_tab[sym[j].st_name] << std::endl;
                            //std::cout << std::printf("%p\n",&sym_tab[sym[j].st_name]) << std::endl;
                        }
                }
            }
            close(fd);
            return 0;
        }
};


#endif