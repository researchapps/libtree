There are two implementations, one in C++ and one in C, and they are different.
I also don't know these languages well and can't derive what is going on.

see [https://github.com/haampie/libtree/blob/e19d555e5205854046b68102e78d6f00facdbf0e/src/deps.cpp](https://github.com/haampie/libtree/blob/e19d555e5205854046b68102e78d6f00facdbf0e/src/deps.cpp) and then the main repository for the c version.

```
void deps::explore(Elf const &parent, std::vector<fs::path> &rpaths, std::vector<bool> &done) {
    auto indent = get_indent(done);
    auto cached = m_visited.count(parent.name) > 0;
    auto excluded = m_skip.count(parent.name) > 0;

    std::cout << indent << (excluded ? termcolor::magenta : cached ? termcolor::blue : termcolor::cyan);
    if (!excluded && !cached)
        std::cout << termcolor::bold;

    std::cout << (m_print_paths && fs::exists(parent.abs_path) ? fs::canonical(parent.abs_path).string() : parent.name)
              << (excluded ? " (skipped)" : cached ? " (collapsed)" : "")
              << termcolor::reset;

    std::cout << (excluded ? termcolor::magenta : cached ? termcolor::blue : termcolor::yellow);
    switch(parent.found_via) {
        case found_t::NONE:            break;
        case found_t::DIRECT:          std::cout << " [direct]"; break;
        case found_t::RPATH:           std::cout << " [rpath]"; break;
        case found_t::LD_LIBRARY_PATH: std::cout << " [LD_LIBRARY_PATH]"; break;
        case found_t::RUNPATH:         std::cout << " [runpath]"; break;
        case found_t::LD_SO_CONF:      std::cout << " [ld.so.conf]"; break;
        case found_t::DEFAULT_PATHS:   std::cout << " [default paths]"; break;
    }

    std::cout << termcolor::reset << '\n';

    // Early return if already visited?
    if (m_verbosity != verbosity_t::VERY_VERBOSE && (cached || excluded))
        return;

    // Cache
    m_visited.insert(parent.name);
    m_all_binaries.push_back(parent);

    // Append the rpaths of the current ELF file.
    auto total_rpaths = rpaths;
    std::copy(parent.rpaths.begin(), parent.rpaths.end(), std::back_inserter(total_rpaths));

    // Vec of found and not found
    std::vector<std::variant<Elf, fs::path>> children;

    // First detect all needed libs
    for (auto const &lib : parent.needed) {
        auto result = locate(parent, lib, total_rpaths);

        if (m_verbosity == verbosity_t::NONE && result && m_skip.count(result->name) > 0)
            continue;

        if (result)
            children.push_back(*result);
        else
            children.push_back(lib);
    }

    // Recurse deeper
    done.push_back(false);

    for (size_t idx = 0; idx < children.size(); ++idx) {

        // Set to true if this is the last child we're visiting.
        if (idx + 1 == children.size())
            done[done.size() - 1] = true;

        std::visit(overloaded {
            [&](Elf const &lib) { explore(lib, total_rpaths, done); },
            [&](fs::path const &lib) { print_error(lib, total_rpaths, parent.runpaths, done); }
        }, children[idx]);
    }

    done.pop_back();
}
```

This should be comparable to:


```
static int recurse(char *current_file, size_t depth, struct libtree_state_t *s,
                   elf_bits_t parent_bits, struct found_t reason) {
    FILE *fptr = fopen(current_file, "rb");
    if (fptr == NULL)
        return 1;

    // When we're done recursing, we should give back the memory we've claimed.
    size_t old_buf_size = s->string_table.n;

    // Parse the header
    char e_ident[16];
    if (fread(&e_ident, 16, 1, fptr) != 1) {
        fclose(fptr);
        return ERR_INVALID_MAGIC;
    }

    // Find magic elfs
    if (e_ident[0] != 0x7f || e_ident[1] != 'E' || e_ident[2] != 'L' ||
        e_ident[3] != 'F') {
        fclose(fptr);
        return ERR_INVALID_MAGIC;
    }

    // Do at least *some* header validation
    if (e_ident[4] != '\x01' && e_ident[4] != '\x02') {
        fclose(fptr);
        return ERR_INVALID_CLASS;
    }

    if (e_ident[5] != '\x01' && e_ident[5] != '\x02') {
        fclose(fptr);
        return ERR_INVALID_DATA;
    }

    elf_bits_t curr_bits = e_ident[4] == '\x02' ? BITS64 : BITS32;
    int is_little_endian = e_ident[5] == '\x01';

    // Make sure that we have matching bits with dependent
    if (parent_bits != EITHER && parent_bits != curr_bits) {
        fclose(fptr);
        return ERR_INVALID_BITS;
    }

    // Make sure that the elf file has a the host's endianness
    // Byte swapping is on the TODO list
    if (is_little_endian ^ host_is_little_endian()) {
        fclose(fptr);
        return ERR_UNSUPPORTED_ELF_FILE;
    }

    // And get the type
    union {
        struct header_64_t h64;
        struct header_32_t h32;
    } header;

    // Read the (rest of the) elf header
    if (curr_bits == BITS64) {
        if (fread(&header.h64, sizeof(struct header_64_t), 1, fptr) != 1) {
            fclose(fptr);
            return ERR_INVALID_HEADER;
        }
        if (header.h64.e_type != ET_EXEC && header.h64.e_type != ET_DYN) {
            fclose(fptr);
            return ERR_NO_EXEC_OR_DYN;
        }
        if (fseek(fptr, header.h64.e_phoff, SEEK_SET) != 0) {
            fclose(fptr);
            return ERR_INVALID_PHOFF;
        }
    } else {
        if (fread(&header.h32, sizeof(struct header_32_t), 1, fptr) != 1) {
            fclose(fptr);
            return ERR_INVALID_HEADER;
        }
        if (header.h32.e_type != ET_EXEC && header.h32.e_type != ET_DYN) {
            fclose(fptr);
            return ERR_NO_EXEC_OR_DYN;
        }
        if (fseek(fptr, header.h32.e_phoff, SEEK_SET) != 0) {
            fclose(fptr);
            return ERR_INVALID_PHOFF;
        }
    }

    // Make sure it's an executable or library
    union {
        struct prog_64_t p64;
        struct prog_32_t p32;
    } prog;

    // map vaddr to file offset (we don't mmap the file, but directly seek in
    // the file which means that we have to translate vaddr to file offset)
    struct small_vec_u64_t pt_load_offset;
    struct small_vec_u64_t pt_load_vaddr;

    small_vec_u64_init(&pt_load_offset);
    small_vec_u64_init(&pt_load_vaddr);

    // Read the program header.
    uint64_t p_offset = MAX_OFFSET_T;
    if (curr_bits == BITS64) {
        for (uint64_t i = 0; i < header.h64.e_phnum; ++i) {
            if (fread(&prog.p64, sizeof(struct prog_64_t), 1, fptr) != 1) {
                fclose(fptr);
                small_vec_u64_free(&pt_load_offset);
                small_vec_u64_free(&pt_load_vaddr);
                return ERR_INVALID_PROG_HEADER;
            }

            if (prog.p64.p_type == PT_LOAD) {
                small_vec_u64_append(&pt_load_offset, prog.p64.p_offset);
                small_vec_u64_append(&pt_load_vaddr, prog.p64.p_vaddr);
            } else if (prog.p64.p_type == PT_DYNAMIC) {
                p_offset = prog.p64.p_offset;
            }
        }
    } else {
        for (uint32_t i = 0; i < header.h32.e_phnum; ++i) {
            if (fread(&prog.p32, sizeof(struct prog_32_t), 1, fptr) != 1) {
                fclose(fptr);
                small_vec_u64_free(&pt_load_offset);
                small_vec_u64_free(&pt_load_vaddr);
                return ERR_INVALID_PROG_HEADER;
            }

            if (prog.p32.p_type == PT_LOAD) {
                small_vec_u64_append(&pt_load_offset, prog.p32.p_offset);
                small_vec_u64_append(&pt_load_vaddr, prog.p32.p_vaddr);
            } else if (prog.p32.p_type == PT_DYNAMIC) {
                p_offset = prog.p32.p_offset;
            }
        }
    }

    // At this point we're going to store the file as "success"
    struct stat finfo;
    if (stat(current_file, &finfo) != 0) {
        fclose(fptr);
        small_vec_u64_free(&pt_load_offset);
        small_vec_u64_free(&pt_load_vaddr);
        return ERR_CANT_STAT;
    }

    int seen_before = visited_files_contains(&s->visited, &finfo);

    if (!seen_before)
        visited_files_append(&s->visited, &finfo);

    // No dynamic section?
    if (p_offset == MAX_OFFSET_T) {
        print_line(depth, current_file, BOLD_CYAN, REGULAR_CYAN, 1, reason, s);
        fclose(fptr);
        small_vec_u64_free(&pt_load_offset);
        small_vec_u64_free(&pt_load_vaddr);
        return 0;
    }

    // I guess you always have to load at least a string
    // table, so if there are not PT_LOAD sections, then
    // it is an error.
    if (pt_load_offset.n == 0) {
        fclose(fptr);
        small_vec_u64_free(&pt_load_offset);
        small_vec_u64_free(&pt_load_vaddr);
        return ERR_NO_PT_LOAD;
    }

    // Go to the dynamic section
    if (fseek(fptr, p_offset, SEEK_SET) != 0) {
        fclose(fptr);
        small_vec_u64_free(&pt_load_offset);
        small_vec_u64_free(&pt_load_vaddr);
        return ERR_INVALID_DYNAMIC_SECTION;
    }

    // Shared libraries can disable searching in
    // "default" search paths, aka ld.so.conf and
    // /usr/lib etc. At least glibc respects this.
    int no_def_lib = 0;

    uint64_t strtab = MAX_OFFSET_T;
    uint64_t rpath = MAX_OFFSET_T;
    uint64_t runpath = MAX_OFFSET_T;
    uint64_t soname = MAX_OFFSET_T;

    // Offsets in strtab
    struct small_vec_u64_t needed;
    small_vec_u64_init(&needed);

    for (int cont = 1; cont;) {
        uint64_t d_tag;
        uint64_t d_val;

        if (curr_bits == BITS64) {
            struct dyn_64_t dyn;
            if (fread(&dyn, sizeof(struct dyn_64_t), 1, fptr) != 1) {
                fclose(fptr);
                small_vec_u64_free(&pt_load_offset);
                small_vec_u64_free(&pt_load_vaddr);
                small_vec_u64_free(&needed);
                return ERR_INVALID_DYNAMIC_ARRAY_ENTRY;
            }
            d_tag = dyn.d_tag;
            d_val = dyn.d_val;

        } else {
            struct dyn_32_t dyn;
            if (fread(&dyn, sizeof(struct dyn_32_t), 1, fptr) != 1) {
                fclose(fptr);
                small_vec_u64_free(&pt_load_offset);
                small_vec_u64_free(&pt_load_vaddr);
                small_vec_u64_free(&needed);
                return ERR_INVALID_DYNAMIC_ARRAY_ENTRY;
            }
            d_tag = dyn.d_tag;
            d_val = dyn.d_val;
        }

        // Store strtab / rpath / runpath / needed / soname info.
        switch (d_tag) {
        case DT_NULL:
            cont = 0;
            break;
        case DT_STRTAB:
            strtab = d_val;
            break;
        case DT_RPATH:
            rpath = d_val;
            break;
        case DT_RUNPATH:
            runpath = d_val;
            break;
        case DT_NEEDED:
            small_vec_u64_append(&needed, d_val);
            break;
        case DT_SONAME:
            soname = d_val;
            break;
        case DT_FLAGS_1:
            no_def_lib |= (DT_1_NODEFLIB & d_val) == DT_1_NODEFLIB;
            break;
        }
    }

    if (strtab == MAX_OFFSET_T) {
        fclose(fptr);
        small_vec_u64_free(&pt_load_offset);
        small_vec_u64_free(&pt_load_vaddr);
        small_vec_u64_free(&needed);
        return ERR_NO_STRTAB;
    }

    // Let's verify just to be sure that the offsets are
    // ordered.
    if (!is_ascending_order(pt_load_vaddr.p, pt_load_vaddr.n)) {
        fclose(fptr);
        small_vec_u64_free(&pt_load_vaddr);
        small_vec_u64_free(&pt_load_offset);
        small_vec_u64_free(&needed);
        return ERR_VADDRS_NOT_ORDERED;
    }

    // Find the file offset corresponding to the strtab virtual address
    size_t vaddr_idx = 0;
    while (vaddr_idx + 1 != pt_load_vaddr.n &&
           strtab >= pt_load_vaddr.p[vaddr_idx + 1]) {
        ++vaddr_idx;
    }

    uint64_t strtab_offset =
        pt_load_offset.p[vaddr_idx] + strtab - pt_load_vaddr.p[vaddr_idx];

    small_vec_u64_free(&pt_load_vaddr);
    small_vec_u64_free(&pt_load_offset);

    // From this point on we actually copy strings from the ELF file into our
    // own string buffer.

    // Copy the current soname
    size_t soname_buf_offset = s->string_table.n;
    if (soname != MAX_OFFSET_T) {
        if (fseek(fptr, strtab_offset + soname, SEEK_SET) != 0) {
            s->string_table.n = old_buf_size;
            fclose(fptr);
            small_vec_u64_free(&needed);
            return ERR_INVALID_SONAME;
        }
        string_table_copy_from_file(&s->string_table, fptr);
    }

    int in_exclude_list =
        soname != MAX_OFFSET_T &&
        is_in_exclude_list(s->string_table.arr + soname_buf_offset);

    // No need to recurse deeper when we aren't in very verbose mode.
    int should_recurse =
        depth < MAX_RECURSION_DEPTH &&
        ((!seen_before && !in_exclude_list) ||
         (!seen_before && in_exclude_list && s->verbosity >= 2) ||
         s->verbosity == 3);

    // Just print the library and return
    if (!should_recurse) {
        char *print_name = soname != MAX_OFFSET_T && !s->path
                               ? s->string_table.arr + soname_buf_offset
                               : current_file;
        char *bold_color = in_exclude_list ? REGULAR_MAGENTA : REGULAR_BLUE;
        char *regular_color = in_exclude_list ? REGULAR_MAGENTA : REGULAR_BLUE;
        print_line(depth, print_name, bold_color, regular_color, 0, reason, s);

        s->string_table.n = old_buf_size;
        fclose(fptr);
        small_vec_u64_free(&needed);
        return 0;
    }

    // Store the ORIGIN string.
    char origin[4096];
    char *last_slash = strrchr(current_file, '/');
    if (last_slash != NULL) {
        // Exclude the last slash
        size_t bytes = last_slash - current_file;
        memcpy(origin, current_file, bytes);
        origin[bytes] = '\0';
    } else {
        // this only happens when the input is relative (e.g. in current dir)
        memcpy(origin, "./", 3);
    }

    // Copy DT_PRATH
    if (rpath == MAX_OFFSET_T) {
        s->rpath_offsets[depth] = SIZE_MAX;
    } else {
        s->rpath_offsets[depth] = s->string_table.n;
        if (fseek(fptr, strtab_offset + rpath, SEEK_SET) != 0) {
            s->string_table.n = old_buf_size;
            fclose(fptr);
            small_vec_u64_free(&needed);
            return ERR_INVALID_RPATH;
        }

        string_table_copy_from_file(&s->string_table, fptr);

        // We store the interpolated string right after the literal copy.
        size_t curr_buf_size = s->string_table.n;
        if (interpolate_variables(s, s->rpath_offsets[depth], origin))
            s->rpath_offsets[depth] = curr_buf_size;
    }

    // Copy DT_RUNPATH
    size_t runpath_buf_offset = s->string_table.n;
    if (runpath != MAX_OFFSET_T) {
        if (fseek(fptr, strtab_offset + runpath, SEEK_SET) != 0) {
            s->string_table.n = old_buf_size;
            fclose(fptr);
            small_vec_u64_free(&needed);
            return ERR_INVALID_RUNPATH;
        }

        string_table_copy_from_file(&s->string_table, fptr);

        // We store the interpolated string right after the literal copy.
        size_t curr_buf_size = s->string_table.n;
        if (interpolate_variables(s, runpath_buf_offset, origin))
            runpath_buf_offset = curr_buf_size;
    }

    // Copy needed libraries.
    struct small_vec_u64_t needed_buf_offsets;
    small_vec_u64_init(&needed_buf_offsets);

    for (size_t i = 0; i < needed.n; ++i) {
        small_vec_u64_append(&needed_buf_offsets, s->string_table.n);
        if (fseek(fptr, strtab_offset + needed.p[i], SEEK_SET) != 0) {
            s->string_table.n = old_buf_size;
            fclose(fptr);
            small_vec_u64_free(&needed_buf_offsets);
            small_vec_u64_free(&needed);
            return ERR_INVALID_NEEDED;
        }
        string_table_copy_from_file(&s->string_table, fptr);
    }

    fclose(fptr);

    char *print_name = soname == MAX_OFFSET_T || s->path
                           ? current_file
                           : (s->string_table.arr + soname_buf_offset);

    char *bold_color = in_exclude_list ? REGULAR_MAGENTA
                                       : seen_before ? REGULAR_BLUE : BOLD_CYAN;
    char *regular_color = in_exclude_list
                              ? REGULAR_MAGENTA
                              : seen_before ? REGULAR_BLUE : REGULAR_CYAN;

    int highlight = !seen_before && !in_exclude_list;
    print_line(depth, print_name, bold_color, regular_color, highlight, reason,
               s);

    // Finally start searching.

    size_t needed_not_found = needed_buf_offsets.n;

    // Skip common libraries if not verbose
    if (needed_not_found && s->verbosity == 0) {
        for (size_t i = 0; i < needed_not_found;) {
            // If in exclude list, swap to the back.
            if (is_in_exclude_list(s->string_table.arr +
                                   needed_buf_offsets.p[i])) {
                size_t tmp = needed_buf_offsets.p[i];
                needed_buf_offsets.p[i] =
                    needed_buf_offsets.p[needed_not_found - 1];
                needed_buf_offsets.p[--needed_not_found] = tmp;
                continue;
            } else {
                ++i;
            }
        }
    }

    // First go over absolute paths in needed libs.
    for (size_t i = 0; i < needed_not_found;) {
        char *name = s->string_table.arr + needed_buf_offsets.p[i];
        if (strchr(name, '/') != NULL) {
            // If it is not an absolute path, we bail, cause it then starts to
            // depend on the current working directory, which is rather
            // nonsensical. This is allowed by glibc though.
            s->found_all_needed[depth] = needed_not_found <= 1;
            if (name[0] != '/') {
                tree_preamble(s, depth + 1);
                if (s->color)
                    fputs(BOLD_RED, stdout);
                fputs(name, stdout);
                fputs(" is not absolute", stdout);
                fputs(s->color ? CLEAR "\n" : "\n", stdout);
            } else if (recurse(name, depth + 1, s, curr_bits,
                               (struct found_t){.how = DIRECT, .depth = 0}) !=
                       0) {
                tree_preamble(s, depth + 1);
                if (s->color)
                    fputs(BOLD_RED, stdout);
                fputs(name, stdout);
                fputs(" not found", stdout);
                fputs(s->color ? CLEAR "\n" : "\n", stdout);
            }

            // Even if not officially found, we mark it as found, cause we
            // handled the error here
            size_t tmp = needed_buf_offsets.p[i];
            needed_buf_offsets.p[i] =
                needed_buf_offsets.p[needed_not_found - 1];
            needed_buf_offsets.p[--needed_not_found] = tmp;
        } else {
            ++i;
        }
    }

    // Consider rpaths only when runpath is empty
    if (runpath == MAX_OFFSET_T) {
        // We have a stack of rpaths, try them all, starting with one set at
        // this lib, then the parents.
        for (int j = depth; j >= 0 && needed_not_found; --j) {
            if (s->rpath_offsets[j] == SIZE_MAX)
                continue;

            check_search_paths((struct found_t){.how = RPATH, .depth = j},
                               s->rpath_offsets[j], &needed_not_found,
                               &needed_buf_offsets, depth, s, curr_bits);
        }
    }

    // Then try LD_LIBRARY_PATH, if we have it.
    if (needed_not_found && s->ld_library_path_offset != SIZE_MAX) {
        check_search_paths((struct found_t){.how = LD_LIBRARY_PATH, .depth = 0},
                           s->ld_library_path_offset, &needed_not_found,
                           &needed_buf_offsets, depth, s, curr_bits);
    }

    // Then consider runpaths
    if (needed_not_found && runpath != MAX_OFFSET_T) {
        check_search_paths((struct found_t){.how = RUNPATH, .depth = 0},
                           runpath_buf_offset, &needed_not_found,
                           &needed_buf_offsets, depth, s, curr_bits);
    }

    // Check ld.so.conf paths
    if (!no_def_lib && needed_not_found) {
        check_search_paths((struct found_t){.how = LD_SO_CONF, .depth = 0},
                           s->ld_so_conf_offset, &needed_not_found,
                           &needed_buf_offsets, depth, s, curr_bits);
    }

    // Then consider standard paths
    if (!no_def_lib && needed_not_found) {
        check_search_paths((struct found_t){.how = DEFAULT, .depth = 0},
                           s->default_paths_offset, &needed_not_found,
                           &needed_buf_offsets, depth, s, curr_bits);
    }

    // Finally summarize those that could not be found.
    if (needed_not_found) {
        print_error(depth, needed_not_found, &needed_buf_offsets,
                    runpath == MAX_OFFSET_T
                        ? NULL
                        : s->string_table.arr + runpath_buf_offset,
                    s, no_def_lib);
        s->string_table.n = old_buf_size;
        small_vec_u64_free(&needed_buf_offsets);
        small_vec_u64_free(&needed);
        // return ERR_NOT_FOUND;
        return 0;
    }

    // Free memory in our string table
    s->string_table.n = old_buf_size;
    small_vec_u64_free(&needed_buf_offsets);
    small_vec_u64_free(&needed);
    return 0;
}


    int libtree_last_err = 0;

    for (int i = 0; i < pathc; ++i) {
        int result = recurse(pathv[i], 0, s, EITHER,
                             (struct found_t){.how = INPUT, .depth = 0});
        if (result != 0)
            libtree_last_err = result;
    }

    libtree_state_free(s);
    return libtree_last_err;
}
```
