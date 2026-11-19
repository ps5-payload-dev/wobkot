//#region Constants
const ELF_MAPPING_ADDR = new BInt('0x926100000');
const ELF_SHADOW_ADDR = new BInt('0x920100000');

const ELF_EHDR_ENTRY = 0x18;
const ELF_EHDR_PHOFF = 0x20;
const ELF_EHDR_SHOFF = 0x28;
const ELF_EHDR_PHNUM = 0x38;
const ELF_EHDR_SHNUM = 0x3c;

const ELF_PHDR_SIZE = 0x38;
const ELF_PHDR_TYPE = 0x00;
const ELF_PHDR_FLAGS = 0x04;
const ELF_PHDR_OFFSET = 0x08;
const ELF_PHDR_VADDR = 0x10;
const ELF_PHDR_FILESZ = 0x20;
const ELF_PHDR_MEMSZ = 0x28;

const ELF_SHDR_SIZE = 0x40;
const ELF_SHDR_TYPE = 0x04;
const ELF_SHDR_OFFSET = 0x18;
const ELF_SHDR_SIZE_OFF = 0x20;

const ELF_RELA_SIZE = 0x18;
const ELF_RELA_OFFSET = 0x00;
const ELF_RELA_INFO = 0x08;
const ELF_RELA_ADDEND = 0x10;

const ELF_ET_DYN = 3;
const ELF_PT_LOAD = 1;
const ELF_SHT_RELA = 4;
const ELF_R_X86_64_RELATIVE = 8;

const ELF_PF_X = 0x1;
//#endregion
//#region Functions
async function load_elf(src) {
  const u8 = await load_file(src);
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

  if (dv.getUint32(0, true) !== 0x464c457f) {
    throw new Error(`${src} is not an ELF !!`);
  }

  const e_type = dv.getUint16(0x10, true);
  if (e_type !== ELF_ET_DYN) {
    throw new Error(`${src} is not position independent (type ${e_type}) !!`);
  }

  const e_entry = dv.getBInt(ELF_EHDR_ENTRY, true);
  const e_phoff = dv.getBInt(ELF_EHDR_PHOFF, true).u;
  const e_shoff = dv.getBInt(ELF_EHDR_SHOFF, true).u;
  const e_phnum = dv.getUint16(ELF_EHDR_PHNUM, true);
  const e_shnum = dv.getUint16(ELF_EHDR_SHNUM, true);

  const elf_addr = u8.buffer.data();
  const exec_ranges = [];

  logger.debug(`Loading ${src}...`);

  // Map and populate all loadable segments.
  for (let i = 0; i < e_phnum; i++) {
    const phdr = e_phoff + i * ELF_PHDR_SIZE;

    if (dv.getUint32(phdr + ELF_PHDR_TYPE, true) !== ELF_PT_LOAD) {
      continue;
    }

    const p_flags = dv.getUint32(phdr + ELF_PHDR_FLAGS, true);
    const p_offset = dv.getBInt(phdr + ELF_PHDR_OFFSET, true).u;
    const p_vaddr = dv.getBInt(phdr + ELF_PHDR_VADDR, true).u;
    const p_filesz = dv.getBInt(phdr + ELF_PHDR_FILESZ, true).u;
    const p_memsz = dv.getBInt(phdr + ELF_PHDR_MEMSZ, true).u;

    if (p_memsz === 0) {
      continue;
    }

    const size = p_memsz.alignUp(PAGE_SIZE);
    const mapping = ELF_MAPPING_ADDR.add(p_vaddr);

    if ((p_flags & ELF_PF_X) !== 0) {
      // Executable memory must come from a JIT shared memory object.
      const exec_fd = fn.jitshm_create.invoke(0, size, PROT_READ | PROT_WRITE | PROT_EXEC);
      if (exec_fd < 0) {
        throw new SyscallError(`Unable to create JIT shared memory of size ${size.hex()} !!`);
      }

      const write_fd = fn.jitshm_alias.invoke(exec_fd, PROT_READ | PROT_WRITE);
      if (write_fd < 0) {
        throw new SyscallError(`Unable to alias JIT shared memory fd ${exec_fd} !!`);
      }

      // Writable shadow mapping used for copying and relocations.
      const shadow = ELF_SHADOW_ADDR.add(p_vaddr);

      if (fn.mmap.invoke(shadow, size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, write_fd, 0).eq(-1)) {
        throw new SyscallError(`Unable to map shadow memory of size ${size.hex()} !!`);
      }

      if (p_filesz > 0) {
        mem.copy(shadow, elf_addr.add(p_offset), p_filesz);
      }

      if (fn.mmap.invoke(mapping, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_SHARED, exec_fd, 0).eq(-1)) {
        throw new SyscallError(`Unable to map executable memory of size ${size.hex()} !!`);
      }

      fn.close.invoke(exec_fd);
      fn.close.invoke(write_fd);

      exec_ranges.push({ start: p_vaddr, end: p_vaddr + p_memsz });
    } else {
      if (fn.mmap.invoke(mapping, size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0).eq(-1)) {
        throw new SyscallError(`Unable to map memory of size ${size.hex()} !!`);
      }

      if (p_filesz > 0) {
        mem.copy(mapping, elf_addr.add(p_offset), p_filesz);
      }
    }
  }

  // Apply R_X86_64_RELATIVE relocations.
  for (let i = 0; i < e_shnum; i++) {
    const shdr = e_shoff + i * ELF_SHDR_SIZE;

    if (dv.getUint32(shdr + ELF_SHDR_TYPE, true) !== ELF_SHT_RELA) {
      continue;
    }

    const sh_offset = dv.getBInt(shdr + ELF_SHDR_OFFSET, true).u;
    const sh_size = dv.getBInt(shdr + ELF_SHDR_SIZE_OFF, true).u;

    for (let j = 0; j < sh_size / ELF_RELA_SIZE; j++) {
      const rela = sh_offset + j * ELF_RELA_SIZE;

      const r_offset = dv.getBInt(rela + ELF_RELA_OFFSET, true);
      const r_info = dv.getBInt(rela + ELF_RELA_INFO, true);
      const r_addend = dv.getBInt(rela + ELF_RELA_ADDEND, true);

      if (r_info.lo !== ELF_R_X86_64_RELATIVE) {
        continue;
      }

      const offset = r_offset.u;
      const in_exec = exec_ranges.some((range) => offset >= range.start && offset < range.end);

      // Redirect writes into executable segments to the writable shadow.
      const target = in_exec ? ELF_SHADOW_ADDR.add(r_offset) : ELF_MAPPING_ADDR.add(r_offset);

      arw.view(target).setBInt(0, ELF_MAPPING_ADDR.add(r_addend), true);
    }
  }

  const entry = ELF_MAPPING_ADDR.add(e_entry);
  logger.debug(`ELF entry: ${entry}`);

  return { entry };
}
//#endregion
