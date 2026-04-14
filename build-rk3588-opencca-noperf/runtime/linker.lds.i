ENTRY(rmm_entry)
MEMORY {
 RAM (rwx): ORIGIN = 0x0, LENGTH = (0x25ff000)
}
SECTIONS
{
 rmm_base = .;
 .text . : {
  rmm_text_start = .;
  *head.S.obj(.text*)
  . = ALIGN(8);
  *(.text*)
  . = ALIGN(((1) << (12)));
 } >RAM
 rmm_text_end = .;
 ASSERT(rmm_text_end == ALIGN(((1) << (12))), "rmm_text_end is not page aligned")
 .rodata ALIGN(((1) << (12))) : {
  rmm_ro_start = .;
  *(.rodata*)
  . = ALIGN(8);
  rmm_got_start = .;
  *(.got)
  rmm_got_end = .;
 } >RAM
 xlat_table ALIGN(((1) << (12))) : {
  *(xlat_static_tables)
 } >RAM
 rmm_ro_end = .;
 ASSERT(rmm_ro_end == ALIGN(((1) << (12))), "rmm_ro_end is not page aligned")
 .data ALIGN(((2) * ((1) << 20))) : {
  rmm_rw_start = .;
  *(.data*)
 } >RAM
 .rela.dyn ALIGN(8) : {
  rmm_rela_start = .;
  *(.rela*)
  rmm_rela_end = .;
 } >RAM
 .bss ALIGN(16) (NOLOAD) : {
  bss_start = .;
  *(.bss*)
  bss_end = .;
 } >RAM
 . = ALIGN(((1) << (12)));
 rmm_rw_end = .;
 ASSERT(rmm_rw_end == ALIGN(((1) << (12))), "rmm_rw_end is not page aligned")
 .stack ALIGN(((1) << (12))) (NOLOAD) : {
  rmm_stack_start = .;
  . = . + ((5) * ((1) << (12)) * (16));
  rmm_stack_end = .;
  rmm_eh_stack_start = .;
  . = . + (((1) << (12)) * (16));
  rmm_eh_stack_end = .;
 } >RAM
 rmm_end = .;
 ASSERT(rmm_end == ALIGN(((1) << (12))), "rmm_end is not page aligned")
 /DISCARD/ : { *(.dynstr*) }
 /DISCARD/ : { *(.dynsym*) }
 /DISCARD/ : { *(.dynamic*) }
 /DISCARD/ : { *(.hash*) }
 /DISCARD/ : { *(.plt*) }
 /DISCARD/ : { *(.interp*) }
 /DISCARD/ : { *(.gnu*) }
 /DISCARD/ : { *(.note*) }
}
