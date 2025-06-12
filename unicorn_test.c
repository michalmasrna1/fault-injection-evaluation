#include <unicorn/unicorn.h>

// #define UC_CPU UC_CPU_ARM_CORTEX_M3
#define UC_CPU UC_CPU_ARM_CORTEX_M4
// #define UC_CPU UC_CPU_ARM_CORTEX_M7
// #define UC_CPU UC_CPU_ARM_CORTEX_M33
// #define UC_CPU UC_CPU_ARM_CORTEX_R5
// #define UC_CPU UC_CPU_ARM_CORTEX_R5F

void main() {
    uc_engine *uc;
    uc_engine *uc2;
    uc_context *ctx;

    uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    uc_ctl_set_cpu_model(uc, UC_CPU);

    uc_context_alloc(uc, &ctx);
    uc_context_save(uc, ctx);

    uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc2);
    uc_ctl_set_cpu_model(uc2, UC_CPU);

    uc_context_restore(uc2, ctx);
    uc_context_free(ctx);
    uc_close(uc); // Frees some memory which will also be freed by uc_close(uc2)
    uc_close(uc2); // free(): double free detected in tcache 2
}