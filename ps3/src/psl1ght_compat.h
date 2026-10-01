#ifndef __PSL1GHT_COMPAT_H__
#define __PSL1GHT_COMPAT_H__

/*
 * Compatibility shim across PSL1GHT versions.
 *
 * The toolchain shipped in the ps3dev Docker images predates the
 * October 2020 header rework: render-target constants are named
 * GCM_TF_* and rsxInit() returns the context directly. Newer
 * PSL1GHT renamed the constants to GCM_SURFACE_* / GCM_TEXTURE_* and
 * takes the context as an out parameter. This header papers over both
 * so the installer builds on either SDK.
 */

#include <ppu-types.h>
#include <rsx/gcm_sys.h>
#include <rsx/rsx.h>

#if !defined(GCM_SURFACE_X8R8G8B8) && defined(GCM_TF_COLOR_X8R8G8B8)
#define GCM_SURFACE_X8R8G8B8 GCM_TF_COLOR_X8R8G8B8
#endif

#if !defined(GCM_SURFACE_TARGET_0) && defined(GCM_TF_TARGET_0)
#define GCM_SURFACE_TARGET_0 GCM_TF_TARGET_0
#endif

#if !defined(GCM_SURFACE_ZETA_Z16) && defined(GCM_TF_ZETA_Z16)
#define GCM_SURFACE_ZETA_Z16 GCM_TF_ZETA_Z16
#endif

#if !defined(GCM_SURFACE_CENTER_1) && defined(GCM_TF_CENTER_1)
#define GCM_SURFACE_CENTER_1 GCM_TF_CENTER_1
#endif

#if !defined(GCM_TEXTURE_LINEAR) && defined(GCM_TF_TYPE_LINEAR)
#define GCM_TEXTURE_LINEAR GCM_TF_TYPE_LINEAR
#endif

/*
 * GCM_TF_* constants only exist in the pre-October-2020 SDK, where
 * rsxInit() also returns the context instead of filling an out
 * parameter. Use that as the version discriminator.
 */
static inline gcmContextData *psl1ght_rsx_init(gcmContextData **context,
                                               u32 cmdSize, u32 ioSize,
                                               void *ioAddress)
{
#if defined(GCM_TF_COLOR_X8R8G8B8)
    /* Older PSL1GHT (ps3dev images): rsxInit() returns the context. */
    *context = rsxInit(cmdSize, ioSize, ioAddress);
    return *context;
#else
    /* Newer PSL1GHT: context is an out parameter. */
    return rsxInit(context, cmdSize, ioSize, ioAddress);
#endif
}

#endif /* __PSL1GHT_COMPAT_H__ */
