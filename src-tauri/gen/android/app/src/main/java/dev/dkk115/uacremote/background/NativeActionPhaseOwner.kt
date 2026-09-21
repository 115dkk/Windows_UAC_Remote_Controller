// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/** Native callback generation, never accepted as a signing or denial permit. */
internal class NativeActionGeneration {
    override fun toString(): String = "NativeActionGeneration([redacted])"
}

/**
 * Presentation ownership only. The registry admits a generation AFTER the
 * existing native action coordinator actually admits its job. Diagnostic
 * observations, sample availability and renderer values are not inputs.
 */
internal class NativeActionPhaseOwner {
    private var current: NativeActionGeneration? = null
    private var retired = false

    @Synchronized fun admitted(generation: NativeActionGeneration): Boolean {
        if (retired) return false
        current = generation
        return true
    }

    @Synchronized fun owns(generation: NativeActionGeneration): Boolean = !retired && current === generation

    @Synchronized fun completed(generation: NativeActionGeneration) {
        if (current === generation) current = null
    }

    @Synchronized fun retire() { retired = true; current = null }

    /** Only a retained delivery transfers; callbacks still require the new locator. */
    @Synchronized fun replaceForDelivery(generation: NativeActionGeneration?): NativeActionPhaseOwner {
        val replacement = NativeActionPhaseOwner()
        if (!retired && generation != null && current === generation) replacement.admitted(generation)
        retire()
        return replacement
    }
}
