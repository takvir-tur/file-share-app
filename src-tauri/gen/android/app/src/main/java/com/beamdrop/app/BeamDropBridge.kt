package com.beamdrop.app

import java.util.concurrent.ConcurrentLinkedQueue

object BeamDropBridge {
    @Volatile
    private var nativeLoaded = false
    private val bufferedPaths = ConcurrentLinkedQueue<String>()

    fun markNativeReady() {
        nativeLoaded = true
        flushBufferedPaths()
    }

    fun enqueuePaths(paths: List<String>) {
        val clean = paths.filter { it.isNotBlank() }
        if (clean.isEmpty()) return

        if (nativeLoaded) {
            flushAndQueue(clean)
        } else {
            bufferedPaths.addAll(clean)
            if (nativeLoaded) {
                flushBufferedPaths()
            }
        }
    }

    private fun flushBufferedPaths() {
        val drained = mutableListOf<String>()
        while (true) {
            val item = bufferedPaths.poll() ?: break
            drained.add(item)
        }
        if (drained.isEmpty()) return

        try {
            nativeQueueSharedPaths(drained.toTypedArray())
        } catch (_: UnsatisfiedLinkError) {
            bufferedPaths.addAll(drained)
        }
    }

    private fun flushAndQueue(paths: List<String>) {
        val combined = mutableListOf<String>()
        while (true) {
            val item = bufferedPaths.poll() ?: break
            combined.add(item)
        }
        combined.addAll(paths)
        try {
            nativeQueueSharedPaths(combined.toTypedArray())
        } catch (_: UnsatisfiedLinkError) {
            bufferedPaths.addAll(combined)
        }
    }

    @JvmStatic
    external fun nativeQueueSharedPaths(paths: Array<String>)
}

