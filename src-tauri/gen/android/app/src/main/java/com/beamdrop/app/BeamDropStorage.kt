package com.beamdrop.app

import android.app.DownloadManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

object BeamDropStorage {
    private const val STREAM_BUFFER_BYTES = 131_072 // 128 KiB matching core chunk size

    @JvmStatic
    fun scanCompletedFiles(context: Context, paths: Array<String>) {
        val valid = paths.filter { path ->
            path.isNotBlank() && File(path).exists()
        }.toTypedArray()

        if (valid.isEmpty()) return

        MediaScannerConnection.scanFile(
            context.applicationContext,
            valid,
            null,
            null
        )
    }

    @JvmStatic
    fun exportFilesToPublicDownloads(
        context: Context,
        sourcePaths: Array<String>,
        relativeSubdirs: Array<String>
    ): Boolean {
        if (sourcePaths.isEmpty()) return true

        val appContext = context.applicationContext
        val scannedLegacy = mutableListOf<String>()
        var allSucceeded = true

        for (i in sourcePaths.indices) {
            val srcFile = File(sourcePaths[i])
            if (!srcFile.isFile) {
                allSucceeded = false
                continue
            }
            val subdir = relativeSubdirs.getOrElse(i) { "" }.trim('/')

            val ok = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                exportViaMediaStoreQ(appContext, srcFile, subdir)
            } else {
                val dest = exportLegacyDownloads(srcFile, subdir)
                if (dest != null) {
                    scannedLegacy.add(dest.absolutePath)
                    true
                } else {
                    false
                }
            }

            if (!ok) {
                allSucceeded = false
            }
        }

        if (scannedLegacy.isNotEmpty()) {
            MediaScannerConnection.scanFile(
                appContext,
                scannedLegacy.toTypedArray(),
                null,
                null
            )
        }

        return allSucceeded
    }

    @JvmStatic
    fun openDownloadsFolder(context: Context): Boolean {
        val appContext = context.applicationContext
        val viewDownloads = Intent(DownloadManager.ACTION_VIEW_DOWNLOADS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            appContext.startActivity(viewDownloads)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun exportViaMediaStoreQ(context: Context, srcFile: File, subdir: String): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false

        val resolver = context.contentResolver
        val relPath = if (subdir.isEmpty()) {
            "${Environment.DIRECTORY_DOWNLOADS}/BeamDrop"
        } else {
            "${Environment.DIRECTORY_DOWNLOADS}/BeamDrop/$subdir"
        }

        val mimeType = detectMimeType(srcFile.name)
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, srcFile.name)
            put(MediaStore.Downloads.MIME_TYPE, mimeType)
            put(MediaStore.Downloads.RELATIVE_PATH, relPath)
            put(MediaStore.Downloads.IS_PENDING, 1)
        }

        val itemUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: return false

        return try {
            val outStream = resolver.openOutputStream(itemUri)
                ?: throw IllegalStateException("ContentResolver returned null OutputStream")

            outStream.use { out ->
                FileInputStream(srcFile).use { input ->
                    val buffer = ByteArray(STREAM_BUFFER_BYTES)
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        out.write(buffer, 0, read)
                    }
                    out.flush()
                }
            }

            val finishValues = ContentValues().apply {
                put(MediaStore.Downloads.IS_PENDING, 0)
            }
            resolver.update(itemUri, finishValues, null, null)
            true
        } catch (_: Exception) {
            try {
                resolver.delete(itemUri, null, null)
            } catch (_: Exception) {
            }
            false
        }
    }

    private fun exportLegacyDownloads(srcFile: File, subdir: String): File? {
        @Suppress("DEPRECATION")
        val baseDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val targetDir = if (subdir.isEmpty()) {
            File(baseDir, "BeamDrop")
        } else {
            File(File(baseDir, "BeamDrop"), subdir)
        }
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            return null
        }

        val destFile = resolveUniqueDestFile(targetDir, srcFile.name)
        return try {
            FileOutputStream(destFile).use { out ->
                FileInputStream(srcFile).use { input ->
                    val buffer = ByteArray(STREAM_BUFFER_BYTES)
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        out.write(buffer, 0, read)
                    }
                    out.flush()
                }
            }
            destFile
        } catch (_: Exception) {
            destFile.delete()
            null
        }
    }

    private fun resolveUniqueDestFile(dir: File, fileName: String): File {
        val candidate = File(dir, fileName)
        if (!candidate.exists()) return candidate

        val dot = fileName.lastIndexOf('.')
        val stem = if (dot > 0) fileName.substring(0, dot) else fileName
        val ext = if (dot > 0) fileName.substring(dot) else ""

        for (idx in 1..9999) {
            val next = File(dir, "$stem ($idx)$ext")
            if (!next.exists()) return next
        }
        return File(dir, "${System.currentTimeMillis()}_$fileName")
    }

    private fun detectMimeType(fileName: String): String {
        val dot = fileName.lastIndexOf('.')
        if (dot >= 0 && dot + 1 < fileName.length) {
            val ext = fileName.substring(dot + 1).lowercase()
            val detected = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
            if (!detected.isNullOrBlank()) return detected
        }
        return "application/octet-stream"
    }
}

