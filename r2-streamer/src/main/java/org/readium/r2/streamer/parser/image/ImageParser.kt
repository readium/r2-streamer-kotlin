/*
 * Module: r2-streamer-kotlin
 * Developers: Quentin Gliosca
 *
 * Copyright (c) 2020. Readium Foundation. All rights reserved.
 * Use of this source code is governed by a BSD-style license which is detailed in the
 * LICENSE file present in the project repository where this source code is maintained.
 */

package org.readium.r2.streamer.parser.image

import org.readium.r2.shared.extensions.md5
import org.readium.r2.shared.fetcher.Fetcher
import org.readium.r2.shared.util.File
import org.readium.r2.shared.format.Format
import org.readium.r2.shared.publication.Link
import org.readium.r2.shared.publication.LocalizedString
import org.readium.r2.shared.publication.Manifest
import org.readium.r2.shared.publication.Metadata
import org.readium.r2.shared.publication.Publication
import org.readium.r2.shared.publication.services.PerResourcePositionsService
import org.readium.r2.shared.util.Try
import org.readium.r2.shared.util.logging.WarningLogger
import org.readium.r2.streamer.PublicationParser
import org.readium.r2.streamer.extensions.guessTitle
import org.readium.r2.streamer.extensions.isHiddenOrThumbs
import org.readium.r2.streamer.extensions.lowercasedExtension
import org.readium.r2.streamer.extensions.hrefCommonFirstComponent
import org.readium.r2.streamer.extensions.toTitle
import java.lang.Exception

/**
 * Parses an image–based Publication from an unstructured archive format containing bitmap files, such as CBZ or a simple ZIP.
 *
 * It can also work for a standalone bitmap file.
 */
class ImageParser : PublicationParser {

    override suspend fun parse(
        file: File,
        fetcher: Fetcher,
        fallbackTitle: String,
        warnings: WarningLogger?
    ): Try<PublicationParser.PublicationBuilder, Throwable>? {

        if (!accepts(file, fetcher))
            return null

        return try {
            Try.success(makeBuilder(file, fetcher, fallbackTitle))
        } catch (e: Exception) {
            Try.failure(e)
        }
    }

    private suspend fun accepts(file: File, fetcher: Fetcher): Boolean {
        if (file.format() == Format.CBZ)
            return true

        val allowedExtensions = listOf("acbf", "txt", "xml")

        if (fetcher.links()
                .filterNot { File(it.href).isHiddenOrThumbs }
                .all { it.mediaType?.isBitmap == true || File(it.href).lowercasedExtension in allowedExtensions })
            return true

        return false
    }

    private suspend fun makeBuilder(file: File, fetcher: Fetcher, fallbackTitle: String):
            PublicationParser.PublicationBuilder {

        val readingOrder = fetcher.links()
            .filter { !File(it.href).isHiddenOrThumbs && it.mediaType?.isBitmap == true }
            .sortedBy(Link::href)
            .toMutableList()

        if (readingOrder.isEmpty())
            throw Exception("No bitmap found in the publication.")

        val title = fetcher.guessTitle()
            ?: fallbackTitle

        // First valid resource is the cover.
        readingOrder[0] = readingOrder[0].copy(rels = setOf("cover"))

        val manifest = Manifest(
            metadata = Metadata(
                identifier = file.file.md5(),
                localizedTitle = LocalizedString(title)
            ),
            readingOrder = readingOrder
        )

        return PublicationParser.PublicationBuilder(
            manifest = manifest,
            fetcher = fetcher,
            servicesBuilder = Publication.ServicesBuilder(
                positions = PerResourcePositionsService.createFactory(fallbackMediaType = "image/*")
            )
        )
    }

}