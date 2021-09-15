/*
 * Copyright 2021 Readium Foundation. All rights reserved.
 * Use of this source code is governed by the BSD-style license
 * available in the top-level LICENSE file of the project.
 */

package org.readium.r2.streamer.parser

import org.readium.r2.shared.UserException
import org.readium.r2.shared.fetcher.Fetcher
import org.readium.r2.shared.publication.ContentProtection
import org.readium.r2.shared.publication.ContentProtection.Scheme
import org.readium.r2.shared.publication.Publication
import org.readium.r2.shared.publication.asset.PublicationAsset
import org.readium.r2.shared.publication.services.ContentProtectionService
import org.readium.r2.shared.publication.services.contentProtectionServiceFactory
import org.readium.r2.shared.util.Try
import org.readium.r2.shared.util.mediatype.MediaType
import org.readium.r2.streamer.extensions.readAsJsonOrNull
import org.readium.r2.streamer.extensions.readAsXmlOrNull
import org.readium.r2.streamer.parser.epub.EncryptionParser

/**
 * [ContentProtection] implementation used as a fallback by the Streamer to detect known DRM
 * schemes (e.g. LCP or ADEPT), if they are not supported by the app.
 */
internal class FallbackContentProtection : ContentProtection {

    class Service(override val scheme: Scheme?) : ContentProtectionService {

        override val isRestricted: Boolean = true
        override val credentials: String? = null
        override val rights = ContentProtectionService.UserRights.AllRestricted
        override val error: UserException = ContentProtection.Exception.SchemeNotSupported(scheme)

        companion object {

            fun createFactory(scheme: Scheme?): (Publication.Service.Context) -> Service =
                { Service(scheme) }
        }

    }

    override suspend fun open(
        asset: PublicationAsset,
        fetcher: Fetcher,
        credentials: String?,
        allowUserInteraction: Boolean,
        sender: Any?
    ): Try<ContentProtection.ProtectedAsset, Publication.OpeningException>? {
        val scheme: Scheme = sniffScheme(fetcher, asset.mediaType())
            ?: return null

        val protectedFile = ContentProtection.ProtectedAsset(
            asset = asset,
            fetcher = fetcher,
            onCreatePublication = {
                servicesBuilder.contentProtectionServiceFactory = Service.createFactory(scheme)
            }
        )

        return Try.success(protectedFile)
    }

    internal suspend fun sniffScheme(fetcher: Fetcher, mediaType: MediaType): Scheme? =
        when {
            fetcher.readAsJsonOrNull("/license.lcpl") != null ->
                Scheme.Lcp

            mediaType.matches(MediaType.EPUB) -> {
                val encryption = fetcher.readAsXmlOrNull("/META-INF/encryption.xml")
                    ?.let { EncryptionParser.parse(it) }
                val rights = fetcher.readAsXmlOrNull("/META-INF/rights.xml")

                when {
                    (
                        fetcher.readAsJsonOrNull("/META-INF/license.lcpl") != null ||
                        encryption?.any { it.value.scheme == "http://readium.org/2014/01/lcp" } == true
                    ) -> Scheme.Lcp

                    (
                        encryption != null &&
                        rights?.namespace == "http://ns.adobe.com/adept"
                    ) -> Scheme.Adept

                    // A file with only obfuscated fonts might still have an `encryption.xml` file.
                    // To make sure that we don't lock a readable publication, we ignore unknown
                    // encryption.xml schemes.
                    else -> null
                }
            }

            else -> null
        }
}
