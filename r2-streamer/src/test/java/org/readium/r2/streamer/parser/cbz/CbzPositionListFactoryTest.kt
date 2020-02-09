/*
 * Module: r2-shared-kotlin
 * Developers: Mickaël Menu
 *
 * Copyright (c) 2020. Readium Foundation. All rights reserved.
 * Use of this source code is governed by a BSD-style license which is detailed in the
 * LICENSE file present in the project repository where this source code is maintained.
 */

package org.readium.r2.streamer.parser.cbz

import org.junit.Assert.*
import org.junit.Test
import org.readium.r2.shared.publication.Link
import org.readium.r2.shared.publication.Locator

class CbzPositionListFactoryTest {

    @Test
    fun `Create from an empty {readingOrder}`() {
        val factory = CbzPositionListFactory(readingOrder = emptyList())

        assertEquals(0, factory.create().size)
    }

    @Test
    fun `Create from a {readingOrder} with one resource`() {
        val factory = CbzPositionListFactory(readingOrder = listOf(
            Link(href = "res")
        ))

        assertEquals(
            listOf(Locator(
                href = "res",
                type = "",
                locations = Locator.Locations(
                    position = 1,
                    totalProgression = 0.0
                )
            )),
            factory.create()
        )
    }

    @Test
    fun `Create from a {readingOrder} with a few resources`() {
        val factory = CbzPositionListFactory(readingOrder = listOf(
            Link(href = "res"),
            Link(href = "chap1", type = "text/html"),
            Link(href = "chap2", type = "text/html", title = "Chapter 2")
        ))

        assertEquals(
            listOf(
                Locator(
                    href = "res",
                    type = "",
                    locations = Locator.Locations(
                        position = 1,
                        totalProgression = 0.0
                    )
                ),
                Locator(
                    href = "chap1",
                    type = "text/html",
                    locations = Locator.Locations(
                        position = 2,
                        totalProgression = 1.0/3.0
                    )
                ),
                Locator(
                    href = "chap2",
                    type = "text/html",
                    title = "Chapter 2",
                    locations = Locator.Locations(
                        position = 3,
                        totalProgression = 2.0/3.0
                    )
                )
            ),
            factory.create()
        )
    }

}