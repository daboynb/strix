/*
 * Copyright 2012 Rui Araujo, Luis Fonseca
 *
 * This file is part of Router Keygen.
 *
 * Router Keygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Router Keygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Router Keygen.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.csploit.strix.data.wifi.algorithms.helpers

/**
 * Java/Kotlin implementation of Bob Jenkins' lookup3 hashword.
 *
 * This is NOT a singleton object because the original Java code uses
 * mutable instance fields (a, b, c) that are modified during hashing,
 * so each caller needs its own instance to avoid concurrency issues.
 */
class JenkinsHash {

    companion object {
        private const val MAX_VALUE = 0xFFFFFFFFL
    }

    private var a: Long = 0
    private var b: Long = 0
    private var c: Long = 0

    private fun add(v: Long, addend: Long): Long = (v + addend) and MAX_VALUE

    private fun subtract(v: Long, subtrahend: Long): Long = (v - subtrahend) and MAX_VALUE

    private fun xor(v: Long, x: Long): Long = (v xor x) and MAX_VALUE

    private fun leftShift(v: Long, shift: Int): Long = (v shl shift) and MAX_VALUE

    private fun rot(v: Long, shift: Int): Long =
        (leftShift(v, shift) or (v ushr (32 - shift))) and MAX_VALUE

    private fun hashMix() {
        a = subtract(a, c); a = xor(a, rot(c, 4));  c = add(c, b)
        b = subtract(b, a); b = xor(b, rot(a, 6));  a = add(a, c)
        c = subtract(c, b); c = xor(c, rot(b, 8));  b = add(b, a)
        a = subtract(a, c); a = xor(a, rot(c, 16)); c = add(c, b)
        b = subtract(b, a); b = xor(b, rot(a, 19)); a = add(a, c)
        c = subtract(c, b); c = xor(c, rot(b, 4));  b = add(b, a)
    }

    private fun finalHash() {
        c = xor(c, b);  c = subtract(c, rot(b, 14))
        a = xor(a, c);  a = subtract(a, rot(c, 11))
        b = xor(b, a);  b = subtract(b, rot(a, 25))
        c = xor(c, b);  c = subtract(c, rot(b, 16))
        a = xor(a, c);  a = subtract(a, rot(c, 4))
        b = xor(b, a);  b = subtract(b, rot(a, 14))
        c = xor(c, b);  c = subtract(c, rot(b, 24))
    }

    @Suppress("NAME_SHADOWING")
    fun hashword(k: LongArray, length: Int, initval: Long): Long {
        var length = length
        a = 0xdeadbeefL + (length.toLong() shl 2) + (initval and MAX_VALUE)
        b = a
        c = a

        var i = 0
        while (length > 3) {
            a = add(a, k[i + 0])
            b = add(b, k[i + 1])
            c = add(c, k[i + 2])
            hashMix()
            length -= 3
            i += 3
        }

        // Fallthrough switch emulation
        when (length) {
            3 -> {
                c = add(c, k[i + 2])
                b = add(b, k[i + 1])
                a = add(a, k[i + 0])
                finalHash()
            }
            2 -> {
                b = add(b, k[i + 1])
                a = add(a, k[i + 0])
                finalHash()
            }
            1 -> {
                a = add(a, k[i + 0])
                finalHash()
            }
            // 0 -> break (no-op)
        }
        return c
    }
}
