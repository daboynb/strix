package org.csploit.strix.core

import android.util.Log

object Logger {
    private const val TAG = "STRIX"

    fun debug(message: String) {
        val caller = callerInfo()
        Log.d("$TAG[$caller]", message)
    }

    fun info(message: String) {
        val caller = callerInfo()
        Log.i("$TAG[$caller]", message)
    }

    fun warning(message: String) {
        val caller = callerInfo()
        Log.w("$TAG[$caller]", message)
    }

    fun error(message: String) {
        val caller = callerInfo()
        Log.e("$TAG[$caller]", message)
    }

    fun error(message: String, throwable: Throwable) {
        val caller = callerInfo()
        Log.e("$TAG[$caller]", message, throwable)
    }

    private fun callerInfo(): String {
        val stack = Thread.currentThread().stackTrace
        for (element in stack) {
            val cls = element.className
            if (cls.startsWith("org.csploit.strix.") && cls != Logger::class.java.name) {
                val shortClass = cls.removePrefix("org.csploit.strix.")
                return "$shortClass.${element.methodName}"
            }
        }
        return "unknown"
    }
}
