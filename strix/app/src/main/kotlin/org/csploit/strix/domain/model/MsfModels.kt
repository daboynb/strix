package org.csploit.strix.domain.model

data class MsfModuleInfo(
    val fullName: String,
    val type: String,
    val name: String,
    val description: String,
    val rank: ExploitRank,
    val references: List<List<String>> = emptyList(),
    val authors: List<String> = emptyList(),
    val targets: Map<Int, String> = emptyMap(),
    val defaultTarget: Int = 0,
)

enum class ExploitRank(val value: Int, val label: String) {
    Manual(0, "Manual"),
    Low(100, "Low"),
    Average(200, "Average"),
    Normal(300, "Normal"),
    Good(400, "Good"),
    Great(500, "Great"),
    Excellent(600, "Excellent");

    companion object {
        fun fromValue(v: Int): ExploitRank =
            entries.firstOrNull { it.value == v } ?: Manual

        fun fromString(s: String): ExploitRank =
            entries.firstOrNull { it.label.equals(s, ignoreCase = true) } ?: Manual
    }
}

data class MsfOption(
    val name: String,
    val type: String,
    val required: Boolean,
    val description: String,
    val default: String? = null,
    val enums: List<String>? = null,
    val advanced: Boolean = false,
    val evasion: Boolean = false,
)

data class MsfSession(
    val id: Int,
    val type: String,
    val info: String = "",
    val targetHost: String = "",
    val targetPort: Int = 0,
    val viaExploit: String = "",
    val viaPayload: String = "",
    val username: String = "",
    val uuid: String = "",
)
