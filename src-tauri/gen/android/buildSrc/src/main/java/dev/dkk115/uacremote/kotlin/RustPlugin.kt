import com.android.build.api.dsl.ApplicationExtension
import org.gradle.api.DefaultTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.get

const val TASK_GROUP = "rust"

enum class ControllerAbi(val abi: String, val arch: String, val target: String, val rustTarget: String) {
    ARM64("arm64-v8a", "arm64", "aarch64", "aarch64-linux-android"),
    X86_64("x86_64", "x86_64", "x86_64", "x86_64-linux-android"),
}

// One closed tuple feeds both Tauri flavors/tasks and the separate controller.
fun selectControllerAbi(controllerAbi: String?, abiList: String?, archList: String?, targetList: String?): ControllerAbi {
    val selected = ControllerAbi.entries.singleOrNull { it.abi == (controllerAbi ?: abiList ?: "arm64-v8a") }
        ?: error("Select exactly one supported controller ABI: arm64-v8a or x86_64.")
    require((abiList == null || abiList == selected.abi) &&
        (archList == null || archList == selected.arch) &&
        (targetList == null || targetList == selected.target)) {
        "controllerAbi and Tauri abiList/archList/targetList must describe the same single Android ABI."
    }
    return selected
}

open class Config(val controllerAbi: ControllerAbi) {
    lateinit var rootDirRel: String
}

open class RustPlugin : Plugin<Project> {
    private lateinit var config: Config

    override fun apply(project: Project) = with(project) {
        fun abiProperty(name: String): String? {
            val value = findProperty(name) ?: return null
            require(value is String && value.length <= 64) { "Android ABI properties must be bounded strings." }
            return value
        }
        val selected = selectControllerAbi(abiProperty("controllerAbi"), abiProperty("abiList"), abiProperty("archList"), abiProperty("targetList"))
        config = extensions.create("rust", Config::class.java, selected)
        val abiList = listOf(selected.abi)
        val archList = listOf(selected.arch)
        val targetsList = listOf(selected.target)

        extensions.configure<ApplicationExtension> {
            @Suppress("UnstableApiUsage")
            flavorDimensions.add("abi")
            productFlavors {
                create("universal") {
                    dimension = "abi"
                    ndk {
                        abiFilters += abiList
                    }
                }
                archList.forEachIndexed { index, arch ->
                    create(arch) {
                        dimension = "abi"
                        ndk {
                            abiFilters.add(abiList[index])
                        }
                    }
                }
            }
        }

        afterEvaluate {
            for (profile in listOf("debug", "release")) {
                val profileCapitalized = profile.replaceFirstChar { it.uppercase() }
                val buildTask = tasks.maybeCreate(
                    "rustBuildUniversal$profileCapitalized",
                    DefaultTask::class.java
                ).apply {
                    group = TASK_GROUP
                    description = "Build dynamic library in $profile mode for all targets"
                }

                tasks["mergeUniversal${profileCapitalized}JniLibFolders"].dependsOn(buildTask)

                for (targetPair in targetsList.withIndex()) {
                    val targetName = targetPair.value
                    val targetArch = archList[targetPair.index]
                    val targetArchCapitalized = targetArch.replaceFirstChar { it.uppercase() }
                    val targetBuildTask = project.tasks.maybeCreate(
                        "rustBuild$targetArchCapitalized$profileCapitalized",
                        BuildTask::class.java
                    ).apply {
                        group = TASK_GROUP
                        description = "Build dynamic library in $profile mode for $targetArch"
                        rootDirRel = config.rootDirRel
                        target = targetName
                        release = profile == "release"
                    }

                    buildTask.dependsOn(targetBuildTask)
                    tasks["merge$targetArchCapitalized${profileCapitalized}JniLibFolders"].dependsOn(
                        targetBuildTask
                    )
                }
            }
        }
    }
}
