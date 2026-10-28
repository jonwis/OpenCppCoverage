vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO OlafvdSpek/ctemplate
    REF 1c397b63e62dc6547054f4711c27918aedce4c2d
    SHA512 9691393cbb89972e95dba3cb802d0a0379f8f45cddc696e4ce223eb94887b3be46a9d999cac161069261ef63ba26fbdc392c53c3f977e1a7ae51768caa7739ea
    PATCHES arm64-load.patch
)
vcpkg_find_acquire_program(PYTHON3)
foreach(parser htmlparser jsparser)
    execute_process(
        COMMAND "${PYTHON3}" "${SOURCE_PATH}/src/htmlparser/generate_fsm.py"
            "${SOURCE_PATH}/src/htmlparser/${parser}_fsm.config"
        WORKING_DIRECTORY "${SOURCE_PATH}/src/htmlparser"
        OUTPUT_FILE "${SOURCE_PATH}/src/htmlparser/${parser}_fsm.h"
        COMMAND_ERROR_IS_FATAL ANY
    )
endforeach()

if(VCPKG_TARGET_ARCHITECTURE STREQUAL "x86")
    set(platform Win32)
elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "x64")
    set(platform x64)
elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm64")
    set(platform ARM64)
else()
    message(FATAL_ERROR "Unsupported ctemplate architecture: ${VCPKG_TARGET_ARCHITECTURE}")
endif()

set(project "${SOURCE_PATH}/vsprojects/libctemplate/libctemplate.vcxproj")
vcpkg_replace_string("${project}" "|Win32" "|${platform}")
vcpkg_replace_string("${project}" "<TargetMachine>MachineX86</TargetMachine>" "")
vcpkg_replace_string("${project}"
    "<OutDir>$(SolutionDir)$(Configuration)\\</OutDir>"
    "<OutDir>$(ProjectDir)..\\..\\$(Configuration)\\</OutDir>")
vcpkg_replace_string("${project}" "<PreprocessorDefinitions>"
    "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;_VARIADIC_MAX=10;")

if(VCPKG_CRT_LINKAGE STREQUAL "static")
    vcpkg_replace_string("${project}" ">MultiThreadedDLL<" ">MultiThreaded<")
    vcpkg_replace_string("${project}" ">MultiThreadedDebugDLL<" ">MultiThreadedDebug<")
else()
    vcpkg_replace_string("${project}" ">MultiThreaded<" ">MultiThreadedDLL<")
    vcpkg_replace_string("${project}" ">MultiThreadedDebug<" ">MultiThreadedDebugDLL<")
endif()

if(VCPKG_LIBRARY_LINKAGE STREQUAL "static")
    vcpkg_replace_string("${project}" "<ConfigurationType>DynamicLibrary</ConfigurationType>"
        "<ConfigurationType>StaticLibrary</ConfigurationType>")
    vcpkg_replace_string("${project}" "<PreprocessorDefinitions>"
        "<PreprocessorDefinitions>CTEMPLATE_DLL_DECL=;")
endif()

vcpkg_install_msbuild(
    SOURCE_PATH "${SOURCE_PATH}"
    PROJECT_SUBPATH vsprojects/libctemplate/libctemplate.vcxproj
    PLATFORM "${platform}"
)

file(INSTALL "${SOURCE_PATH}/src/windows/ctemplate" DESTINATION "${CURRENT_PACKAGES_DIR}/include"
    FILES_MATCHING PATTERN "*.h")
if(VCPKG_LIBRARY_LINKAGE STREQUAL "static")
    file(GLOB headers "${CURRENT_PACKAGES_DIR}/include/ctemplate/*.h")
    foreach(header IN LISTS headers)
        vcpkg_replace_string("${header}" "__declspec(dllimport)" "")
        vcpkg_replace_string("${header}" "__declspec(dllexport)" "")
    endforeach()
endif()
file(INSTALL "${SOURCE_PATH}/COPYING" DESTINATION "${CURRENT_PACKAGES_DIR}/share/ctemplate" RENAME copyright)
