set(AUTH-FILE_BIN auth-file)

set(AUTH-FILE_SRCS
    init.cpp
        WebAuthModule.cpp
        WebAuthInstance.cpp
        WebAuthSourceMapper.cpp
)

add_library(${AUTH-FILE_BIN} SHARED ${AUTH-FILE_SRCS})

set_target_properties(${AUTH-FILE_BIN} PROPERTIES
    COMPILE_FLAGS "${MODULE_COMPILE_FLAGS}"
    )

install(TARGETS ${AUTH-FILE_BIN} DESTINATION ${LEOSAC_MODULE_INSTALL_DIR})
