#
# Dependencies
#
find_package(Threads)

#
# Sources
#
set(SOURCES
    ludicrypt-pkcs11.cpp
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})

#
# Target
#
add_library(ludicrypt-pkcs11 SHARED ${SOURCES})
target_compile_definitions(ludicrypt-pkcs11 PRIVATE CRYPTOKI_EXPORTS)
target_link_libraries(ludicrypt-pkcs11
    PRIVATE
    ludicrypt-client
)
