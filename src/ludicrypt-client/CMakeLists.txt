#
# Dependencies
#
#set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl@1.1/1.1.1l_1")
#find_package(OpenSSL REQUIRED)
#include_directories(${OPENSSL_INCLUDE_DIR})
set(Protobuf_USE_STATIC_LIBS ON)
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})
find_package(gRPC CONFIG REQUIRED)
find_package(Threads)

#
# Protobuf/Grpc source files
#
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)
set(PROTO_FILES
    ${PARENT_DIR}/Ludicrypt/Protos/crypto_provider.proto
)

#
# Add Library target with protobuf sources
#
add_library(ludicrypt-client ${PROTO_FILES})
target_link_libraries(ludicrypt-client
    PUBLIC
    protobuf::libprotobuf
    gRPC::grpc
    gRPC::grpc++
)
target_include_directories(ludicrypt-client PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

#
# Compile protobuf and grpc files in ludicrypt-client target to cpp
#
get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)
protobuf_generate(TARGET ludicrypt-client LANGUAGE cpp APPEND_PATH ${PARENT_DIR}/Ludicrypt/Protos)
protobuf_generate(TARGET ludicrypt-client LANGUAGE grpc APPEND_PATH ${PARENT_DIR}/Ludicrypt/Protos GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc PLUGIN "protoc-gen-grpc=${grpc_cpp_plugin_location}")
