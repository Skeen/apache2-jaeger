cmake_minimum_required(VERSION 3.2)

include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.23.201.tar.gz"
    SHA1 "29f10683f10c7b35e1f599d71542af0c2daa6a01"
)

project(mod_opentracing)


#hunter_add_package(jaegertracing)
#find_package(jaegertracing CONFIG REQUIRED)
#list(APPEND LIBS jaegertracing::jaegertracing-static)

add_library(mod_opentracing SHARED mod_opentracing.c)
target_link_libraries(mod_opentracing PUBLIC ${LIBS})
# Do not set lib prefix aka libmod_opentracing
SET_TARGET_PROPERTIES(mod_opentracing PROPERTIES PREFIX "")

# Include apache paths
target_include_directories(mod_opentracing PRIVATE /usr/include/apache2)
target_include_directories(mod_opentracing PRIVATE /usr/include/apr-1.0)
target_include_directories(mod_opentracing PRIVATE /usr/include)

# Install target to copy module into apache modules
install(TARGETS mod_opentracing DESTINATION /usr/lib/apache2/modules/)


add_custom_target(restart
    COMMAND sudo apachectl restart
    DEPENDS mod_opentracing
    WORKING_DIRECTORY ${CMAKE_PROJECT_DIR}
)
